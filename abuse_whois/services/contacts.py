import contextlib
from dataclasses import dataclass
from urllib.parse import urlparse

from returns.functions import raise_exception
from returns.future import FutureResultE, future_safe
from returns.pipeline import flow
from returns.pointfree import bind

from abuse_whois import errors, schemas, settings
from abuse_whois.matchers.shared_hosting import get_shared_hosting_provider
from abuse_whois.matchers.whois import get_whois_contact
from abuse_whois.utils import (
    get_registered_domain,
    is_domain,
    is_email,
    is_ipv4,
    is_ipv6,
    is_url,
    resolve,
)
from abuse_whois.whois import query

from .abstract import AbstractService


@dataclass
class Container:
    address: str
    hostname: str


@dataclass
class ContainerWithRecords(Container):
    ip_address: str | None
    domain_record: schemas.WhoisRecord | None
    ip_record: schemas.WhoisRecord | None


@future_safe
async def validate_address(address: str) -> str:
    funcs = [is_email, is_domain, is_ipv4, is_ipv6, is_url]
    for f in funcs:
        if f(address):
            return address

    raise errors.AddressError(f"{address} is not supported type address")


@future_safe
async def get_hostname(address: str) -> Container:
    if is_ipv6(address) or is_ipv4(address) or is_domain(address):
        return Container(hostname=address, address=address)

    url_or_email = address
    if is_email(url_or_email):
        url_or_email = f"http://{address}"

    parsed = urlparse(url_or_email)
    if parsed.hostname is None:
        raise errors.AddressError(f"{address} does not have hostname")

    return Container(hostname=parsed.hostname, address=address)


@future_safe
async def whois_query(
    hostname, *, timeout: int = settings.QUERY_TIMEOUT
) -> schemas.WhoisRecord:
    return await query(hostname, timeout=timeout)


async def get_domain_records(
    container: Container, *, timeout: int = settings.QUERY_TIMEOUT
) -> ContainerWithRecords:
    domain_record = (
        (await whois_query(container.hostname, timeout=timeout).awaitable())
        .alt(raise_exception)
        .unwrap()
        ._inner_value
    )

    # get IP address by domain
    ip_record: schemas.WhoisRecord | None = None
    ip_address: str | None = None
    with contextlib.suppress(OSError):
        ip_address = await resolve(container.hostname)

    if ip_address is not None:
        ip_record = (
            await whois_query(container.hostname, timeout=timeout).awaitable()
        )._inner_value.value_or(None)

    return ContainerWithRecords(
        address=container.address,
        hostname=container.hostname,
        domain_record=domain_record,
        ip_record=ip_record,
        ip_address=ip_address,
    )


async def get_ip_records(
    container: Container, *, timeout: int = settings.QUERY_TIMEOUT
) -> ContainerWithRecords:
    ip_record = (
        (await whois_query(container.hostname, timeout=timeout).awaitable())
        .alt(raise_exception)
        .unwrap()
        ._inner_value
    )

    return ContainerWithRecords(
        address=container.address,
        hostname=container.hostname,
        domain_record=None,
        ip_record=ip_record,
        ip_address=container.hostname,
    )


@future_safe
async def get_records(
    container: Container, *, timeout: int = settings.QUERY_TIMEOUT
) -> ContainerWithRecords:
    if is_domain(container.hostname):
        return await get_domain_records(container, timeout=timeout)

    return await get_ip_records(container, timeout=timeout)


@future_safe
async def get_contacts(container: ContainerWithRecords):
    main_record = (
        container.domain_record
        if is_domain(container.hostname)
        else container.ip_record
    )
    if main_record is None:
        raise errors.NotFoundError(
            f"Record for {container.hostname} is not found or something went wrong"
        )

    registered_domain: str | None = None
    if is_domain(container.hostname):
        # set registered domain
        registered_domain = get_registered_domain(container.hostname)

    registrar: schemas.Contact | None = None
    if container.domain_record is not None:
        registrar = get_whois_contact(container.domain_record)

    hosting_provider: schemas.Contact | None = None
    if container.ip_record is not None:
        hosting_provider = get_whois_contact(container.ip_record)

    shared_hosting_provider = get_shared_hosting_provider(container.hostname)

    return schemas.Contacts(
        address=container.address,
        hostname=container.hostname,
        ip_address=container.ip_address,
        registered_domain=registered_domain,
        shared_hosting_provider=shared_hosting_provider,
        registrar=registrar,
        hosting_provider=hosting_provider,
        record=main_record,
    )


class ContactsQuery(AbstractService):
    async def call(self, address: str) -> schemas.Contacts:
        result: FutureResultE[schemas.Contacts] = flow(
            address,
            validate_address,
            bind(get_hostname),
            bind(get_records),
            bind(get_contacts),
        )
        return (await result.awaitable()).alt(raise_exception).unwrap()._inner_value
