import contextlib
from dataclasses import dataclass
from functools import partial
from urllib.parse import urlparse

import aiometer
from returns.functions import raise_exception
from returns.future import FutureResultE, future_safe
from returns.pipeline import flow
from returns.pointfree import bind
from returns.result import ResultE, safe
from returns.unsafe import unsafe_perform_io

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
    hostname: str
    ip_address: str | None
    domain_record: schemas.WhoisRecord | None
    ip_record: schemas.WhoisRecord | None


@future_safe
async def validate_address(address: str) -> str:
    for f in [is_email, is_domain, is_ipv4, is_ipv6, is_url]:
        if f(address):
            return address

    raise errors.AddressError(f"Address:{address} not supported address type")


@future_safe
async def get_hostname(address: str) -> str:
    if is_ipv6(address) or is_ipv4(address) or is_domain(address):
        return address

    url_or_email = address
    if is_email(url_or_email):
        url_or_email = f"http://{address}"

    parsed = urlparse(url_or_email)
    if parsed.hostname is None:
        raise errors.AddressError(f"Address:{address} does not have hostname")

    return parsed.hostname


@future_safe
async def safe_query(
    hostname, *, timeout: int = settings.QUERY_TIMEOUT
) -> schemas.WhoisRecord:
    return await query(hostname, timeout=timeout)


async def get_ip_record(
    hostname: str, *, timeout: int = settings.QUERY_TIMEOUT
) -> schemas.WhoisRecord:
    ip_f_result = await safe_query(hostname, timeout=timeout)
    return unsafe_perform_io(ip_f_result.alt(raise_exception).unwrap())


async def get_optional_ip_record(
    hostname: str | None, *, timeout: int = settings.QUERY_TIMEOUT
) -> schemas.WhoisRecord | None:
    if hostname is None:
        return None

    return await get_ip_record(hostname, timeout=timeout)


async def get_domain_record(
    hostname: str, *, timeout: int = settings.QUERY_TIMEOUT
) -> schemas.WhoisRecord:
    domain_f_result = await safe_query(hostname, timeout=timeout)
    return unsafe_perform_io(domain_f_result.alt(raise_exception).unwrap())


async def get_optional_domain_record(
    hostname: str, *, timeout: int = settings.QUERY_TIMEOUT
) -> schemas.WhoisRecord | None:
    if not is_domain(hostname):
        return None

    domain_f_result = await safe_query(hostname, timeout=timeout)
    return unsafe_perform_io(domain_f_result.alt(raise_exception).unwrap())


@future_safe
async def get_records(
    hostname: str, *, timeout: int = settings.QUERY_TIMEOUT
) -> Container:
    domain_record: schemas.WhoisRecord | None = None
    ip_record: schemas.WhoisRecord | None = None

    ip_address: str | None = None
    if is_domain(hostname):
        # get IP address by domain
        with contextlib.suppress(OSError):
            ip_address = await resolve(hostname)
    else:
        ip_address = hostname

    tasks = [
        partial(get_optional_domain_record, hostname, timeout=timeout),
        partial(get_optional_ip_record, ip_address, timeout=timeout),
    ]
    domain_record, ip_record = await aiometer.run_all(tasks)
    return Container(
        hostname=hostname,
        domain_record=domain_record,
        ip_record=ip_record,
        ip_address=ip_address,
    )


@future_safe
async def get_contacts(container: Container, *, address: str) -> schemas.Contacts:
    @safe
    def set_records(container: Container) -> schemas.Contacts:
        if container.ip_record is None and container.domain_record is None:
            raise errors.NotFoundError(
                f"Record: {container.hostname} not found or something went wrong"
            )

        return schemas.Contacts(
            records=schemas.ContactsRecords(
                ip_address=container.ip_record, domain=container.domain_record
            ),
            address=address,
            ip_address=container.ip_address,
            hostname=container.hostname,
            registered_domain=None,
            shared_hosting_provider=None,
            hosting_provider=None,
            registrar=None,
        )

    @safe
    def set_registered_domain(contacts: schemas.Contacts) -> schemas.Contacts:
        if is_domain(container.hostname):
            contacts.registered_domain = get_registered_domain(container.hostname)

        return contacts

    @safe
    def set_registrar(contacts: schemas.Contacts) -> schemas.Contacts:
        if container.domain_record is not None:
            contacts.registrar = get_whois_contact(container.domain_record)

        return contacts

    @safe
    def set_hosting_provider(contacts: schemas.Contacts) -> schemas.Contacts:
        if container.ip_record is not None:
            contacts.hosting_provider = get_whois_contact(container.ip_record)

        return contacts

    @safe
    def set_shared_hosting_provider(
        contacts: schemas.Contacts,
    ) -> schemas.Contacts:
        contacts.shared_hosting_provider = get_shared_hosting_provider(
            container.hostname
        )
        return contacts

    result: ResultE[schemas.Contacts] = flow(
        set_records(container),
        bind(set_registered_domain),
        bind(set_registrar),
        bind(set_hosting_provider),
        bind(set_shared_hosting_provider),
    )
    return result.alt(raise_exception).unwrap()


class ContactsQuery(AbstractService):
    async def call(self, address: str) -> schemas.Contacts:
        f_result: FutureResultE[schemas.Contacts] = flow(
            address,
            validate_address,
            bind(get_hostname),
            bind(get_records),
            bind(partial(get_contacts, address=address)),
        )
        result = await f_result.awaitable()
        return unsafe_perform_io(result.alt(raise_exception).unwrap())
