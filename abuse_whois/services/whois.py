from functools import partial
from typing import Any, cast

from asyncwhois.client import DomainClient, NumberClient
from asyncwhois.errors import NotFoundError as WhoIsNotFoundError
from asyncwhois.parse import IPBaseKeys, TLDBaseKeys
from returns.functions import raise_exception
from returns.future import FutureResultE, future_safe
from returns.maybe import Maybe
from returns.pipeline import flow, is_successful
from returns.pointfree import bind
from returns.unsafe import unsafe_perform_io
from whodap import DomainResponse
from whodap.errors import NotFoundError as WhodapNotFoundError
from whodap.errors import RateLimitError

from abuse_whois import errors, schemas, settings
from abuse_whois.utils import (
    get_registered_domain,
    is_domain,
    is_ipv4,
    is_ipv6,
)

from .abstract import AbstractService

QueryOutput = (
    tuple[str, dict[str, Any]]
    | tuple[str, dict[TLDBaseKeys, Any]]
    | tuple[str, dict[IPBaseKeys, Any]]
)


@future_safe
async def domain_rdap(domain: str, *, client: DomainClient) -> QueryOutput:
    return await client.aio_rdap(domain)


@future_safe
async def domain_whois(domain: str, *, client: DomainClient) -> QueryOutput:
    return await client.aio_whois(domain)


@future_safe
async def raise_on_rate_limit(query_output: QueryOutput) -> QueryOutput:
    query_string, _ = query_output
    for message in settings.WHOIS_RATE_LIMIT_MESSAGES:
        if message in query_string:
            raise RateLimitError()

    return query_output


@future_safe
async def rdap(hostname: str, *, client: DomainClient | NumberClient):
    return await client.aio_rdap(hostname)


@future_safe
async def whois(hostname: str, *, client: DomainClient | NumberClient):
    return await client.aio_whois(hostname)


async def _query(hostname: str, *, client: DomainClient | NumberClient):
    rdap_result = await rdap(hostname, client=client)
    if is_successful(rdap_result):
        query_string, parsed = unsafe_perform_io(rdap_result.unwrap())

        registrar = parsed.get("registrar")
        email = parsed.get("registrar_abuse_email")
        if registrar is not None or email is not None:
            return query_string, parsed

    whois_f_result: FutureResultE[QueryOutput] = flow(
        whois(hostname, client=client), bind(raise_on_rate_limit)
    )
    whois_result = await whois_f_result.awaitable()
    return unsafe_perform_io(whois_result.alt(raise_exception).unwrap())


@future_safe
async def query(address: str, *, timeout: int = settings.QUERY_TIMEOUT) -> QueryOutput:
    @future_safe
    async def inner() -> QueryOutput:
        if is_domain(address):
            return await _query(address, client=DomainClient(timeout=timeout))

        if is_ipv4(address) or is_ipv6(address):
            return await _query(address, client=NumberClient(timeout=timeout))

        raise errors.AddressError(f"{address} is neither of domain, IPv4 and IPv6")

    f_result = inner()
    result = await f_result.awaitable()
    if not is_successful(result):
        failure = unsafe_perform_io(result.failure())
        match failure:
            case WhodapNotFoundError() | WhoIsNotFoundError():
                raise errors.NotFoundError(f"Record:{address} not found") from failure
            case RateLimitError():
                raise errors.RateLimitError(
                    f"Query:{address} rate limited"
                ) from failure

    return unsafe_perform_io(result.alt(raise_exception).unwrap())


def get_contact(parsed: dict, prefix: str) -> schemas.WhoisContact:
    return schemas.WhoisContact(
        name=parsed.get(f"{prefix}_name", None),
        email=parsed.get(f"{prefix}_email", None),
        telephone=parsed.get(f"{prefix}_phone", None),
        organization=parsed.get(f"{prefix}_organization", None),
    )


def get_abuse(parsed: dict) -> schemas.WhoisAbuse:
    return schemas.WhoisAbuse(
        email=parsed.get("registrar_abuse_email"),
        telephone=parsed.get("registrar_abuse_phone"),
    )


@future_safe
async def normalize(hostname: str) -> str:
    if is_domain(hostname):
        return get_registered_domain(hostname) or hostname

    return hostname


def normalize_domain(domain: DomainResponse | str | None) -> str | None:
    if domain is None:
        return None

    if isinstance(domain, str):
        return domain.lower().removesuffix(".")

    return (
        Maybe.from_optional(domain.to_dict().get("stringValue"))
        .bind_optional(lambda x: str(x).lower().removesuffix("."))
        .value_or(None)
    )


def is_str_list(values: Any) -> bool:
    if not isinstance(values, list):
        return False

    return all(isinstance(v, str) for v in values)


def get_str_list(data: dict[str, Any], key: str) -> list[str]:
    return cast(
        list[str],
        (
            Maybe.from_optional(data.get(key))
            .bind_optional(lambda x: x if is_str_list(x) else [])
            .value_or([])
        ),
    )


@future_safe
async def parse(query_output: QueryOutput) -> schemas.WhoisRecord:
    query_string, parsed = query_output
    parsed = cast(dict[str, Any], parsed)
    return schemas.WhoisRecord(
        raw_text=query_string,
        domain=normalize_domain(parsed.get("domain_name")),
        name_servers=get_str_list(parsed, "name_servers"),
        statuses=get_str_list(parsed, "status"),
        tech=get_contact(parsed, "technical"),
        admin=get_contact(parsed, "admin"),
        registrant=get_contact(parsed, "registrant"),
        abuse=get_abuse(parsed),
        expires_at=parsed.get("expires"),
        updated_at=parsed.get("updated"),
        registered_at=parsed.get("registered"),
        registrar=parsed.get("registrar"),
    )


class WhoisQuery(AbstractService):
    async def call(
        self, hostname: str, *, timeout: int = settings.QUERY_TIMEOUT
    ) -> schemas.WhoisRecord:
        f_result: FutureResultE[schemas.WhoisRecord] = flow(
            hostname, normalize, bind(partial(query, timeout=timeout)), bind(parse)
        )
        result = await f_result.awaitable()
        return unsafe_perform_io(result.alt(raise_exception).unwrap())
