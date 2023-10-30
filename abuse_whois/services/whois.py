import ssl
from functools import partial
from typing import Any

import httpx
import orjson
from asyncwhois.errors import NotFoundError as WhoIsNotFoundError
from asyncwhois.pywhois import DomainLookup, NumberLookup
from httpx._exceptions import TimeoutException
from loguru import logger
from returns.functions import raise_exception
from returns.future import FutureResultE, future_safe
from returns.pipeline import flow
from returns.pointfree import bind
from whodap import DomainResponse
from whodap.errors import (
    NotFoundError as WhodapNotFoundError,
)
from whodap.errors import (
    RateLimitError,
    WhodapError,
)

from abuse_whois import errors, schemas, settings
from abuse_whois.utils import (
    get_registered_domain,
    is_domain,
    is_ipv4,
    is_ipv6,
)

from .abstract import AbstractService


def check_rate_limit(lookup: DomainLookup) -> None:
    for message in settings.WHOIS_RATE_LIMIT_MESSAGES:
        if message in lookup.query_output:
            # use whodap's RateLimitError just for convenience
            raise RateLimitError()


async def domain_query(
    address: str, *, timeout: int = settings.QUERY_TIMEOUT
) -> DomainLookup:
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            return await DomainLookup.aio_rdap_domain(address, client)
        except (TimeoutException, WhodapError, ssl.SSLError):
            # fallback to whois
            pass
        except Exception as e:
            # also fallback to whois
            logger.exception(e)

    # fallback to whois
    lookup = await DomainLookup.aio_whois_domain(
        address,
        timeout=timeout,
        authoritative_only=False,
        proxy_url=None,  # type: ignore
    )

    check_rate_limit(lookup)

    return lookup


@future_safe
async def query(
    address: str, *, timeout: int = settings.QUERY_TIMEOUT
) -> DomainLookup | NumberLookup:
    try:
        if is_domain(address):
            return await domain_query(address, timeout=timeout)

        if is_ipv4(address):
            return await NumberLookup.aio_whois_ipv4(
                address,
                timeout=timeout,
                authoritative_only=False,
                proxy_url=None,  # type: ignore
            )

        if is_ipv6(address):
            return await NumberLookup.aio_whois_ipv6(
                address,
                timeout=timeout,
                authoritative_only=False,
                proxy_url=None,  # type: ignore
            )
    except (WhodapNotFoundError, WhoIsNotFoundError) as e:
        raise errors.NotFoundError(f"Record for {address} is not found") from e
    except RateLimitError as e:
        raise errors.RateLimitError(f"Query for {address} is rate limited") from e

    raise errors.AddressError(f"{address} is neither of domain, IPv4 and IPv6")


def get_contact(parsed: dict, prefix: str) -> schemas.WhoisContact:
    name = parsed.get(f"{prefix}_name", None)
    email = parsed.get(f"{prefix}_email", None)
    telephone = parsed.get(f"{prefix}_phone", None)
    organization = parsed.get(f"{prefix}_organization", None)
    return schemas.WhoisContact(
        organization=organization, email=email, telephone=telephone, name=name
    )


def get_abuse(parsed: dict) -> schemas.WhoisAbuse:
    email = parsed.get("registrar_abuse_email", None)
    telephone = parsed.get("registrar_abuse_phone", None)
    return schemas.WhoisAbuse(
        email=email,
        telephone=telephone,
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

    v = domain.to_dict().get("stringValue")
    if v is None:
        return None

    return str(v).lower().removesuffix(".")


def is_str_list(values: Any) -> bool:
    if not isinstance(values, list):
        return False

    return all(isinstance(v, str) for v in values)


@future_safe
async def parse(result: DomainLookup | NumberLookup) -> schemas.WhoisRecord:
    parser_output = result.parser_output
    query_output = result.query_output

    raw_text: str = ""
    if isinstance(query_output, dict):
        raw_text = orjson.dumps(query_output).decode()
    else:
        raw_text = str(query_output)

    domain = normalize_domain(parser_output.get("domain_name"))

    name_servers = parser_output.get("name_servers", [])
    if not is_str_list(name_servers):
        name_servers = []

    statuses = parser_output.get("status", [])
    if not is_str_list(statuses):
        statuses = []

    return schemas.WhoisRecord(
        raw_text=raw_text,
        domain=domain,
        name_servers=name_servers,
        statuses=statuses,
        tech=get_contact(parser_output, "technical"),
        admin=get_contact(parser_output, "admin"),
        registrant=get_contact(parser_output, "registrant"),
        abuse=get_abuse(parser_output),
        expires_at=parser_output.get("expires"),
        updated_at=parser_output.get("updated"),
        registered_at=parser_output.get("registered"),
        registrar=parser_output.get("registrar"),
    )


class WhoisQuery(AbstractService):
    async def call(
        self, hostname: str, *, timeout: int = settings.QUERY_TIMEOUT
    ) -> schemas.WhoisRecord:
        result: FutureResultE[schemas.WhoisRecord] = flow(
            hostname, normalize, bind(partial(query, timeout=timeout)), bind(parse)
        )
        return (await result.awaitable()).alt(raise_exception).unwrap()._inner_value
