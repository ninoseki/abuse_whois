import asyncio
import socket
from contextlib import contextmanager

from asyncer import asyncify
from cachetools import TTLCache, cached

from . import schemas, settings
from .errors import InvalidAddressError
from .matchers.shared_hosting import get_shared_hosting_provider
from .matchers.whois import get_whois_contact
from .utils import (
    get_hostname,
    get_registered_domain,
    is_domain,
    is_ip_address,
    is_supported_address,
)
from .whois import get_whois_record


@contextmanager
def with_socket_timeout(timeout: float):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        yield
    except (socket.timeout, ValueError):
        raise asyncio.TimeoutError(
            f"{timeout} seconds have passed but there is no response"
        )
    finally:
        socket.setdefaulttimeout(old)


@cached(
    cache=TTLCache(
        maxsize=settings.IP_ADDRESS_LOOKUP_CACHE_SIZE,
        ttl=settings.IP_ADDRESS_LOOKUP_CACHE_TTL,
    )
)
def _resolve(
    hostname: str, *, timeout: float = float(settings.IP_ADDRESS_LOOKUP_TIMEOUT)
) -> str:
    with with_socket_timeout(timeout):
        ip = socket.gethostbyname(hostname)
        return ip


resolve = asyncify(_resolve)


async def get_contact(domain_or_ip: str | None):
    if domain_or_ip is None:
        return None

    return await get_whois_contact(domain_or_ip)


async def get_abuse_contacts(address: str) -> schemas.Contacts:
    if not is_supported_address(address):
        raise InvalidAddressError(f"{address} is not supported type address")

    hostname = get_hostname(address)  # Domain or IP address

    domain: str | None = None
    ip_address: str | None = None
    registered_domain: str | None = None

    if is_domain(hostname):
        domain = hostname
        registered_domain = get_registered_domain(hostname)

        # get IP address by domain
        try:
            ip_address = await resolve(hostname)
        except OSError:
            pass

    if is_ip_address(hostname):
        ip_address = hostname

    whois_record = await get_whois_record(hostname)
    shared_hosting_provider = get_shared_hosting_provider(hostname)

    registrar, hosting_provider = await asyncio.gather(
        get_contact(domain), get_contact(ip_address)
    )

    return schemas.Contacts(
        address=address,
        hostname=hostname,
        ip_address=ip_address,
        registered_domain=registered_domain,
        shared_hosting_provider=shared_hosting_provider,
        registrar=registrar,
        hosting_provider=hosting_provider,
        whois_record=whois_record,
    )
