import socket
from contextlib import contextmanager

from asyncer import asyncify
from cachetools import TTLCache, cached

from . import settings
from .errors import TimeoutError


@contextmanager
def socket_with_timeout(timeout: float):
    old_timeout = socket.getdefaulttimeout()

    try:
        socket.setdefaulttimeout(timeout)
        yield socket
    except (socket.timeout, ValueError):
        raise TimeoutError(f"{timeout} seconds have passed but there is no response")
    finally:
        socket.setdefaulttimeout(old_timeout)


@cached(
    cache=TTLCache(
        maxsize=settings.IP_ADDRESS_LOOKUP_CACHE_SIZE,
        ttl=settings.IP_ADDRESS_LOOKUP_CACHE_TTL,
    )
)
def _resolve_ip_address(
    hostname: str, *, timeout: int = settings.IP_ADDRESS_LOOKUP_TIMEOUT
) -> str:
    with socket_with_timeout(float(timeout)):
        ip = socket.gethostbyname(hostname)
        return ip


resolve_ip_address = asyncify(_resolve_ip_address)
