import socket
from contextlib import contextmanager

from . import settings
from .errors import TimeoutError


@contextmanager
def socket_with_timeout(timeout: float):
    old_timeout = socket.getdefaulttimeout()

    try:
        socket.setdefaulttimeout(timeout)
        yield socket
    except (socket.timeout, ValueError):
        raise TimeoutError(
            f"{settings.WHOIS_TIMEOUT} seconds have passed but there is no response"
        )
    finally:
        socket.setdefaulttimeout(old_timeout)


def resolve_ip_address(hostname: str, *, timeout: int = settings.WHOIS_TIMEOUT) -> str:
    with socket_with_timeout(float(timeout)):
        ip = socket.gethostbyname(hostname)
        return ip
