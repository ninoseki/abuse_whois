import asyncio
import socket
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from typing import Any, TypeVar

import tld
import validators
from asyncer import asyncify

from . import settings


def _is_x(v: str, *, validator: Callable[[str], bool]) -> bool:
    res = validator(v)

    if isinstance(res, validators.ValidationError):
        return False

    return res


def is_ipv4(v: str) -> bool:
    return _is_x(v, validator=validators.ipv4)  # type: ignore


def is_ipv6(v: str) -> bool:
    return _is_x(v, validator=validators.ipv6)  # type: ignore


def is_domain(v: str) -> bool:
    if len(v.split(".")) == 1:
        return False

    if "@" in v:
        return False

    return _is_x(v, validator=validators.domain)  # type: ignore


def is_url(v: str) -> bool:
    if not v.startswith(("http://", "https://")):
        return False

    return _is_x(v, validator=validators.url)  # type: ignore


def is_email(v: str) -> bool:
    return _is_x(v, validator=validators.email)  # type: ignore


def get_registered_domain(v: str) -> str | None:
    registered_domain = tld.get_fld(v, fail_silently=True, fix_protocol=True)

    if registered_domain == "":
        return None

    return registered_domain


@contextmanager
def with_socket_timeout(timeout: float):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        yield
    except (TimeoutError, ValueError) as e:
        raise asyncio.TimeoutError(
            f"{timeout} seconds have passed but there is no response"
        ) from e
    finally:
        socket.setdefaulttimeout(old)


def _resolve(hostname: str, *, timeout: float = float(settings.QUERY_TIMEOUT)) -> str:
    with with_socket_timeout(timeout):
        return socket.gethostbyname(hostname)


resolve = asyncify(_resolve)


def is_iterable(obj: Any) -> bool:
    try:
        iter(obj)
    except TypeError:
        return False
    return True


T = TypeVar("T")


def unique(src: Iterable[T], key: str | Callable[[T], Any] | None = None) -> list[T]:
    return list(unique_iter(src, key))


def unique_iter(src: Iterable[T], key: str | Callable[[T], Any] | None = None):
    if not is_iterable(src):
        raise TypeError(f"expected an iterable, not {type(src)!r}")

    def build_key_func():
        if key is None:
            return lambda x: x

        if callable(key):
            return key

        if isinstance(key, str):
            return lambda x: getattr(x, key, x)

        raise TypeError(f'"key" expected a string or callable, not {key!r}')

    key_func = build_key_func()
    seen = set()
    for i in src:
        k = key_func(i)
        if k not in seen:
            seen.add(k)
            yield i
