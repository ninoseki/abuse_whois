import asyncio
import pathlib
import socket
from collections.abc import Callable
from contextlib import contextmanager
from typing import cast

import tldextract
import validators
import yaml
from asyncache import cached
from asyncer import asyncify
from cachetools import TTLCache
from starlette.datastructures import CommaSeparatedStrings

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
    parsed = tldextract.extract(v)

    if parsed.registered_domain == "":
        return None

    return parsed.registered_domain


@contextmanager
def with_socket_timeout(timeout: float):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        yield
    except (socket.timeout, ValueError) as e:
        raise asyncio.TimeoutError(
            f"{timeout} seconds have passed but there is no response"
        ) from e
    finally:
        socket.setdefaulttimeout(old)


@cached(cache=TTLCache(maxsize=settings.QUERY_CACHE_SIZE, ttl=settings.QUERY_CACHE_TTL))
def _resolve(hostname: str, *, timeout: float = float(settings.QUERY_TIMEOUT)) -> str:
    with with_socket_timeout(timeout):
        return socket.gethostbyname(hostname)


resolve = asyncify(_resolve)


def load_yaml(path: str | pathlib.Path) -> dict:
    with open(path) as f:
        return cast(dict, yaml.safe_load(f))


def glob_rules(
    base_directory: str | pathlib.Path,
    *,
    additional_directories: list[str] | list[pathlib.Path] | CommaSeparatedStrings,
    rule_extensions=settings.RULE_EXTENSIONS,
) -> list[pathlib.Path]:
    directories = [base_directory]
    directories.extend(additional_directories)

    directories = [pathlib.Path(d) for d in directories]

    paths: set[str] = set()
    for directory in directories:
        for extension in rule_extensions:
            paths.update([str(p) for p in directory.glob(f"*.{extension}")])  # type: ignore

    return [pathlib.Path(p) for p in paths]
