import asyncio

import pytest
from pytest_mock import MockerFixture

from abuse_whois.utils import is_domain, is_email, is_ipv4, is_url, resolve


@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.1.1.1", True),
        ("example.com", False),
        ("https://github.com", False),
        ("foo@test.com", False),
    ],
)
def test_is_ipv4(v: str, expected: bool):
    assert is_ipv4(v) is expected


@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.1.1.1", False),
        ("example.com", True),
        ("https://github.com", False),
        ("foo@test.com", False),
    ],
)
def test_is_domain(v: str, expected: bool):
    assert is_domain(v) is expected


@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.1.1.1", False),
        ("example.com", False),
        ("https://github.com", True),
        ("foo@test.com", False),
    ],
)
def test_is_url(v: str, expected: bool):
    assert is_url(v) is expected


@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.1.1.1", False),
        ("example.com", False),
        ("https://github.com", False),
        ("foo@test.com", True),
    ],
)
def test_is_email(v: str, expected: bool):
    assert is_email(v) is expected


@pytest.mark.asyncio
async def test_resolve_with_timeout(mocker: MockerFixture):
    with pytest.raises(asyncio.TimeoutError):
        assert await resolve("github.com", timeout=-1.0)
