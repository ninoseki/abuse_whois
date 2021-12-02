import pytest

from abuse_whois.utils import get_hostname, is_domain, is_email, is_ip_address, is_url


@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.1.1.1", True),
        ("example.com", False),
        ("https://github.com", False),
        ("foo@test.com", False),
    ],
)
def test_is_ip_address(v: str, expected: bool):
    assert is_ip_address(v) is expected


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


@pytest.mark.parametrize(
    "v,hostname",
    [
        ("1.1.1.1", "1.1.1.1"),
        ("example.com", "example.com"),
        ("https://github.com", "github.com"),
        ("foo@test.com", "test.com"),
    ],
)
def test_get_hostname(v: str, hostname: str):
    assert get_hostname(v) == hostname
