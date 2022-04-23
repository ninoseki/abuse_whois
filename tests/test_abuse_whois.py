import pytest

from abuse_whois import __version__, get_abuse_contacts


def test_version():
    assert isinstance(__version__, str)


@pytest.mark.parametrize(
    "address,hostname",
    [
        ("1.1.1.1", "1.1.1.1"),
        ("example.com", "example.com"),
        ("https://github.com", "github.com"),
        ("foo@test.com", "test.com"),
    ],
)
@pytest.mark.asyncio
async def test_get_abuse_contacts(address: str, hostname: str):
    contacts = await get_abuse_contacts(address)
    assert contacts.hostname == hostname
