import pytest

from abuse_whois.main import get_abuse_contacts


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


@pytest.mark.asyncio
async def test_get_abuse_contacts_with_ip_address():
    contacts = await get_abuse_contacts("1.1.1.1")
    assert contacts.hostname == "1.1.1.1"
    assert contacts.ip_address == "1.1.1.1"
    assert contacts.registered_domain is None
    assert contacts.registrar is None
    assert contacts.hosting_provider is not None


@pytest.mark.asyncio
async def test_get_abuse_contacts_with_domain():
    contacts = await get_abuse_contacts("www.github.com")
    assert contacts.hostname == "www.github.com"
    assert contacts.ip_address is not None
    assert contacts.registered_domain == "github.com"
    assert contacts.registrar is not None
    assert contacts.hosting_provider is not None
