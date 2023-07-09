import pytest

from abuse_whois.matchers.whois import get_whois_contact


@pytest.mark.parametrize(
    "hostname",
    [
        "1.1.1.1",
        "github.com",
    ],
)
@pytest.mark.asyncio
async def test_get_contact_from_whois(hostname: str):
    assert await get_whois_contact(hostname) is not None
