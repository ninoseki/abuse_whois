import pytest

from abuse_whois.matchers.whois.rule import WhoisRule
from abuse_whois.schemas import Contact


@pytest.mark.asyncio
async def test_base_domains_matching():
    test = WhoisRule(
        contact=Contact(provider="dummy", address="dummy@example.com"),
        base_domains=["example.com"],
    )

    assert await test.match("http://example.com") is True
    assert await test.match("http://foo.example.com") is True
