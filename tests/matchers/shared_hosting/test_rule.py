import pytest

from abuse_whois.matchers.shared_hosting.rule import SharedHostingRule
from abuse_whois.schemas import Contact


@pytest.mark.parametrize(
    "hostname,base_domains,expected",
    [
        ("example.com", ["example.com"], True),
        ("foo.com", ["example.com"], False),
        ("foo.example.com", ["example.com"], True),
        ("example.com", ["foo.com", "example.com"], True),
        ("foo.com", ["foo.com", "example.com"], True),
    ],
)
def test_match(hostname: str, base_domains: list[str], expected: bool):
    contact = Contact(provider="test", address="test")
    base = SharedHostingRule(contact=contact, base_domains=base_domains)

    assert base.match(hostname) is expected
