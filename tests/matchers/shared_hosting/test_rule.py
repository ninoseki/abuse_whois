import glob

import pytest

from abuse_whois.matchers.shared_hosting.rule import SharedHostingRule
from abuse_whois.schemas import Contact
from abuse_whois.utils import load_yaml

paths = [p for p in glob.glob("abuse_whois/matchers/shared_hosting/rules/*.yaml")]


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert SharedHostingRule.parse_obj(load_yaml(path))


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
    base = SharedHostingRule(
        contact=contact, base_domains=base_domains, title="dummy", description="dummy"
    )

    assert base.match(hostname) is expected
