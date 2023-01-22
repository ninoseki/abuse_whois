import glob

import pytest

from abuse_whois.matchers.whois.rule import WhoisRule
from abuse_whois.pysigma.parser import check_event
from abuse_whois.schemas import Contact, WhoisRecord
from abuse_whois.utils import load_yaml

paths = [p for p in glob.glob("abuse_whois/matchers/whois/rules/*.yaml")]


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert WhoisRule.parse_obj(load_yaml(path))


@pytest.mark.asyncio
async def test_base_domains_matching():
    test = WhoisRule(
        contact=Contact(provider="dummy", address="dummy@example.com"),
        base_domains=["example.com"],
        title="dummy",
        description="dummy",
    )

    assert await test.match("example.com") is True
    assert await test.match("foo.example.com") is True


@pytest.fixture
def godaddy_whois_record():
    return WhoisRecord.parse_file("tests/fixtures/godaddy.com.json")


@pytest.fixture
def godaddy_whois_rule():
    return WhoisRule.parse_obj(
        load_yaml("abuse_whois/matchers/whois/rules/godaddy.yaml")
    )


def test_godaddy(godaddy_whois_record: WhoisRecord, godaddy_whois_rule: WhoisRule):
    sigma_rule = godaddy_whois_rule.sigma_rule
    alerts = check_event(godaddy_whois_record.dict(by_alias=True), sigma_rule)
    assert len(alerts) > 0

    alerts = check_event({}, sigma_rule)
    assert len(alerts) == 0
