import glob

import pytest

from abuse_whois.matchers.whois.rule import WhoisRule
from abuse_whois.schemas import WhoisRecord
from abuse_whois.utils import load_yaml

paths = [p for p in glob.glob("abuse_whois/matchers/whois/rules/*.yaml")]


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert WhoisRule.parse_obj(load_yaml(path))


@pytest.fixture
def godaddy_whois_record():
    return WhoisRecord.parse_file("tests/fixtures/godaddy.com.json")


@pytest.fixture
def godaddy_whois_rule():
    return WhoisRule.parse_obj(
        load_yaml("abuse_whois/matchers/whois/rules/godaddy.yaml")
    )


def test_godaddy(godaddy_whois_record: WhoisRecord, godaddy_whois_rule: WhoisRule):
    condition = godaddy_whois_rule.detection_condition
    assert (
        condition(godaddy_whois_rule, godaddy_whois_record.dict(by_alias=True)) is True
    )
    assert condition(godaddy_whois_rule, {}) is False
