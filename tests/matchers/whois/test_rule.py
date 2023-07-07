import glob
import json

import pytest

from abuse_whois.matchers.whois.rule import WhoisRule
from abuse_whois.schemas import WhoisRecord
from abuse_whois.utils import load_yaml

paths = [p for p in glob.glob("abuse_whois/matchers/whois/rules/*.yaml")]


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert WhoisRule.model_validate(load_yaml(path))


@pytest.fixture
def godaddy_whois_record():
    with open("tests/fixtures/godaddy.com.json") as f:
        data = json.loads(f.read())
        return WhoisRecord.model_validate(data)


@pytest.fixture
def godaddy_whois_rule():
    return WhoisRule.model_validate(
        load_yaml("abuse_whois/matchers/whois/rules/godaddy.yaml")
    )


def test_godaddy(godaddy_whois_record: WhoisRecord, godaddy_whois_rule: WhoisRule):
    condition = godaddy_whois_rule.detection.condition
    assert (
        condition(godaddy_whois_rule, godaddy_whois_record.model_dump(by_alias=True))
        is True
    )
    assert condition(godaddy_whois_rule, {}) is False
