import glob

import pytest

from abuse_whois.matchers.shared_hosting.rule import SharedHostingRule

paths = [p for p in glob.glob("abuse_whois/matchers/shared_hosting/rules/*.yaml")]


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert SharedHostingRule.parse_file(path)


@pytest.fixture
def bitly_rule():
    return SharedHostingRule.parse_file(
        "abuse_whois/matchers/shared_hosting/rules/bitly.yaml"
    )


def test_bit_ly(bitly_rule: SharedHostingRule):
    condition = bitly_rule.detection.condition
    assert condition(bitly_rule, {"domain": "bit.ly"}) is True
    assert condition(bitly_rule, {"domain": ""}) is False
