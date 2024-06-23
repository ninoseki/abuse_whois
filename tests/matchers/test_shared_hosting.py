import glob

import pytest

from abuse_whois.matchers.shared_hosting import (
    SharedHostingRule,
    SharedHostingRuleSet,
    get_shared_hosting_provider,
)

paths = list(glob.glob("abuse_whois/matchers/shared_hosting/rules/*.yaml"))


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert SharedHostingRule.model_validate_file(path)


@pytest.fixture
def bitly_rule():
    return SharedHostingRule.model_validate_file(
        "abuse_whois/matchers/shared_hosting/rules/bitly.yaml"
    )


def test_bit_ly(bitly_rule: SharedHostingRule):
    condition = bitly_rule.detection.condition
    assert condition(bitly_rule, {"domain": "bit.ly"}) is True
    assert condition(bitly_rule, {"domain": ""}) is False


@pytest.mark.parametrize(
    "hostname",
    ["foo.bit.ly", "foo.blogger.com"],
)
def test_get_shared_hosting_provider(hostname: str):
    assert get_shared_hosting_provider(hostname) is not None


def test_shared_hosting_rule_set():
    rule_set = SharedHostingRuleSet.from_dir()
    assert len(rule_set.root) > 0
