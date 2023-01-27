import glob

import pytest

from abuse_whois.matchers.shared_hosting.rule import SharedHostingRule
from abuse_whois.pysigma.parser import check_event
from abuse_whois.utils import load_yaml

paths = [p for p in glob.glob("abuse_whois/matchers/shared_hosting/rules/*.yaml")]


@pytest.mark.parametrize("path", paths)
def test_load_rules(path: str):
    assert SharedHostingRule.parse_obj(load_yaml(path))


@pytest.fixture
def bitly_rule():
    return SharedHostingRule.parse_obj(
        load_yaml("abuse_whois/matchers/shared_hosting/rules/bitly.yaml")
    )


def test_godaddy(bitly_rule: SharedHostingRule):
    sigma_rule = bitly_rule.sigma_rule
    alerts = check_event({"domain": "bit.ly"}, sigma_rule)
    assert len(alerts) > 0

    alerts = check_event({"domain": "example.com"}, sigma_rule)
    assert len(alerts) == 0
