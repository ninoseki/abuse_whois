from abuse_whois.matchers.shared_hosting.rules import load_rules


def test_load_rules():
    assert len(load_rules()) > 0
