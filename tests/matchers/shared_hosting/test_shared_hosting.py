import pytest

from abuse_whois.matchers.shared_hosting import get_shared_hosting_provider


@pytest.mark.parametrize(
    "hostname",
    ["foo.bit.ly", "foo.blogger.com"],
)
def test_get_shared_hosting_provider(hostname: str):
    assert get_shared_hosting_provider(hostname) is not None
