import pytest

from abuse_whois.errors import TimeoutError
from abuse_whois.ip import resolve_ip_address


def test_timeout_error():
    with pytest.raises(TimeoutError):
        assert resolve_ip_address("github.com", timeout=-1)
