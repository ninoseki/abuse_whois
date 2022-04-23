import pytest

from abuse_whois.errors import TimeoutError
from abuse_whois.whois import _get_whois_record


def test_timeout_error():
    with pytest.raises(TimeoutError):
        assert _get_whois_record("github.com", timeout=-1)
