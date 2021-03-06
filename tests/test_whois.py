import pytest

from abuse_whois.errors import TimeoutError
from abuse_whois.whois import get_whois_record


@pytest.mark.asyncio
async def test_timeout_error():
    with pytest.raises(TimeoutError):
        assert await get_whois_record("github.com", timeout=-1)
