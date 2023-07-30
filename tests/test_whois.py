import asyncio
from unittest.mock import MagicMock

import pytest
from whois_parser.dataclasses import WhoisRecord
from whois_parser.parser import WhoisParser

from abuse_whois.errors import RateLimitError
from abuse_whois.whois import get_whois_record


@pytest.mark.asyncio
async def test_timeout_error():
    with pytest.raises(asyncio.TimeoutError):
        assert await get_whois_record("example.com", timeout=-1)


@pytest.fixture
def whois_record() -> WhoisRecord:
    record = WhoisParser().parse("", hostname="example.com")
    record.is_rate_limited = True
    return record


@pytest.fixture
def mock(whois_record: WhoisRecord):
    m = MagicMock()
    m.parse.return_value = whois_record
    return m


@pytest.mark.asyncio
async def test_with_rate_limit(mock: MagicMock):
    with pytest.raises(RateLimitError):
        assert await get_whois_record("example.com", parser=mock)
