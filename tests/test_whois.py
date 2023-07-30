import asyncio

import pytest
from pytest_mock import MockerFixture
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


@pytest.mark.asyncio
async def test_with_rate_limit(mocker: MockerFixture, whois_record: WhoisRecord):
    mocker.patch("abuse_whois.whois.parse", return_value=whois_record)

    with pytest.raises(RateLimitError):
        assert await get_whois_record("example.com")
