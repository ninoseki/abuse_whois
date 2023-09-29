import asyncio

import pytest

from abuse_whois import services


@pytest.mark.asyncio
async def test_with_timeout():
    with pytest.raises(asyncio.TimeoutError):
        assert await services.WhoisQuery().call("example.com", timeout=-1)
