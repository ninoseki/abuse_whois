import asyncio

import stamina
from asyncache import cached
from cachetools import TTLCache

from . import errors, services, settings


@stamina.retry(
    on=(asyncio.TimeoutError, errors.RateLimitError),
    attempts=settings.QUERY_MAX_RETRIES,
    timeout=None,
)
@cached(cache=TTLCache(maxsize=settings.QUERY_CACHE_SIZE, ttl=settings.QUERY_CACHE_TTL))
async def query(
    hostname: str,
    *,
    timeout: int = settings.QUERY_TIMEOUT,
):
    return await services.WhoisQuery().call(hostname=hostname, timeout=timeout)
