import asyncio

import stamina

from . import errors, services, settings


@stamina.retry(
    on=(asyncio.TimeoutError, errors.RateLimitError),
    attempts=settings.QUERY_MAX_RETRIES,
    timeout=None,
)
async def query(
    hostname: str,
    *,
    timeout: int = settings.QUERY_TIMEOUT,
):
    return await services.WhoisQuery().call(hostname=hostname, timeout=timeout)
