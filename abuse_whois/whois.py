import asyncio
from dataclasses import asdict

import stamina
from asyncache import cached
from asyncwhois.query import DomainQuery, NumberQuery
from cachetools import TTLCache
from whois_parser import WhoisParser, WhoisRecord

from . import schemas, settings
from .errors import RateLimitError
from .utils import get_registered_domain, is_domain, is_ip_address

whois_parser = WhoisParser()


def parse(
    raw_text: str, hostname: str, *, parser: WhoisParser = whois_parser
) -> WhoisRecord:
    return parser.parse(raw_text, hostname=hostname)


async def query(address: str, *, timeout: int = settings.WHOIS_LOOKUP_TIMEOUT) -> str:
    klass = DomainQuery if is_domain(address) else NumberQuery
    query = await klass.new_aio(address, timeout=timeout)
    return query.query_output


@stamina.retry(
    on=(asyncio.TimeoutError, RateLimitError),
    attempts=settings.WHOIS_LOOKUP_MAX_RETRIES,
    timeout=None,
)
@cached(
    cache=TTLCache(
        maxsize=settings.WHOIS_LOOKUP_CACHE_SIZE, ttl=settings.WHOIS_LOOKUP_CACHE_TTL
    )
)
async def get_whois_record(
    hostname: str,
    *,
    timeout: int = settings.WHOIS_LOOKUP_TIMEOUT,
    parser: WhoisParser = whois_parser
) -> schemas.WhoisRecord:
    if not is_ip_address(hostname):
        hostname = get_registered_domain(hostname) or hostname

    query_result = await query(hostname, timeout=timeout)
    query_result = "\n".join(query_result.splitlines())

    parsed = parse(query_result, hostname, parser=parser)
    if parsed.is_rate_limited:
        raise RateLimitError()

    return schemas.WhoisRecord.model_validate(asdict(parsed))
