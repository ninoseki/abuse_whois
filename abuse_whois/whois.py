import asyncio
import functools
import shlex
import warnings

from asyncache import cached
from cachetools import TTLCache
from whois_parser import WhoisParser

from . import schemas, settings
from .errors import TimeoutError
from .utils import get_registered_domain, is_ip_address

# Ignore dateparser warnings regarding pytz
# ref. https://github.com/scrapinghub/dateparser/issues/1013
warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)


@functools.lru_cache(maxsize=1)
def get_whois_parser() -> WhoisParser:
    return WhoisParser()


def parse(raw_text: str, hostname: str) -> schemas.WhoisRecord:
    parser = get_whois_parser()
    record = parser.parse(raw_text, hostname=hostname)

    return schemas.WhoisRecord.parse_obj(record.to_dict())


@cached(
    cache=TTLCache(
        maxsize=settings.WHOIS_LOOKUP_CACHE_SIZE, ttl=settings.WHOIS_LOOKUP_CACHE_TTL
    )
)
async def get_whois_record(
    hostname: str, *, timeout: int = settings.WHOIS_LOOKUP_TIMEOUT
) -> schemas.WhoisRecord:
    if not is_ip_address(hostname):
        hostname = get_registered_domain(hostname) or hostname

    # open a new process for "whois" command
    cmd = f"whois {shlex.quote(hostname)}"
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        # block for query_result
        query_result_, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        query_result = query_result_.decode(errors="ignore")
        query_result = query_result.strip()
    except asyncio.TimeoutError:
        raise TimeoutError(f"{timeout} seconds have passed but there is no response")

    return parse(query_result, hostname)
