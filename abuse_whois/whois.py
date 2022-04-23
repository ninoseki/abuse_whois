import functools
import warnings
from typing import cast

import sh
from cachetools import TTLCache, cached
from whois_parser import WhoisParser
from whois_parser.dataclasses import WhoisRecord

from . import settings
from .errors import TimeoutError
from .utils import get_registered_domain, is_ip_address

# Ignore dateparser warnings regarding pytz
# ref. https://github.com/scrapinghub/dateparser/issues/1013
warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)


@functools.lru_cache(maxsize=1)
def get_whois_command() -> sh.Command:
    return sh.Command("whois")


@functools.lru_cache(maxsize=1)
def get_whois_parser() -> WhoisParser:
    return WhoisParser()


@cached(
    cache=TTLCache(
        maxsize=settings.WHOIS_RECORD_CACHE_SIZE, ttl=settings.WHOIS_RECORD_CACHE_TTL
    )
)
def get_whois_record(
    hostname: str, *, timeout: int = settings.WHOIS_TIMEOUT
) -> WhoisRecord:
    if not is_ip_address(hostname):
        hostname = get_registered_domain(hostname) or hostname

    whois = get_whois_command()
    try:
        result = cast(sh.RunningCommand, whois(hostname, _timeout=timeout))
    except sh.TimeoutException:
        raise TimeoutError(
            f"{settings.WHOIS_TIMEOUT} seconds have passed but there is no response"
        )

    whois_text = str(result)

    parser = get_whois_parser()
    return parser.parse(whois_text, hostname=hostname)
