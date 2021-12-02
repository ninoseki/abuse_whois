import functools
import warnings
from typing import cast

import sh
from whois_parser import WhoisParser
from whois_parser.dataclasses import WhoisRecord

from .utils import get_registered_domain, is_ip_address

# Ignore dateparser warnings regarding pytz
# ref. https://github.com/scrapinghub/dateparser/issues/1013
warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)


@functools.lru_cache()
def get_whois_command() -> sh.Command:
    return sh.Command("whois")


@functools.lru_cache()
def get_whois_parser() -> WhoisParser:
    return WhoisParser()


@functools.lru_cache(maxsize=1024)
def get_whois_record(hostname: str) -> WhoisRecord:
    if not is_ip_address(hostname):
        hostname = get_registered_domain(hostname) or hostname

    whois = get_whois_command()
    result = cast(sh.RunningCommand, whois(hostname))
    whois_text = str(result)

    parser = get_whois_parser()
    return parser.parse(whois_text, hostname=hostname)
