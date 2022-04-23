import sys

from starlette.config import Config

config = Config(".env")

# FastAPI settings

PROJECT_NAME: str = config("PROJECT_NAME", default="abuse-whois")

DEBUG: bool = config("DEBUG", cast=bool, default=False)
TESTING: bool = config("TESTING", cast=bool, default=False)

LOG_FILE = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE: bool = config("LOG_BACKTRACE", cast=bool, default=True)

# Abuse Whois setting
WHOIS_LOOKUP_TIMEOUT: int = config("WHOIS_LOOKUP_TIMEOUT", cast=int, default=10)
WHOIS_LOOKUP_CACHE_SIZE: int = config("WHOIS_LOOKUP_CACHE_SIZE", cast=int, default=1024)
WHOIS_LOOKUP_CACHE_TTL: int = config(
    "WHOIS_LOOKUP_CACHE_TTL", cast=int, default=60 * 60
)


IP_ADDRESS_LOOKUP_TIMEOUT: int = config(
    "IP_ADDRESS_LOOKUP_TIMEOUT", cast=int, default=10
)
IP_ADDRESS_LOOKUP_CACHE_SIZE: int = config(
    "IP_ADDRESS_LOOKUP_CACHE_SIZE", cast=int, default=1024
)
IP_ADDRESS_LOOKUP_CACHE_TTL: int = config(
    "IP_ADDRESS_LOOKUP_CACHE_TTL", cast=int, default=60 * 60
)
