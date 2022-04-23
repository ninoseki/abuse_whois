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
WHOIS_TIMEOUT: int = config("WHOIS_TIMEOUT", cast=int, default=10)
WHOIS_RECORD_CACHE_SIZE: int = config("WHOIS_RECORD_CACHE_SIZE", cast=int, default=1024)
WHOIS_RECORD_CACHE_TTL: int = config(
    "WHOIS_RECORD_CACHE_TTL", cast=int, default=60 * 60
)
