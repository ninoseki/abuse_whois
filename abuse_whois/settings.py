import sys

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings

config = Config(".env")

# FastAPI settings
PROJECT_NAME: str = config("PROJECT_NAME", default="abuse-whois")

DEBUG: bool = config("DEBUG", cast=bool, default=False)
TESTING: bool = config("TESTING", cast=bool, default=False)

LOG_FILE = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE: bool = config("LOG_BACKTRACE", cast=bool, default=True)

# Query settings
QUERY_TIMEOUT: int = config("QUERY_TIMEOUT", cast=int, default=10)
QUERY_CACHE_SIZE: int = config("QUERY_CACHE_SIZE", cast=int, default=1024)
QUERY_CACHE_TTL: int = config("QUERY_CACHE_TTL", cast=int, default=60 * 60)
QUERY_MAX_RETRIES: int = config("QUERY_MAX_RETRIES", cast=int, default=3)

# Rule settings
RULE_EXTENSIONS: CommaSeparatedStrings = config(
    "RULE_EXTENSIONS", cast=CommaSeparatedStrings, default="yaml,yml"
)
ADDITIONAL_WHOIS_RULE_DIRECTORIES: CommaSeparatedStrings = config(
    "ADDITIONAL_WHOIS_RULE_DIRECTORIES", cast=CommaSeparatedStrings, default=""
)
ADDITIONAL_SHARED_HOSTING_RULE_DIRECTORIES: CommaSeparatedStrings = config(
    "ADDITIONAL_SHARED_HOSTING_RULE_DIRECTORIES", cast=CommaSeparatedStrings, default=""
)

# Etc.
WHOIS_RATE_LIMIT_MESSAGES: set[str] = {
    "WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS",
    "Your access is too fast,please try again later.",
    "Your connection limit exceeded.",
    "Number of allowed queries exceeded.",
    "WHOIS LIMIT EXCEEDED",
    "Requests of this client are not permitted.",
    "Too many connection attempts. Please try again in a few seconds.",
    "We are unable to process your request at this time.",
    "HTTP/1.1 400 Bad Request",
    "Closing connections because of Timeout",
    "Access to whois service at whois.isoc.org.il was **DENIED**",
    "IP Address Has Reached Rate Limit",
}
