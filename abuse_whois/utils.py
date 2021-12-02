import pathlib
from typing import Dict, Optional, Union, cast
from urllib.parse import urlparse

import tldextract
import yaml
from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, ValidationError
from pydantic.networks import AnyHttpUrl


class UrlModel(BaseModel):
    url: AnyHttpUrl


def is_ip_address(v: str) -> bool:
    try:
        model = UrlModel(url=f"http://{v}")
        return model.url.host_type in ["ipv4", "ipv6"]
    except ValidationError:
        return False


def is_domain(v: str) -> bool:
    if len(v.split(".")) == 1:
        return False

    if "@" in v:
        return False

    try:
        model = UrlModel(url=f"http://{v}")
        return model.url.host_type in ["domain", "int_domain"]
    except ValidationError:
        return False


def is_url(v: str) -> bool:
    if not v.startswith(("http://", "https://")):
        return False

    try:
        UrlModel(url=v)
        return True
    except ValidationError:
        return False


def is_email(v: str) -> bool:
    try:
        validate_email(v, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def is_supported_address(v: str) -> bool:
    if is_domain(v) or is_ip_address(v) or is_email(v) or is_url(v):
        return True

    return False


def get_registered_domain(v: str) -> Optional[str]:
    parsed = tldextract.extract(v)

    if parsed.registered_domain == "":
        return None

    return parsed.registered_domain


def get_hostname(value: str) -> str:
    if is_ip_address(value) or is_domain(value):
        return value

    if is_email(value):
        value = f"http://{value}"

    parsed = urlparse(value)
    return parsed.hostname or value


def load_yaml(path: Union[str, pathlib.Path]) -> Dict:
    with open(path) as f:
        return cast(Dict, yaml.safe_load(f))
