from dataclasses import dataclass, field
from typing import Optional

from .utils import is_email, is_url


@dataclass
class Contact:
    provider: str
    address: str
    type: str = field(default="email")

    def __post_init__(self):
        if is_email(self.address):
            self.type = "email"

        if is_url(self.address):
            self.type = "form"


@dataclass
class BaseRule:
    contact: Contact

    def match(self, hostname: str) -> Optional[Contact]:
        raise NotImplementedError()


@dataclass
class Contacts:
    address: str
    hostname: str
    ip_address: Optional[str] = field(default=None)

    shared_hosting_provider: Optional[Contact] = field(default=None)
    registrar: Optional[Contact] = field(default=None)
    hosting_provider: Optional[Contact] = field(default=None)
