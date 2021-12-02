from typing import Any, Optional

from pydantic import Field

from abuse_whois.utils import is_email, is_url

from .api_model import APIModel


class Contact(APIModel):
    provider: str
    address: str
    type: str = Field(default="email")

    def __init__(self, **data: Any):
        super().__init__(**data)

        if is_email(self.address):
            self.type = "email"

        if is_url(self.address):
            self.type = "form"


class Contacts(APIModel):
    address: str
    hostname: str
    ip_address: Optional[str] = None

    shared_hosting_provider: Optional[Contact] = None
    registrar: Optional[Contact] = None
    hosting_provider: Optional[Contact] = None
