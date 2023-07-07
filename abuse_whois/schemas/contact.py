from typing import Any, Literal

from pydantic import Field

from abuse_whois.schemas.whois import WhoisRecord
from abuse_whois.utils import is_email, is_url

from .api_model import APIModel


class Contact(APIModel):
    provider: str = Field(..., description="Provider name")
    address: str = Field(..., description="Contact address")
    type: Literal["email", "form"] = Field(
        "email", description="Type of contact method"
    )

    def __init__(self, **data: Any):
        super().__init__(**data)

        if is_email(self.address):
            self.type = "email"

        if is_url(self.address):
            self.type = "form"


class Contacts(APIModel):
    address: str
    hostname: str = Field(..., description="Host name")

    ip_address: str | None = Field(None, description="IP address")
    registered_domain: str | None = Field(
        None, description="Registered domain (a.k.a. free level domain)"
    )

    shared_hosting_provider: Contact | None = Field(
        None, description="Shared hosting provider"
    )
    registrar: Contact | None = Field(None, description="Registrar")
    hosting_provider: Contact | None = Field(None, description="Hosting provider")

    whois_record: WhoisRecord | None = Field(
        None, description="Whois record of hostname"
    )
