from typing import Literal

from pydantic import Field, model_validator

from abuse_whois.utils import is_email, is_url

from .api_model import APIModel
from .whois import WhoisRecord

ContactType = Literal["email", "form"]


class Contact(APIModel):
    provider: str = Field(..., description="Provider name")
    address: str = Field(..., description="Contact address")
    type: ContactType = Field(default="email", description="Type of contact method")

    @model_validator(mode="after")
    def change_type(self):
        if is_email(self.address):
            self.type = "email"
        elif is_url(self.address):
            self.type = "form"

        return self


class ContactsRecords(APIModel):
    domain: WhoisRecord | None = Field(
        default=None, description="Domain Whois/RDAP record"
    )
    ip_address: WhoisRecord | None = Field(
        default=None, description="IP Address Whois/RDAP record"
    )


class Contacts(APIModel):
    address: str
    hostname: str = Field(..., description="Hostname")

    ip_address: str | None = Field(None, description="IP address")
    registered_domain: str | None = Field(
        None, description="Registered domain (a.k.a. free level domain)"
    )

    shared_hosting_provider: Contact | None = Field(
        None, description="Shared hosting provider"
    )
    registrar: Contact | None = Field(None, description="Registrar")
    hosting_provider: Contact | None = Field(None, description="Hosting provider")

    records: ContactsRecords = Field(..., description="Domain/IP Whois records")
