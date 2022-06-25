from datetime import datetime
from typing import Optional, Union

from .api_model import APIModel


class Contact(APIModel):
    organization: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    telephone: Optional[str] = None


class Abuse(APIModel):
    email: Optional[str] = None
    telephone: Optional[str] = None


class WhoisRecord(APIModel):
    raw_text: str

    tech: Contact
    admin: Contact
    registrant: Contact
    abuse: Abuse

    statuses: list[str]
    name_servers: list[str]

    domain: Optional[str] = None
    registrar: Optional[str] = None

    expires_at: Optional[Union[datetime, str]] = None
    registered_at: Optional[Union[datetime, str]] = None
    updated_at: Optional[Union[datetime, str]] = None
