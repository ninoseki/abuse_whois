from datetime import datetime
from typing import List, Optional, Union

from pydantic import Field

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

    statuses: List[str] = Field(default_factory=list)
    name_servers: List[str] = Field(default_factory=list)

    domain: Optional[str] = None
    registrar: Optional[str] = None

    expires_at: Optional[Union[datetime, str]] = None
    registered_at: Optional[Union[datetime, str]] = None
    updated_at: Optional[Union[datetime, str]] = None
