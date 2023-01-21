from datetime import datetime

from pydantic import Field

from .api_model import APIModel


class Contact(APIModel):
    organization: str | None = None
    email: str | None = None
    name: str | None = None
    telephone: str | None = None


class Abuse(APIModel):
    email: str | None = None
    telephone: str | None = None


class WhoisRecord(APIModel):
    raw_text: str

    tech: Contact
    admin: Contact
    registrant: Contact
    abuse: Abuse

    statuses: list[str] = Field(default_factory=list)
    name_servers: list[str] = Field(default_factory=list)

    domain: str | None = None
    registrar: str | None = None

    expires_at: datetime | str | None = None
    registered_at: datetime | str | None = None
    updated_at: datetime | str | None = None
