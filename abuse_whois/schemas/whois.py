from datetime import datetime

from pydantic import Field

from .api_model import APIModel


class WhoisContact(APIModel):
    organization: str | None = None
    email: str | None = None
    name: str | None = None
    telephone: str | None = None


class WhoisAbuse(APIModel):
    email: str | None = None
    telephone: str | None = None


class WhoisRecord(APIModel):
    raw_text: str

    tech: WhoisContact
    admin: WhoisContact
    registrant: WhoisContact
    abuse: WhoisAbuse

    statuses: list[str] = Field(default_factory=list)
    name_servers: list[str] = Field(default_factory=list)

    domain: str | None = None
    registrar: str | None = None

    expires_at: datetime | str | None = None
    registered_at: datetime | str | None = None
    updated_at: datetime | str | None = None
