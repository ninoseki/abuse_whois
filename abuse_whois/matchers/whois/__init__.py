from returns.maybe import Maybe

from abuse_whois import schemas
from abuse_whois.utils import is_email

from .rule import WhoisRule
from .rules import load_rules


def normalize_abuse_email(email: str | None) -> str | None:
    return (
        Maybe.from_optional(email)
        .bind_optional(lambda x: x.removeprefix("mailto:"))
        .value_or(None)
    )


def get_provider(record: schemas.WhoisRecord) -> str | None:
    def inner(email: str) -> str | None:
        if not is_email(email):
            return None

        # use email's domain as a provider if provider is None
        return email.split("@")[-1]

    return (
        Maybe.from_optional(normalize_abuse_email(record.abuse.email))
        .bind_optional(inner)
        .value_or(record.registrar)
    )


def get_address(record: schemas.WhoisRecord) -> str | None:
    def inner(email: str) -> str | None:
        # check email format for just in case
        if not is_email(email):
            return None

        return email

    return (
        Maybe.from_optional(normalize_abuse_email(record.abuse.email))
        .bind_optional(inner)
        .value_or(None)
    )


def get_registrar_contact(record: schemas.WhoisRecord) -> schemas.Contact | None:
    provider = get_provider(record)
    address = get_address(record)

    if provider is None or address is None:
        return None

    return schemas.Contact(provider=provider, address=address)


def get_whois_contact(
    record: schemas.WhoisRecord, *, rules: list[WhoisRule] | None = None
) -> schemas.Contact | None:
    rules = rules or load_rules()
    for rule in rules:
        if rule.match(record):
            return rule.contact

    return get_registrar_contact(record)
