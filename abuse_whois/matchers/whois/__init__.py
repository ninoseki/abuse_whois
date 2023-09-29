from abuse_whois import schemas
from abuse_whois.utils import is_email

from .rule import WhoisRule
from .rules import load_rules


def get_registrar_contact(record: schemas.WhoisRecord) -> schemas.Contact | None:
    provider = record.registrar
    email: str | None = None

    # check email format for just in case
    if is_email(record.abuse.email or ""):
        email = record.abuse.email

    if email is None:
        return None

    # use email's domain as a provider if provider is None
    if provider is None and is_email(email or ""):
        provider = email.split("@")[-1]

    if provider is None or email is None:
        return None

    return schemas.Contact(provider=provider, address=email)


def get_whois_contact(
    record: schemas.WhoisRecord, *, rules: list[WhoisRule] | None = None
) -> schemas.Contact | None:
    rules = rules or load_rules()
    for rule in rules:
        if rule.match(record):
            return rule.contact

    return get_registrar_contact(record)
