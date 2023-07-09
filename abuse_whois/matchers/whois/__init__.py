import re

from abuse_whois.schemas import Contact, WhoisRecord
from abuse_whois.utils import is_email
from abuse_whois.whois import get_whois_record

from .rules import load_rules


def get_whois_abuse_contact_by_regexp(
    record: WhoisRecord,
    *,
    email_pattern: str = r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+"
) -> str | None:
    matches = re.findall(email_pattern, record.raw_text)
    if len(matches) == 0:
        return None

    # returns the email address which contains "abuse"
    emails = [str(match) for match in matches if is_email(str(match))]
    emails.reverse()

    for email in emails:
        if "abuse" in email:
            return email

    return None


def get_whois_abuse_contact(record: WhoisRecord) -> Contact | None:
    provider = record.registrar
    email: str | None = None

    # check email format for just in case
    if is_email(record.abuse.email or ""):
        email = record.abuse.email

    if email is None:
        # fallback to regexp based search
        email = get_whois_abuse_contact_by_regexp(record)
        if email is None:
            return None

    # use email's domain as a provider if provider is None
    if provider is None and is_email(email or ""):
        provider = email.split("@")[-1]

    if provider is None or email is None:
        return None

    return Contact(provider=provider, address=email)


async def get_whois_contact(
    hostname: str,
) -> Contact | None:
    rules = load_rules()
    for rule in rules:
        if await rule.match(hostname):
            return rule.contact

    # Use whois registrar & abuse data
    try:
        whois_record = await get_whois_record(hostname)
    except Exception:
        return None

    return get_whois_abuse_contact(whois_record)


async def get_optional_whois_contact(hostname: str | None) -> Contact | None:
    if hostname is None:
        return None

    return await get_whois_contact(hostname)
