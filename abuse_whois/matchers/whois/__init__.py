import re
from typing import Optional, Pattern

from whois_parser.dataclasses import WhoisRecord

from abuse_whois.schemas import Contact
from abuse_whois.whois import get_whois_record

from .rules import load_rules


def get_whois_abuse_contact_by_regexp(
    record: WhoisRecord, *, abuse_email_pattern: Pattern = r"abuse@[a-z0-9\-.]+"
) -> Optional[Contact]:
    provider = record.registrar or ""

    matches = re.findall(abuse_email_pattern, record.raw_text)
    if len(matches) == 0:
        return None

    email = matches[-1]

    return Contact(provider=provider, address=email)


def get_whois_abuse_contact(record: WhoisRecord) -> Optional[Contact]:
    provider = record.registrar
    email = record.abuse.email

    if email is None:
        # fallback to regexp based search
        return get_whois_abuse_contact_by_regexp(record)

    return Contact(provider=provider, address=email)


def get_contact_from_whois(
    hostname: str,
) -> Optional[Contact]:
    rules = load_rules()
    for rule in rules:
        if rule.match(hostname):
            return rule.contact

    # Use whois registrar & abuse data
    try:
        whois_record = get_whois_record(hostname)
    except Exception:
        return None

    return get_whois_abuse_contact(whois_record)
