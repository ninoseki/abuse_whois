from abuse_whois.schemas import Contact

from .rules import load_rules


def get_shared_hosting_provider(hostname: str) -> Contact | None:
    rules = load_rules()
    for rule in rules:
        if rule.match(hostname):
            return rule.contact

    return None
