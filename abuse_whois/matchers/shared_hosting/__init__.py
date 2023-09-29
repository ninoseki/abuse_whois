from abuse_whois.schemas import Contact

from .rule import SharedHostingRule
from .rules import load_rules


def get_shared_hosting_provider(
    hostname: str, *, rules: list[SharedHostingRule] | None = None
) -> Contact | None:
    rules = rules or load_rules()

    for rule in rules:
        if rule.match(hostname):
            return rule.contact

    return None
