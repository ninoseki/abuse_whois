import itertools
import pathlib
from pathlib import Path

from returns.maybe import Maybe

from abuse_whois import schemas, settings
from abuse_whois.utils import is_email, unique

DEFAULT_RULE_DIRECTORY: pathlib.Path = pathlib.Path(__file__).parent / "./rules"


class WhoisRule(schemas.Rule):
    def match(self, record: schemas.WhoisRecord) -> bool:
        return super().match(record.model_dump(by_alias=True))


class WhoisRuleSet(schemas.RootAPIModel):
    root: list[WhoisRule]

    @classmethod
    def from_dir(cls, dir: str | Path = DEFAULT_RULE_DIRECTORY):
        dir = Path(dir) if isinstance(dir, str) else dir
        paths = itertools.chain.from_iterable(
            [dir.glob(f"**/*.{ext}") for ext in settings.RULE_EXTENSIONS]
        )
        return cls(root=[WhoisRule.model_validate_file(p) for p in paths])


def load_rule_set():
    base = WhoisRuleSet.from_dir(DEFAULT_RULE_DIRECTORY)
    addition = (
        WhoisRuleSet(root=[])
        if settings.ADDITIONAL_WHOIS_RULE_DIRECTORY is None
        else WhoisRuleSet.from_dir(settings.ADDITIONAL_WHOIS_RULE_DIRECTORY)
    )
    return WhoisRuleSet(root=unique(addition.root + base.root, "id"))


default_rule_set = load_rule_set()


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
    rule_set = WhoisRuleSet(root=rules or default_rule_set.root)  # type: ignore
    for rule in rule_set:
        if rule.match(record):
            return rule.contact

    return get_registrar_contact(record)
