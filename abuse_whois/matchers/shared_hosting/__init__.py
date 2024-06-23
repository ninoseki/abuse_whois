import itertools
import pathlib
from pathlib import Path

from abuse_whois import schemas, settings
from abuse_whois.utils import unique

DEFAULT_RULE_DIRECTORY: pathlib.Path = pathlib.Path(__file__).parent / "./rules"


class SharedHostingRule(schemas.Rule):
    def match(self, hostname: str) -> bool:
        return super().match({"domain": hostname})


class SharedHostingRuleSet(schemas.RootAPIModel):
    root: list[SharedHostingRule]

    @classmethod
    def from_dir(cls, dir: str | Path = DEFAULT_RULE_DIRECTORY):
        dir = Path(dir) if isinstance(dir, str) else dir
        paths = itertools.chain.from_iterable(
            [dir.glob(f"**/*.{ext}") for ext in settings.RULE_EXTENSIONS]
        )
        return cls(root=[SharedHostingRule.model_validate_file(p) for p in paths])


def load_rule_set():
    base = SharedHostingRuleSet.from_dir()
    addition = (
        SharedHostingRuleSet(root=[])
        if settings.ADDITIONAL_WHOIS_RULE_DIRECTORY is None
        else SharedHostingRuleSet.from_dir(settings.ADDITIONAL_WHOIS_RULE_DIRECTORY)
    )
    return SharedHostingRuleSet(root=unique(addition.root + base.root, key="id"))


default_rule_set = load_rule_set()


def get_shared_hosting_provider(
    hostname: str, *, rules: list[SharedHostingRule] | None = None
) -> schemas.Contact | None:
    rule_set = SharedHostingRuleSet(root=rules or default_rule_set.root)
    for rule in rule_set:
        if rule.match(hostname):
            return rule.contact

    return None
