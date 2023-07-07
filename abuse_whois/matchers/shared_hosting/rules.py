import pathlib
from functools import lru_cache

from abuse_whois import settings
from abuse_whois.utils import glob_rules, load_yaml

from .rule import SharedHostingRule

DEFAULT_RULE_DIRECTORY: pathlib.Path = pathlib.Path(__file__).parent / "./rules"


@lru_cache(maxsize=1)
def load_rules() -> list[SharedHostingRule]:
    paths = glob_rules(
        DEFAULT_RULE_DIRECTORY,
        additional_directories=settings.ADDITIONAL_SHARED_HOSTING_RULE_DIRECTORIES,
    )
    return [SharedHostingRule.model_validate(load_yaml(path)) for path in paths]
