import pathlib
from functools import lru_cache

from ... import settings
from ...utils import glob_rules, load_yaml
from .rule import WhoisRule

DEFAULT_RULE_DIRECTORY: pathlib.Path = pathlib.Path(__file__).parent / "./rules"


@lru_cache(maxsize=1)
def load_rules() -> list[WhoisRule]:
    paths = glob_rules(
        DEFAULT_RULE_DIRECTORY,
        additional_directories=settings.ADDITIONAL_WHOIS_RULE_DIRECTORIES,
    )
    return [WhoisRule.model_validate(load_yaml(path)) for path in paths]
