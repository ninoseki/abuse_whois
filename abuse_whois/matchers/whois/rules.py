import pathlib
from functools import lru_cache

from abuse_whois.utils import load_yaml

from .rule import WhoisRule


@lru_cache(maxsize=1)
def load_rules() -> list[WhoisRule]:
    paths = pathlib.Path(__file__).parent.glob("./rules/*.yaml")
    return [WhoisRule.parse_obj(load_yaml(path)) for path in paths]
