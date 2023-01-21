import pathlib
from functools import lru_cache

from abuse_whois.utils import load_yaml

from .rule import WhoisRule


@lru_cache(maxsize=1)
def load_rules() -> list[WhoisRule]:
    rules: list[WhoisRule] = []
    for path in pathlib.Path(__file__).parent.glob("./rules/*.yaml"):
        data = load_yaml(path)
        rules.append(WhoisRule.parse_obj(data))

    return rules
