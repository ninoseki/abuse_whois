import pathlib
from functools import lru_cache

from abuse_whois.utils import load_yaml

from .rule import SharedHostingRule


@lru_cache(maxsize=1)
def load_rules() -> list[SharedHostingRule]:
    rules: list[SharedHostingRule] = []
    for path in pathlib.Path(__file__).parent.glob("./rules/*.yaml"):
        data = load_yaml(path)
        rules.append(SharedHostingRule.parse_obj(data))

    return rules
