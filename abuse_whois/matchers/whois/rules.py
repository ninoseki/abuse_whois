import pathlib
from typing import List

from abuse_whois.utils import load_yaml

from .rule import WhoisRule


def load_rules() -> List[WhoisRule]:
    rules: List[WhoisRule] = []
    for path in pathlib.Path(__file__).parent.glob("./rules/*.yaml"):
        data = load_yaml(path)
        rules.append(WhoisRule.parse_obj(data))

    return rules
