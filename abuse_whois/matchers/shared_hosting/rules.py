import pathlib
from typing import List

from abuse_whois.utils import load_yaml

from .rule import SharedHostingRule


def load_rules() -> List[SharedHostingRule]:
    rules: List[SharedHostingRule] = []
    for path in pathlib.Path(__file__).parent.glob("./rules/*.yaml"):
        data = load_yaml(path)
        rules.append(SharedHostingRule.parse_obj(data))

    return rules
