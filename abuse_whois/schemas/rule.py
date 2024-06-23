import azuma

from .api_model import APIModel, RootAPIModel
from .contact import Contact


class Rule(APIModel, azuma.Rule):
    contact: Contact


class RuleSet(RootAPIModel, azuma.RuleSet):
    pass
