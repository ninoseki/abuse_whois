import azuma

from .api_model import APIModel
from .contact import Contact


class BaseRule(APIModel, azuma.Rule):
    contact: Contact
