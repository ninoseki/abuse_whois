from typing import Optional

from .api_model import APIModel
from .contact import Contact


class BaseRule(APIModel):
    contact: Contact

    def match(self, hostname: str) -> Optional[Contact]:
        raise NotImplementedError()
