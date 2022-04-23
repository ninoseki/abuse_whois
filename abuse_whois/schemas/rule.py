from .api_model import APIModel
from .contact import Contact


class BaseRule(APIModel):
    contact: Contact

    async def match(self, hostname: str) -> bool:
        raise NotImplementedError()
