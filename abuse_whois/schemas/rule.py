from typing import Any

from pydantic import Field

from abuse_whois.pysigma import schemas
from abuse_whois.pysigma.factories import RuleFactory

from .api_model import APIModel
from .contact import Contact


class BaseRule(APIModel):
    contact: Contact

    base_domains: list[str] = Field(default_factory=list)

    detection: Any | None = Field(default=None)

    def to_sigma_rule(self) -> schemas.Rule | None:
        if self.detection is None:
            return None

        data = {"title": self.contact.provider, "detection": self.detection}
        return RuleFactory.from_data(data)

    async def match(self, hostname: str) -> bool:
        raise NotImplementedError()
