from typing import Any

from pydantic import root_validator

from abuse_whois.pysigma import schemas
from abuse_whois.pysigma.factories import RuleFactory
from abuse_whois.pysigma.validator import SigmaValidator

from .api_model import APIModel
from .contact import Contact


class BaseRule(APIModel):
    title: str
    description: str
    detection: Any

    contact: Contact

    @root_validator
    def validate_detection(cls, values: dict[str, Any]):
        detection = values.get("detection")
        if detection is None:
            return values

        validator = SigmaValidator(values)
        if len(validator.file_errors) > 0:
            raise ValueError(validator.file_errors)

        return values

    @property
    def sigma_rule(self) -> schemas.Rule | None:
        if self.detection is None:
            return None

        return RuleFactory.from_data(self.dict())

    async def match(self, hostname: str) -> bool:
        raise NotImplementedError()
