import datetime
import uuid
from dataclasses import dataclass, field
from typing import Any

from .exceptions import RuleLoadError, UnsupportedFeature
from .factories import RuleFactory

MANDATORY_FIELDS = [
    "title",
    "detection",
]
OPTIONAL_FIELDS = [
    "author",
    "description",
    "falsepositives",
    "fields",
    "id",
    "level",
    "logsource",
    "references",
    "related",
    "status",
    "tags",
]


def validate_date(date_text: str):
    try:
        if date_text != datetime.datetime.strptime(date_text, "%Y/%m/%d").strftime(
            "%Y/%m/%d"
        ):
            raise ValueError
        return True
    except ValueError:
        return False


def validate_uuid(value: str):
    # Checks if uuid complies with version 4 uuid
    try:
        uuid.UUID(str(value), version=4)
        return True
    except ValueError:
        return False


@dataclass
class SigmaReturn:
    msg: str
    key: str
    description: str | None = field(default=None)


class SigmaValidator:
    def __init__(self, data: dict[Any, Any]):
        self.data = data
        self.file_errors: list[SigmaReturn] = []
        self.sigma_rules = None

        self.validate_errors()

    def validate_errors(self):
        errors: list[SigmaReturn] = []
        for key in MANDATORY_FIELDS:
            if key not in self.data:
                errors.append(SigmaReturn("Missing field ", key))

        # Test signature load
        try:
            RuleFactory.from_data(self.data)
        except ValueError as e:
            errors.append(SigmaReturn("Signature Load error", e))
        except RuleLoadError as e:
            errors.append(SigmaReturn("Signature Load error", e))
        except UnsupportedFeature as e:
            errors.append(SigmaReturn("Unsupported feature ", e))

        self.file_errors = errors
