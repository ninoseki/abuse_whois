from typing import Any

from abuse_whois.pysigma import schemas
from abuse_whois.pysigma.parser import prepare_condition
from abuse_whois.pysigma.utils import normalize_detection


class DetectionFactory:
    @staticmethod
    def from_data(*, data: dict[Any, Any]):
        detection: dict[Any, Any] = data["detection"]
        condition: schemas.Condition | None = None

        if "condition" in detection:
            condition = prepare_condition(detection.pop("condition"))

        detection = normalize_detection(detection)

        return schemas.Detection(
            detection=detection,
            condition=condition,
        )
