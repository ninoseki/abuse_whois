import copy
from typing import Any

from abuse_whois.pysigma import schemas

from .detection import DetectionFactory


class RuleFactory:
    @staticmethod
    def from_data(data: dict[Any, Any]):
        new_data = copy.deepcopy(data)

        detection = None
        if "detection" in data:
            detection = DetectionFactory.from_data(data=new_data)

        new_data["detection"] = detection
        return schemas.Rule.parse_obj(new_data)
