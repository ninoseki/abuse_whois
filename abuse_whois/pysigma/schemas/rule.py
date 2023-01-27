from pydantic import Field

from .base_model import BaseModel
from .detection import Condition, Detection, DetectionField


class Rule(BaseModel):
    title: str = Field(...)
    detection: Detection = Field(...)

    author: str | None = Field(default=None)
    description: str | None = Field(default=None)
    id: str | None = Field(default=None)
    level: str | None = Field(default=None)
    status: str | None = Field(default=None)

    references: list[str] | None = Field(default=None)
    tags: list[str] | None = Field(default=None)

    related: dict[str, str] | None = Field(default=None)
    logsource: dict[str, str] | None = Field(default=None)

    def get_condition(self) -> Condition | None:
        return self.detection.condition

    def get_all_searches(self) -> dict[str, DetectionField]:
        return self.detection.detection

    def get_search_fields(self, search_id) -> DetectionField | None:
        return self.detection.detection.get(search_id)
