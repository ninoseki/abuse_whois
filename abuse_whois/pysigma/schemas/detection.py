import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Optional, Union

from pydantic import Field

from .base_model import BaseModel

if TYPE_CHECKING:
    pass

Query = Optional[Union[str, re.Pattern, Any]]
DetectionMap = list[tuple[str, tuple[list[Query], list[str]]]]
Condition = Callable[["Rule", dict[Any, Any]], Any]


class DetectionField(BaseModel):
    list_search: list[Query] = Field(default_factory=list)
    map_search: list[DetectionMap] = Field(default_factory=list)


class Detection(BaseModel):
    detection: dict[str, DetectionField] = Field(...)
    condition: Condition | None = Field(default=None)
