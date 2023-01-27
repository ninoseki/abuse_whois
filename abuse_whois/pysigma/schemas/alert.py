from typing import Any

from pydantic import Field

from .base_model import BaseModel
from .rule import Rule


class Alert(BaseModel):
    event: dict[Any, Any] = Field(...)
    rule: Rule = Field(...)
