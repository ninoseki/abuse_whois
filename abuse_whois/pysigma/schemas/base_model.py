import pydantic


class BaseModel(pydantic.BaseModel):
    class Config:
        arbitrary_types_allowed = True
