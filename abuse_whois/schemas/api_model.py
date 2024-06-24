from pydantic import BaseModel, ConfigDict, RootModel
from pydantic.alias_generators import to_camel


class APIModel(BaseModel):
    model_config = ConfigDict(
        from_attributes=True, alias_generator=to_camel, populate_by_name=True
    )


class RootAPIModel(RootModel):
    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]

    model_config = ConfigDict(
        from_attributes=True, alias_generator=to_camel, populate_by_name=True
    )
