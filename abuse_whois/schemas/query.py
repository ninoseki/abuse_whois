from pydantic import Field

from .api_model import APIModel


class Query(APIModel):
    address: str = Field(description="URL, domain, IP address or email address")
