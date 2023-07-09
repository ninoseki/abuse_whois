from ...schemas import BaseRule
from ...whois import get_whois_record


class WhoisRule(BaseRule):
    async def match(self, hostname: str) -> bool:
        whois_record = await get_whois_record(hostname)
        data = whois_record.model_dump(by_alias=True)
        return super().match(data)
