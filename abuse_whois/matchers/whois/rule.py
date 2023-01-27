from typing import Any

from abuse_whois.pysigma.parser import check_event
from abuse_whois.schemas import BaseRule
from abuse_whois.whois import get_whois_record


class WhoisRule(BaseRule):
    async def match(self, hostname: str) -> bool:
        data: dict[Any, Any] | None = None

        try:
            whois_record = await get_whois_record(hostname)
            data = whois_record.dict(by_alias=True)
        except Exception:
            data = {"domain": hostname}

        sigma_rule = self.sigma_rule
        if sigma_rule is None:
            return False

        alerts = check_event(data, sigma_rule)
        return len(alerts) > 0
