from typing import List

from abuse_whois.schemas import BaseRule, Contact
from abuse_whois.whois import get_whois_record


class WhoisRule(BaseRule):
    contact: Contact
    keywords: List[str]

    async def match(self, hostname: str) -> bool:
        try:
            whois_record = await get_whois_record(hostname)
        except Exception:
            return False

        for keyword in self.keywords:
            if keyword in whois_record.raw_text:
                return True

        return False
