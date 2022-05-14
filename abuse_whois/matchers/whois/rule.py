from typing import List

from pydantic import Field

from abuse_whois.schemas import BaseRule, Contact
from abuse_whois.utils import is_included_in_base_domains
from abuse_whois.whois import get_whois_record


class WhoisRule(BaseRule):
    contact: Contact
    keywords: List[str] = Field(default_factory=list)
    base_domains: List[str] = Field(default_factory=list)

    async def match(self, hostname: str) -> bool:
        if is_included_in_base_domains(self.base_domains, hostname):
            return True

        try:
            whois_record = await get_whois_record(hostname)
        except Exception:
            return False

        for keyword in self.keywords:
            if keyword in whois_record.raw_text:
                return True

        return False
