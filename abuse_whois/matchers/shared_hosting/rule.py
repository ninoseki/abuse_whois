from typing import List

from pydantic import Field

from abuse_whois.schemas import BaseRule, Contact
from abuse_whois.utils import is_included_in_base_domains


class SharedHostingRule(BaseRule):
    contact: Contact
    base_domains: List[str] = Field(default_factory=list)

    def match(self, hostname: str) -> bool:
        return is_included_in_base_domains(self.base_domains, hostname)
