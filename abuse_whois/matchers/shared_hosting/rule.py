from typing import List

from abuse_whois.schemas import BaseRule, Contact


class SharedHostingRule(BaseRule):
    contact: Contact
    base_domains: List[str]

    def match(self, hostname: str) -> bool:
        if hostname in self.base_domains:
            return True

        for base_domain in self.base_domains:
            if hostname.endswith(f".{base_domain}"):
                return True

        return False
