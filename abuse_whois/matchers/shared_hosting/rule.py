from abuse_whois.schemas import BaseRule
from abuse_whois.utils import is_included_in_base_domains


class SharedHostingRule(BaseRule):
    def match(self, hostname: str) -> bool:
        return is_included_in_base_domains(self.base_domains, hostname)
