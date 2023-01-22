from abuse_whois.pysigma.parser import check_event
from abuse_whois.schemas import BaseRule
from abuse_whois.utils import is_included_in_base_domains
from abuse_whois.whois import get_whois_record


class WhoisRule(BaseRule):
    async def match(self, hostname: str) -> bool:
        if is_included_in_base_domains(self.base_domains, hostname):
            return True

        try:
            whois_record = await get_whois_record(hostname)
        except Exception:
            return False

        rule = self.to_sigma_rule()
        if rule is None:
            return False

        alerts = check_event(whois_record.dict(by_alias=True), rule)
        return len(alerts) > 0
