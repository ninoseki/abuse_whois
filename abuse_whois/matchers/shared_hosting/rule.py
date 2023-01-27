from abuse_whois.pysigma.parser import check_event
from abuse_whois.schemas import BaseRule


class SharedHostingRule(BaseRule):
    def match(self, hostname: str) -> bool:
        sigma_rule = self.sigma_rule
        if sigma_rule is None:
            return False

        data = {"domain": hostname}
        alerts = check_event(data, sigma_rule)
        return len(alerts) > 0
