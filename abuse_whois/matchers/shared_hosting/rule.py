from abuse_whois.schemas import BaseRule


class SharedHostingRule(BaseRule):
    def match(self, hostname: str) -> bool:
        return super().match({"domain": hostname})
