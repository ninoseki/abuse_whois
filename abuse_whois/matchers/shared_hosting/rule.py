from abuse_whois.schemas import BaseRule


class SharedHostingRule(BaseRule):
    def match(self, hostname: str) -> bool:
        data = {"domain": hostname}
        return super().match(data)
