from abuse_whois import schemas


class WhoisRule(schemas.BaseRule):
    def match(self, whois_record: schemas.WhoisRecord) -> bool:
        data = whois_record.model_dump(by_alias=True)
        return super().match(data)
