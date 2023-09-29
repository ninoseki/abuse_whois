from abuse_whois import schemas


class WhoisRule(schemas.BaseRule):
    def match(self, record: schemas.WhoisRecord) -> bool:
        data = record.model_dump(by_alias=True)
        return super().match(data)
