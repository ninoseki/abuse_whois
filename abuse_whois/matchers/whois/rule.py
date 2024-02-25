from abuse_whois import schemas


class WhoisRule(schemas.BaseRule):
    def match(self, record: schemas.WhoisRecord) -> bool:
        return super().match(record.model_dump(by_alias=True))
