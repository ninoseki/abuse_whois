class AbuseWhoisError(Exception):
    pass


class InvalidAddressError(AbuseWhoisError):
    pass


class RateLimitError(AbuseWhoisError):
    pass
