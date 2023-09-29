class AbuseWhoisError(Exception):
    pass


class AddressError(AbuseWhoisError):
    pass


class NotFoundError(AbuseWhoisError):
    pass


class RateLimitError(AbuseWhoisError):
    pass
