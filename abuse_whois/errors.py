class AbuseWhoisError(Exception):
    pass


class InvalidAddressError(AbuseWhoisError):
    pass


class TimeoutError(AbuseWhoisError):
    pass
