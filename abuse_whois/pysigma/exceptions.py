class PySigmaError(Exception):
    pass


class UnsupportedFeature(PySigmaError):
    """Raised when a signature using an unsupported sigma feature is loaded."""


class RuleLoadError(PySigmaError):
    pass
