import importlib.metadata as importlib_metadata

from .main import get_abuse_contacts  # noqa: F401

__version__ = importlib_metadata.version(__name__)
