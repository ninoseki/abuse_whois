import socket
from typing import Optional

from abuse_whois.matchers.shared_hosting import get_shared_hosting_provider
from abuse_whois.matchers.whois import get_contact_from_whois

from .errors import InvalidAddressError
from .schemas import Contact, Contacts
from .utils import get_hostname, is_domain, is_ip_address, is_supported_address

try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata


__version__ = importlib_metadata.version(__name__)


def get_abuse_contacts(address: str) -> Contacts:
    if not is_supported_address(address):
        raise InvalidAddressError(f"{address} is not supported type address")

    shared_hosting_provider: Optional[Contact] = None
    registrar: Optional[Contact] = None
    hosting_provider: Optional[Contact] = None

    hostname = get_hostname(address)
    ip_address: Optional[str] = None

    shared_hosting_provider = get_shared_hosting_provider(hostname)

    if is_domain(hostname):
        registrar = get_contact_from_whois(hostname)

        # get IP address by domain
        try:
            ip_address = socket.gethostbyname(hostname)
        except OSError:
            pass

    if is_ip_address(hostname):
        ip_address = hostname

    if ip_address is not None:
        hosting_provider = get_contact_from_whois(ip_address)

    return Contacts(
        address=address,
        hostname=hostname,
        ip_address=ip_address,
        shared_hosting_provider=shared_hosting_provider,
        registrar=registrar,
        hosting_provider=hosting_provider,
    )
