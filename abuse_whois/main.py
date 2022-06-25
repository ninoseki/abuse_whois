from functools import partial
from typing import Optional

import aiometer

from abuse_whois.matchers.shared_hosting import get_shared_hosting_provider
from abuse_whois.matchers.whois import get_contact_from_whois

from .errors import InvalidAddressError
from .ip import resolve_ip_address
from .schemas import Contact, Contacts
from .utils import (
    get_hostname,
    get_registered_domain,
    is_domain,
    is_ip_address,
    is_supported_address,
)


async def get_contact(domain_or_ip_address: Optional[str] = None) -> Optional[Contact]:
    if domain_or_ip_address is None:
        return None

    return await get_contact_from_whois(domain_or_ip_address)


async def get_registrar_and_hosting_provider_contacts(
    *, domain: Optional[str] = None, ip_address: Optional[str] = None
):
    values = [domain, ip_address]
    return await aiometer.run_all([partial(get_contact, value) for value in values])


async def get_abuse_contacts(address: str) -> Contacts:
    if not is_supported_address(address):
        raise InvalidAddressError(f"{address} is not supported type address")

    shared_hosting_provider: Optional[Contact] = None
    registrar: Optional[Contact] = None
    hosting_provider: Optional[Contact] = None

    hostname = get_hostname(address)

    domain: Optional[str] = None  # FQDN
    ip_address: Optional[str] = None
    registered_domain: Optional[str] = None

    shared_hosting_provider = get_shared_hosting_provider(hostname)

    if is_domain(hostname):
        domain = hostname
        registered_domain = get_registered_domain(hostname)

        # get IP address by domain
        try:
            ip_address = await resolve_ip_address(hostname)
        except OSError:
            pass

    if is_ip_address(hostname):
        ip_address = hostname

    registrar, hosting_provider = await get_registrar_and_hosting_provider_contacts(
        domain=domain, ip_address=ip_address
    )

    return Contacts(
        address=address,
        hostname=hostname,
        ip_address=ip_address,
        registered_domain=registered_domain,
        shared_hosting_provider=shared_hosting_provider,
        registrar=registrar,
        hosting_provider=hosting_provider,
    )
