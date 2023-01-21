from functools import partial

import aiometer

from abuse_whois.matchers.shared_hosting import get_shared_hosting_provider
from abuse_whois.matchers.whois import get_contact_from_whois

from .errors import InvalidAddressError, TimeoutError
from .ip import resolve_ip_address
from .schemas import Contact, Contacts, WhoisRecord
from .utils import (
    get_hostname,
    get_registered_domain,
    is_domain,
    is_ip_address,
    is_supported_address,
)
from .whois import get_whois_record as _get_whois_record


async def get_whois_record(hostname: str) -> WhoisRecord | None:
    try:
        return await _get_whois_record(hostname)
    except TimeoutError:
        return None


async def get_contact(domain_or_ip_address: str | None = None) -> Contact | None:
    if domain_or_ip_address is None:
        return None

    return await get_contact_from_whois(domain_or_ip_address)


async def get_registrar_and_hosting_provider_contacts(
    *, domain: str | None = None, ip_address: str | None = None
):
    values = [domain, ip_address]
    return await aiometer.run_all([partial(get_contact, value) for value in values])


async def get_abuse_contacts(address: str) -> Contacts:
    if not is_supported_address(address):
        raise InvalidAddressError(f"{address} is not supported type address")

    shared_hosting_provider: Contact | None = None
    registrar: Contact | None = None
    hosting_provider: Contact | None = None

    hostname = get_hostname(address)

    domain: str | None = None  # FQDN
    ip_address: str | None = None
    registered_domain: str | None = None
    whois_record: WhoisRecord | None = None

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

    # it will get cached result (if there is no TimeoutError)
    whois_record = await get_whois_record(hostname)

    return Contacts(
        address=address,
        hostname=hostname,
        ip_address=ip_address,
        registered_domain=registered_domain,
        shared_hosting_provider=shared_hosting_provider,
        registrar=registrar,
        hosting_provider=hosting_provider,
        whois_record=whois_record,
    )
