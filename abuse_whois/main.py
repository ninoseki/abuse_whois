import asyncio
import json

import typer

from . import schemas
from .errors import InvalidAddressError, RateLimitError
from .matchers.shared_hosting import get_shared_hosting_provider
from .matchers.whois import (
    get_optional_whois_contact,
    get_whois_contact_by_whois_record,
)
from .utils import (
    get_hostname,
    get_registered_domain,
    is_domain,
    is_ip_address,
    is_supported_address,
    resolve,
)
from .whois import get_whois_record


async def get_abuse_contacts(address: str) -> schemas.Contacts:
    if not is_supported_address(address):
        raise InvalidAddressError(f"{address} is not supported type address")

    hostname = get_hostname(address)  # Domain or IP address

    try:
        whois_record = await get_whois_record(hostname)
    except asyncio.TimeoutError as e:
        raise asyncio.TimeoutError(f"whois timeout for {hostname}") from e
    except RateLimitError as e:
        raise asyncio.TimeoutError(f"whois rate limit error for {hostname}") from e

    ip_address: str | None = None
    registered_domain: str | None = None
    registrar: schemas.Contact | None = None

    if is_domain(hostname):
        # set registered domain
        registered_domain = get_registered_domain(hostname)

        # get IP address by domain
        try:
            ip_address = await resolve(hostname)
        except OSError:
            pass

        # get registrar contact
        registrar = get_whois_contact_by_whois_record(whois_record)

    if is_ip_address(hostname):
        ip_address = hostname

    shared_hosting_provider = get_shared_hosting_provider(hostname)
    hosting_provider = await get_optional_whois_contact(ip_address)

    return schemas.Contacts(
        address=address,
        hostname=hostname,
        ip_address=ip_address,
        registered_domain=registered_domain,
        shared_hosting_provider=shared_hosting_provider,
        registrar=registrar,
        hosting_provider=hosting_provider,
        whois_record=whois_record,
    )


app = typer.Typer()


@app.command()
def whois(
    address: str = typer.Argument(..., help="URL, domain, IP address or email address")
):
    try:
        contacts = asyncio.run(get_abuse_contacts(address))
        print(contacts.model_dump_json(by_alias=True))  # noqa: T201
    except (InvalidAddressError, asyncio.TimeoutError) as e:
        print(json.dumps({"error": str(e)}))  # noqa: T201


if __name__ == "__main__":
    app()
