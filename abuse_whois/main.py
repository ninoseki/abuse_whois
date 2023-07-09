import asyncio
import json

import typer

from . import schemas
from .errors import InvalidAddressError
from .matchers.shared_hosting import get_shared_hosting_provider
from .matchers.whois import get_optional_whois_contact
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

    domain: str | None = None
    ip_address: str | None = None
    registered_domain: str | None = None

    if is_domain(hostname):
        domain = hostname
        registered_domain = get_registered_domain(hostname)

        # get IP address by domain
        try:
            ip_address = await resolve(hostname)
        except OSError:
            pass

    if is_ip_address(hostname):
        ip_address = hostname

    whois_record = await get_whois_record(hostname)
    shared_hosting_provider = get_shared_hosting_provider(hostname)

    registrar, hosting_provider = await asyncio.gather(
        get_optional_whois_contact(domain), get_optional_whois_contact(ip_address)
    )

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
