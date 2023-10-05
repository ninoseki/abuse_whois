import asyncio
import json

import typer
from asyncwhois.errors import WhoIsError
from whodap.errors import WhodapError

from . import errors, schemas, services

app = typer.Typer()


async def get_abuse_contacts(address: str) -> schemas.Contacts:
    try:
        return await services.ContactsQuery().call(address)
    except (WhodapError, WhoIsError) as e:
        raise errors.AbuseWhoisError(str(e)) from e


@app.command()
def whois(
    address: str = typer.Argument(..., help="URL, domain, IP address or email address")
):
    try:
        contacts = asyncio.run(get_abuse_contacts(address))
        print(contacts.model_dump_json(by_alias=True))  # noqa: T201
    except (errors.AbuseWhoisError, asyncio.TimeoutError, ConnectionResetError) as e:
        print(json.dumps({"error": str(e)}))  # noqa: T201


if __name__ == "__main__":
    app()
