import asyncio
import json
import sys

import typer
from returns.result import Failure, Success, safe

from . import schemas, services

app = typer.Typer()


async def get_abuse_contacts(address: str) -> schemas.Contacts:
    return await services.ContactsQuery().call(address)


@app.command()
def whois(
    address: str = typer.Argument(..., help="URL, domain, IP address or email address"),
):
    @safe
    def inner() -> schemas.Contacts:
        return asyncio.run(get_abuse_contacts(address))

    result = inner()
    match result:
        case Success(value):
            print(value.model_dump_json(by_alias=True))  # noqa: T201
        case Failure(e):
            print(json.dumps({"detail": str(e)}), file=sys.stderr)  # noqa: T201
            sys.exit(1)


if __name__ == "__main__":
    app()
