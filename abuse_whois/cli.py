import json

import typer

from . import get_abuse_contacts
from .errors import InvalidAddressError

app = typer.Typer()


@app.command()
def whois(
    address: str = typer.Argument(..., help="URL, domain, IP address or email address")
):
    try:
        contacts = get_abuse_contacts(address)
        print(contacts.json(by_alias=True))  # noqa: T001
    except InvalidAddressError as e:
        print(json.dumps({"error": str(e)}))  # noqa: T001


if __name__ == "__main__":
    app()
