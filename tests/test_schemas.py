import pytest

from abuse_whois import schemas


@pytest.mark.parametrize(
    "address,expected",
    [
        ("http://example.com", "form"),
        ("abuse@example.com", "email"),
    ],
)
def test_contact_type(address: str, expected: str):
    assert schemas.Contact(provider="foo", address=address).type == expected
