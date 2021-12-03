from fastapi import APIRouter, HTTPException

from abuse_whois import get_abuse_contacts, schemas
from abuse_whois.errors import InvalidAddressError

router = APIRouter(prefix="/whois")


@router.post("/", response_model=schemas.Contacts)
def whois(query: schemas.Query):
    try:
        return get_abuse_contacts(query.address)
    except InvalidAddressError as e:
        raise HTTPException(400, detail=str(e))
