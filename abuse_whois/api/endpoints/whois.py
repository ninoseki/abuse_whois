import asyncio

from fastapi import APIRouter, HTTPException, status

from abuse_whois import get_abuse_contacts, schemas
from abuse_whois.errors import InvalidAddressError

router = APIRouter(prefix="/whois")


@router.post("/", response_model=schemas.Contacts)
async def whois(query: schemas.Query) -> schemas.Contacts:
    try:
        return await get_abuse_contacts(query.address)
    except InvalidAddressError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))
    except asyncio.TimeoutError as e:
        raise HTTPException(status.HTTP_408_REQUEST_TIMEOUT, detail=str(e))
