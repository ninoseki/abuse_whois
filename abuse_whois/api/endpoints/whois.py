import asyncio

from fastapi import APIRouter, HTTPException, status

from abuse_whois import errors, get_abuse_contacts, schemas

router = APIRouter(prefix="/whois")


@router.post("/", response_model=schemas.Contacts)
async def whois(query: schemas.Query) -> schemas.Contacts:
    try:
        return await get_abuse_contacts(query.address)
    except errors.AddressError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except asyncio.TimeoutError as e:
        raise HTTPException(status.HTTP_408_REQUEST_TIMEOUT, detail=str(e)) from e
    except errors.RateLimitError as e:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e)) from e
    except errors.NotFoundError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except errors.AbuseWhoisError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
    except ConnectionResetError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
