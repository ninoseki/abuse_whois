import asyncio

from fastapi import APIRouter, HTTPException, status
from returns.future import future_safe
from returns.pipeline import is_successful
from returns.unsafe import unsafe_perform_io

from abuse_whois import errors, get_abuse_contacts, schemas

router = APIRouter(prefix="/whois")


@router.post("/", response_model=schemas.Contacts)
async def whois(query: schemas.Query) -> schemas.Contacts:
    @future_safe
    async def inner():
        return await get_abuse_contacts(query.address)

    result = await inner()
    if not is_successful(result):
        failure = unsafe_perform_io(result.failure())
        status_code = status.HTTP_400_BAD_REQUEST

        match failure:
            case errors.NotFoundError():
                status_code = status.HTTP_404_NOT_FOUND
            case asyncio.TimeoutError():
                status_code = status.HTTP_408_REQUEST_TIMEOUT
            case errors.RateLimitError():
                status_code = status.HTTP_429_TOO_MANY_REQUESTS
            case errors.AbuseWhoisError():
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            case ConnectionResetError():
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        raise HTTPException(status_code, detail=str(failure))

    return unsafe_perform_io(result.unwrap())
