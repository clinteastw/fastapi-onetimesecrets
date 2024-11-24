from typing import Dict, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_async_session

from .schemas import SecretCreate
from .service import generate_secret_key, get_secret_message


generate_secret_router = APIRouter(
    tags=["Generate secret key"]
)


@generate_secret_router.post("/")
async def generate_secret(
    secret_in: SecretCreate,
    session: AsyncSession = Depends(get_async_session)
) -> Dict:
    secret_key = await generate_secret_key(secret_in=secret_in, session=session)

    return secret_key


get_secret_router = APIRouter(
    tags=["Get secret message"]
)


@get_secret_router.get("/secret/{secret_key}")
async def get_secret(
    secret_key: str,
    passphrase: Optional[str] = None,
    session: AsyncSession = Depends(get_async_session)
) -> Dict:
    secret_message = await get_secret_message(secret_key, session, passphrase)

    if "message" in secret_message:
        return {"Your decrypted message": secret_message["message"]}
    return secret_message
