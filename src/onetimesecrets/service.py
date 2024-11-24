from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.secrets import Secret

from .schemas import SecretCreate
from .utils import (delete_found_secret_message_after_reading, encrypt_secret,
                    verify_passphrase, decrypt_secret)


async def generate_secret_key(
    secret_in: SecretCreate,
    session: AsyncSession
) -> Dict[str, str]:
    """Generates secret_key and encrypts secret message and saving it to db.

    Args:
        secret_in (SecretCreate): Pydantic schema for creating secret
        session (AsyncSession): Db session

    Returns:
        str: unique secret_key which will be used to find and decrypt secret.
    """
    new_secret = Secret(**secret_in.model_dump())
    encrypted_secret = encrypt_secret(new_secret)
    session.add(encrypted_secret)
    await session.commit()
    return {"Your secret_key": encrypted_secret.secret_key}


@delete_found_secret_message_after_reading
async def get_secret_message(
    secret_key: str,
    session: AsyncSession,
    passphrase: Optional[str] = None
) -> Dict:
    """Get secret from db than decrypts it either with passphrase or not.
    Than automatically delets it from db.

    Args:
        secret_key (str): Unqiue identifier of the secret
        session (AsyncSession): Db session
        passphrase (Union[str, None]): Provided passpharse by user or None if not provided.

    Returns:
        Dict: Decrypted secret message or error. Also 'found_secret' provided for decorator
        to automatically delete it from db after users gets decrypted message.
    """
    stmt = (select(Secret).where(Secret.secret_key == secret_key))
    result = await session.execute(stmt)
    found_secret = result.scalar_one_or_none()

    if not found_secret:
        return {"error": "Secret not found"}

    if passphrase is None:
        decoded_secret_message = decrypt_secret(found_secret, passphrase=None)
        return {"message": decoded_secret_message, "found_secret": found_secret}

    if verify_passphrase(found_secret, passphrase):
        decoded_secret_message = decrypt_secret(found_secret, passphrase)
        return {"message": decoded_secret_message, "found_secret": found_secret}

    return {"error": "Invalid passphrase"}
