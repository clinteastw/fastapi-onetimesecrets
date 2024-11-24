import uuid
from base64 import urlsafe_b64encode
from functools import wraps
from typing import Optional

import bcrypt
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from config import FERNET_KEY
from models.secrets import Secret

#Fernet instance for encryption
f = Fernet(FERNET_KEY.encode("utf-8"))

#Salt for hashing
salt = b'$2b$12$ge7ZjwywBd5r5KG.tcznne'


def encrypt_secret(secret: Secret) -> Secret:
    """Encrypt a secret using a users provided passphrase or a default key.
    If a passphrase is provided, it is hashed using bcrypt to generate a unique
    Fernet key, which is then used to encrypt the secret message.
    Otherwise, secret encrypts with pre-defiend Fernet key, that stores in our env.

    Args:
        secret (Secret): Secret object with message and optional passphrase

    Returns:
        Secret: Encrypted secret
    """
    secret_key = str(uuid.uuid4())
    if secret.passphrase:
        hashed_secret_passphrase = bcrypt.hashpw(
            secret.passphrase.encode("utf-8"), salt=salt)
        fernet_key = urlsafe_b64encode(hashed_secret_passphrase[:32]).decode()
        fernet = Fernet(fernet_key)
        secret_message = secret.message
        hashed_secret_message = fernet.encrypt(secret_message.encode("utf-8"))
        hashed_secret = Secret(message=hashed_secret_message.decode(),
                               passphrase=hashed_secret_passphrase.decode(),
                               secret_key=secret_key)
    else:
        secret_message = secret.message
        hashed_secret_message = f.encrypt(secret_message.encode("utf-8"))
        hashed_secret = Secret(message=hashed_secret_message.decode(),
                               passphrase=None, secret_key=secret_key)

    return hashed_secret


def decrypt_secret(encrypted_secret: Secret, passphrase: Optional[str] = None) -> str:
    """Decrypt encrypted secret using a users provided passphrase or a default key.
    If a passphrase was used during encryption, it is used to generate the Fernet key.
    Otherwise, the default Fernet key will be used.

    Args:
        encrypted_secret (Secret): The encrypted secret object
        passphrase (str): The passphrase that was used to encrypt the secret

    Returns:
        str: Decrypted secret message
    """
    if encrypted_secret.passphrase:
        hashed_secret_passphrase = bcrypt.hashpw(
            passphrase.encode("utf-8"), salt=salt)
        fernet_key = urlsafe_b64encode(hashed_secret_passphrase[:32]).decode()
        fernet = Fernet(fernet_key)
        decrypted_secret_message = fernet.decrypt(encrypted_secret.message)
        return decrypted_secret_message
    else:
        decrypted_secret_message = f.decrypt(encrypted_secret.message)
        return decrypted_secret_message


def verify_passphrase(secret: Secret, user_passphrase: str) -> bool:
    """Verify that users provided passphrase matches the one stored in database.

    Args:
        secret (Secret): Secret object with passphrase
        user_passphrase (str): Passphrase input by user

    Returns:
       bool: True is passphrases match, else False
    """
    if bcrypt.checkpw(user_passphrase.encode("utf-8"), secret.passphrase.encode("utf-8")):
        return True
    return False


def delete_found_secret_message_after_reading(func):
    """Decorator to automatically delete a found secret after reading it.
    Once a secret is returned it is deleted from the database.

    Args:
        func: Async func

    Returns:
        Async func that deletes secret after reading
    """
    @wraps(func)
    async def wrapper(secret_key: str, session: AsyncSession, passphrase: Optional[str] = None):
        result = await func(secret_key, session, passphrase)

        if "found_secret" in result:
            await session.delete(result["found_secret"])
            await session.commit()

        return result
    return wrapper
