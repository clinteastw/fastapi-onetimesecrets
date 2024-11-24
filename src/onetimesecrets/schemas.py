from typing import Union

from pydantic import BaseModel


class SecretCreate(BaseModel):
    message: str
    passphrase: Union[str, None] = None
    
class SecretGet(BaseModel):
    secret_key: str
    passphrase: Union[str, None] = None