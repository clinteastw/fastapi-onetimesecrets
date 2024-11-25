from typing import Optional

from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Secret(Base):
    __tablename__ = "secrets"
    
    message: Mapped[str] = mapped_column(nullable=True)
    passphrase: Mapped[str] = mapped_column(nullable=True)
    secret_key: Mapped[Optional[str]]
    