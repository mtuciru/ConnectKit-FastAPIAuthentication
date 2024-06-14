from datetime import datetime
from typing import List

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from sqlalchemy import TIMESTAMP, func, ForeignKey, ARRAY, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base

_hasher = PasswordHasher()


class LoginProtection(Base):
    __tablename__ = 'login_protection'
    login: Mapped[str] = mapped_column(primary_key=True, autoincrement=False, index=True)
    csrf_protector: Mapped[dict] = mapped_column(JSONB, nullable=True)
    otp_secret: Mapped[str] = mapped_column(nullable=True)
    otp_codes: Mapped[List[str]] = mapped_column(ARRAY(String, dimensions=1), nullable=True)
    otp_codes_secret: Mapped[str] = mapped_column(nullable=True)
    otp_codes_init: Mapped[int] = mapped_column(nullable=True)
    block: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE")
    block_reason: Mapped[str] = mapped_column(nullable=True)


class Account(AsyncAttrs, Base):
    __tablename__ = "account"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    login: Mapped[str] = mapped_column(nullable=False, unique=True, index=True)
    __password: Mapped[str] = mapped_column("password", nullable=False,
                                            deferred=True, deferred_group="sensitive")
    active: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE")
    properties: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}",
                                             deferred=True, deferred_group="info")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 server_default=func.current_timestamp(),
                                                 deferred=True, deferred_group="date")
    password_changed_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True,
                                                          server_default=func.current_timestamp(),
                                                          deferred=True, deferred_group="date")

    sessions: Mapped[List["AccountSession"]] = relationship(back_populates="account", uselist=True,
                                                            passive_deletes=True)

    @hybrid_property
    def password(self):
        return self.__password

    @password.setter
    def password(self, value):
        self.__password = _hasher.hash(value)

    @hybrid_method
    def verify_password(self, value: str):
        try:
            _hasher.verify(self.__password, value)
            if _hasher.check_needs_rehash(self.__password):
                self.__password = _hasher.hash(value)
            return True
        except Argon2Error:
            return False


class AccountSession(AsyncAttrs, Base):
    __tablename__ = "account_session"
    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("account.id", ondelete='CASCADE'),
                                            nullable=False, index=True)
    wait_otp: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE")
    otp_attempts: Mapped[int] = mapped_column(nullable=False, server_default="0")
    fingerprint: Mapped[str] = mapped_column(nullable=False)
    invalid_after: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                    deferred=True, deferred_group="date")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 server_default=func.current_timestamp(),
                                                 deferred=True, deferred_group="date")
    identity: Mapped[str] = mapped_column(nullable=False)

    account: Mapped["Account"] = relationship(back_populates="sessions", uselist=False, passive_deletes=True)
