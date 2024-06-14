from typing import Tuple, Optional

from sqlalchemy import select
from sqlalchemy.orm import load_only

from authentication.models import Account, LoginProtection
from authentication.schemes import NewAccount
from database.asyncio import AsyncDatabase, AsyncSession


async def create_new_account(new_account: NewAccount) -> Account:
    async with AsyncDatabase() as db:
        account = await db.scalar(select(Account).options(
            load_only(Account.id)
        ).filter_by(login=new_account.login))
        if account is not None:
            raise ValueError(f'Account with login {new_account.login} already exists')
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=new_account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            db.add(protection)
        protection.login = new_account.login
        protection.csrf_protector = None
        protection.block = False
        protection.block_reason = None
        protection.otp_codes = None
        protection.otp_secret = None
        protection.otp_codes_init = None
        protection.otp_codes_secret = None
        account = Account()
        account.login = new_account.login
        account.password = new_account.password
        account.properties = new_account.properties or dict()
        account.active = new_account.active
        db.add(account)
        await db.commit()
        db.expunge(account)
        return account


async def delete_account(temp_account: Account) -> None:
    async with AsyncDatabase() as db:
        account = await db.scalar(select(Account).options(
            load_only(Account.id)
        ).filter_by(login=temp_account.login))
        if account is not None:
            await db.delete(account)
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=temp_account.login).with_for_update())
        if protection is not None:
            await db.delete(protection)
        await db.commit()


async def _set_block_account(account: Account, block: bool, reason: str = None) -> None:
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            protection.login = account.login
            db.add(protection)
        protection.block = block
        protection.block_reason = reason
        await db.commit()


async def block_account(account: Account, reason: str) -> None:
    await _set_block_account(account, block=True, reason=reason)


async def unblock_account(account: Account) -> None:
    await _set_block_account(account, block=False)


async def get_block_status(account: Account) -> Tuple[bool, Optional[str]]:
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.block, LoginProtection.block_reason)
        ).filter_by(login=account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            protection.login = account.login
            protection.block = False
            protection.block_reason = None
            db.add(protection)
            await db.commit()
        return protection.block, protection.block_reason


async def disable_otp(account: Account):
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            protection.login = account.login
        protection.otp_secret = None
        protection.otp_codes = None
        protection.otp_codes_secret = None
        protection.otp_codes_init = None
        await db.commit()


async def get_status_otp(account: Account):
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.otp_codes_init)
        ).filter_by(login=account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            protection.login = account.login
            protection.otp_codes_init = None
            await db.commit()
        return protection.otp_codes_init is not None


async def get_database() -> AsyncSession:
    async with AsyncDatabase() as db:
        yield db
