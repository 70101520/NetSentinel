import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, select

from app import cli
from app.db import SessionLocal, engine
from app.models import AuditEvent, Device, Permission, Role, RolePermission, User, UserRole
from app.security import hash_password, verify_password


@pytest.fixture
async def recovery_accounts():
    await engine.dispose()
    suffix=uuid.uuid4().hex
    target=User(email=f"recovery-{suffix}@example.invalid",password_hash=hash_password("old-password-value"),failed_logins=7,locked_until=datetime.now(timezone.utc)+timedelta(hours=1))
    other=User(email=f"unrelated-{suffix}@example.invalid",password_hash=hash_password("unrelated-password"),failed_logins=2)
    device=Device(device_identifier=f"recovery-device-{suffix}",hostname="RECOVERY-UNCHANGED")
    permission=Permission(code=f"recovery.permission.{suffix}")
    role=Role(name=f"Recovery Role {suffix}",permissions=[permission])
    target.roles.append(role)
    async with SessionLocal() as db:
        db.add_all([target,other,device]); await db.commit()
        await db.refresh(target); await db.refresh(other); await db.refresh(device)
        history=AuditEvent(actor_id=target.id,action="existing.audit.history",resource_type="user",resource_id=str(target.id),source_ip=None,previous_value=None,new_value=None,result="success",request_id=f"test-{uuid.uuid4()}")
        db.add(history); await db.commit(); await db.refresh(history)
        values={"target_id":target.id,"other_id":other.id,"other_hash":other.password_hash,"device_id":device.id,"target_email":target.email,"role_id":role.id,"permission_id":permission.id,"history_id":history.id}
    yield values
    async with SessionLocal() as db:
        await db.execute(delete(AuditEvent).where(AuditEvent.resource_id==str(values["target_id"])))
        await db.execute(delete(Device).where(Device.id==values["device_id"]))
        await db.execute(delete(UserRole).where(UserRole.user_id==values["target_id"]))
        await db.execute(delete(RolePermission).where(RolePermission.role_id==values["role_id"]))
        await db.execute(delete(User).where(User.id.in_([values["target_id"],values["other_id"]])))
        await db.execute(delete(Role).where(Role.id==values["role_id"]))
        await db.execute(delete(Permission).where(Permission.id==values["permission_id"]))
        await db.commit()
    await engine.dispose()


def password_prompts(monkeypatch,first,second):
    answers=iter((first,second)); monkeypatch.setattr(cli.getpass,"getpass",lambda _prompt: next(answers))


@pytest.mark.asyncio
async def test_successful_reset_changes_only_target_and_clears_lockout(monkeypatch,recovery_accounts):
    new_password="new-secure-password-value"; password_prompts(monkeypatch,new_password,new_password)
    async with SessionLocal() as db:
        user_count=await db.scalar(select(func.count()).select_from(User)); device_count=await db.scalar(select(func.count()).select_from(Device))
    await cli.reset_admin_password(recovery_accounts["target_email"])
    async with SessionLocal() as db:
        target=await db.get(User,recovery_accounts["target_id"]); other=await db.get(User,recovery_accounts["other_id"])
        assert not verify_password("old-password-value",target.password_hash)
        assert verify_password(new_password,target.password_hash)
        assert target.failed_logins==0 and target.locked_until is None
        assert target.id==recovery_accounts["target_id"]
        assert [role.id for role in target.roles]==[recovery_accounts["role_id"]]
        assert [permission.id for permission in target.roles[0].permissions]==[recovery_accounts["permission_id"]]
        assert other.password_hash==recovery_accounts["other_hash"] and other.failed_logins==2
        assert await db.scalar(select(func.count()).select_from(User))==user_count
        assert await db.scalar(select(func.count()).select_from(Device))==device_count
        event=await db.scalar(select(AuditEvent).where(AuditEvent.resource_id==str(target.id),AuditEvent.action=="admin.password.recovery"))
        assert event is not None and event.result=="success"
        assert await db.get(AuditEvent,recovery_accounts["history_id"]) is not None
        assert "password" not in str(event.previous_value).lower() and "password" not in str(event.new_value).lower()


@pytest.mark.asyncio
async def test_nonexistent_account_is_refused(monkeypatch):
    monkeypatch.setattr(cli.getpass,"getpass",lambda _prompt: pytest.fail("password prompt must not run"))
    with pytest.raises(SystemExit,match="not found"): await cli.reset_admin_password(f"missing-{uuid.uuid4()}@example.invalid")


@pytest.mark.asyncio
@pytest.mark.parametrize(("first","second","message"),[("too-short","too-short","at least 14"),("first-password-value","second-password-value","does not match")])
async def test_invalid_password_input_does_not_change_account(monkeypatch,recovery_accounts,first,second,message):
    password_prompts(monkeypatch,first,second)
    async with SessionLocal() as db: original=(await db.get(User,recovery_accounts["target_id"])).password_hash
    with pytest.raises(SystemExit,match=message): await cli.reset_admin_password(recovery_accounts["target_email"])
    async with SessionLocal() as db:
        target=await db.get(User,recovery_accounts["target_id"])
        assert target.password_hash==original and target.failed_logins==7 and target.locked_until is not None
