import uuid
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import User

passwords = PasswordHash.recommended()
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
def hash_password(value: str) -> str: return passwords.hash(value)
def verify_password(value: str, digest: str) -> bool: return passwords.verify(value, digest)
def issue_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub":str(user.id),"iss":settings.jwt_issuer,"aud":"netsentinel-api","iat":now,"exp":now+timedelta(minutes=settings.access_token_minutes),"jti":str(uuid.uuid4())}, settings.jwt_secret, algorithm="HS256")
async def current_user(token: str=Depends(oauth2), db: AsyncSession=Depends(get_db)) -> User:
    try:
        claims=jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], audience="netsentinel-api", issuer=settings.jwt_issuer)
        user=await db.scalar(select(User).where(User.id==uuid.UUID(claims["sub"])))
    except (jwt.PyJWTError, ValueError): user=None
    if not user or not user.is_active: raise HTTPException(status.HTTP_401_UNAUTHORIZED,"Invalid credentials")
    return user
def require(permission: str):
    async def check(user: User=Depends(current_user)):
        granted={p.code for role in user.roles for p in role.permissions}
        if permission not in granted: raise HTTPException(status.HTTP_403_FORBIDDEN,"Permission denied")
        return user
    return check
