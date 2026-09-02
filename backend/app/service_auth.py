import hashlib,hmac,uuid
from datetime import datetime,timezone
from fastapi import Depends,Header,HTTPException,Request,status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import ServiceCredential
def derive_secret(value:str)->str:
    return hmac.new(settings.service_token_pepper.encode(),value.encode(),hashlib.sha256).hexdigest()
async def service_identity(request:Request,x_service_token:str=Header(...),db:AsyncSession=Depends(get_db))->ServiceCredential:
    try: credential_id,secret=x_service_token.split(".",1); key=uuid.UUID(credential_id)
    except (ValueError,AttributeError): raise HTTPException(status.HTTP_401_UNAUTHORIZED,"Invalid service credential")
    cache_key=f"netsentinel:service-credential:{key}"
    cached=await request.app.state.redis.get(cache_key)
    if cached:
        cached_hash,cached_kind=cached.split(":",1)
        if not hmac.compare_digest(derive_secret(secret),cached_hash): raise HTTPException(status.HTTP_401_UNAUTHORIZED,"Invalid service credential")
        return ServiceCredential(id=key,name="cached",kind=cached_kind,secret_hash=cached_hash)
    credential=await db.scalar(select(ServiceCredential).where(ServiceCredential.id==key))
    now=datetime.now(timezone.utc)
    invalid=not credential or credential.revoked_at is not None or (credential.expires_at and credential.expires_at<=now)
    expected=credential.secret_hash if credential else "0"*64
    if invalid or not hmac.compare_digest(derive_secret(secret),expected): raise HTTPException(status.HTTP_401_UNAUTHORIZED,"Invalid service credential")
    await request.app.state.redis.set(cache_key,f"{credential.secret_hash}:{credential.kind}",ex=60)
    return credential
