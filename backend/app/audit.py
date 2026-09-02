import uuid
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import AuditEvent, User
async def record(db:AsyncSession, request:Request, actor:User|None, action:str, resource_type:str, resource_id:str|None, result:str, previous=None, new=None):
    db.add(AuditEvent(actor_id=actor.id if actor else None, action=action, resource_type=resource_type, resource_id=resource_id, source_ip=request.client.host if request.client else None, previous_value=previous, new_value=new, result=result, request_id=getattr(request.state,"request_id",str(uuid.uuid4()))))
