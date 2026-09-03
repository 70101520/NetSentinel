import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from redis.asyncio import Redis
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from app.audit import record
from app.config import settings
from app.db import engine, get_db
from app.models import Device, Policy, PolicyRule, User
from app.policy import evaluate
from app.schemas import Decision, DecisionRequest, DevicePage, Token
from app.security import issue_token, require, verify_password
from app.telemetry import router as telemetry_router
from app.metrics import router as metrics_router

redis=Redis.from_url(settings.redis_url, decode_responses=True)
@asynccontextmanager
async def lifespan(app:FastAPI):
    yield
    await redis.aclose(); await engine.dispose()
app=FastAPI(title="NetSentinel Management API",version="0.2.0",lifespan=lifespan,docs_url="/docs")
app.state.redis=redis
app.include_router(telemetry_router); app.include_router(metrics_router)
app.add_middleware(CORSMiddleware,allow_origins=settings.allowed_origins,allow_credentials=False,allow_methods=["GET","POST","PUT","DELETE"],allow_headers=["Authorization","Content-Type","X-Request-ID"])
@app.middleware("http")
async def request_context(request:Request,call_next):
    length=request.headers.get("content-length")
    if request.url.path=="/api/v1/telemetry/events" and length and length.isdigit() and int(length)>settings.telemetry_max_body_bytes:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail":"Request body too large"},status_code=413)
    request.state.request_id=request.headers.get("X-Request-ID",str(uuid.uuid4()))[:64]
    response=await call_next(request); response.headers["X-Request-ID"]=request.state.request_id; response.headers["X-Content-Type-Options"]="nosniff"; response.headers["X-Frame-Options"]="DENY"; return response
@app.get("/health/live")
async def live(): return {"status":"ok"}
@app.get("/health/ready")
async def ready():
    checks={}
    try:
        async with engine.connect() as c: await c.execute(text("SELECT 1")); checks["database"]="ok"
    except Exception: checks["database"]="unavailable"
    try: checks["redis"]="ok" if await redis.ping() else "unavailable"
    except Exception: checks["redis"]="unavailable"
    if "unavailable" in checks.values(): raise HTTPException(503,detail=checks)
    return {"status":"ok","components":checks}
@app.post("/api/v1/auth/token",response_model=Token)
async def token(request:Request, form:OAuth2PasswordRequestForm=Depends(), db:AsyncSession=Depends(get_db)):
    user=await db.scalar(select(User).where(func.lower(User.email)==form.username.lower()))
    if not user or not verify_password(form.password,user.password_hash):
        await record(db,request,user,"auth.login","session",None,"denied"); await db.commit(); raise HTTPException(401,"Invalid credentials")
    await record(db,request,user,"auth.login","session",None,"success"); await db.commit()
    return Token(access_token=issue_token(user),expires_in=settings.access_token_minutes*60)
@app.get("/api/v1/devices",response_model=DevicePage)
async def devices(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1),db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    page_size=min(page_size,settings.max_page_size)
    total=await db.scalar(select(func.count()).select_from(Device)) or 0
    rows=(await db.scalars(select(Device).order_by(Device.hostname,Device.id).offset((page-1)*page_size).limit(page_size))).all()
    cutoff=datetime.now(timezone.utc).timestamp()-settings.agent_heartbeat_timeout_seconds
    items=[{"id":d.id,"device_identifier":d.device_identifier,"hostname":d.hostname,"username":d.username,"ip_address":d.ip_address,"os_name":d.os_name,"agent_version":d.agent_version,"last_heartbeat":d.last_heartbeat,"status":"online" if d.last_heartbeat and d.last_heartbeat.timestamp()>=cutoff else "offline"} for d in rows]
    return {"items":items,"meta":{"page":page,"page_size":page_size,"total":total,"pages":(total+page_size-1)//page_size}}
@app.post("/api/v1/policies/evaluate",response_model=Decision)
async def decide(body:DecisionRequest,db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    policy=await db.get(Policy,body.policy_id)
    if not policy: raise HTTPException(404,"Policy not found")
    rules=(await db.scalars(select(PolicyRule).where(PolicyRule.policy_id==policy.id,PolicyRule.version==policy.active_version))).all()
    action,rule_id,reason=evaluate(policy,list(rules),body.domain)
    return Decision(action=action,policy_id=policy.id,policy_version=policy.active_version,matched_rule_id=rule_id,reason=reason)
@app.get("/api/v1/dashboard")
async def dashboard(db:AsyncSession=Depends(get_db),_:User=Depends(require("dashboard.view"))):
    total=await db.scalar(select(func.count()).select_from(Device)); cutoff=datetime.fromtimestamp(datetime.now(timezone.utc).timestamp()-settings.agent_heartbeat_timeout_seconds,tz=timezone.utc); online=await db.scalar(select(func.count()).select_from(Device).where(Device.last_heartbeat>=cutoff))
    return {"devices":{"total":total,"online":online,"offline":total-online},"components":{"api":"ok"}}
