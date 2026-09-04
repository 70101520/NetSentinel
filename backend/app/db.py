from collections.abc import AsyncIterator
import structlog
from fastapi import HTTPException
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError, TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

class Base(DeclarativeBase): pass
engine = create_async_engine(settings.database_url, pool_pre_ping=True, pool_size=settings.db_pool_size, max_overflow=settings.db_max_overflow, pool_timeout=10)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
async def get_db() -> AsyncIterator[AsyncSession]:
    try:
        async with SessionLocal() as session:
            yield session
    except (OperationalError, InterfaceError, SQLAlchemyTimeoutError, DBAPIError, OSError) as exc:
        structlog.get_logger("database").error("database_dependency_unavailable", error_type=type(exc).__name__)
        raise HTTPException(503, "Database service unavailable") from exc
