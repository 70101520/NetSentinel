import os
os.environ.setdefault("DATABASE_URL","postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL","redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET","test-secret-that-is-at-least-thirty-two-characters")
os.environ.setdefault("SERVICE_TOKEN_PEPPER","test-pepper-that-is-at-least-thirty-two-characters")
from urllib.parse import urlsplit
database_name=urlsplit(os.environ["DATABASE_URL"].replace("postgresql+asyncpg://","postgresql://",1)).path.strip("/")
if database_name not in {"test","netsentinel_test"}:
    raise RuntimeError("Backend tests refuse to run against a non-test database")
