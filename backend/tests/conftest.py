import os
os.environ.setdefault("DATABASE_URL","postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL","redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET","test-secret-that-is-at-least-thirty-two-characters")
