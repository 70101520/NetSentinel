from logging.config import fileConfig
from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config
from app.config import settings
from app.db import Base
from app import models  # noqa: F401

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)
if config.config_file_name:
    fileConfig(config.config_file_name)

def run_migrations_offline():
    context.configure(url=settings.database_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction(): context.run_migrations()

async def run_async_migrations():
    connectable = async_engine_from_config(config.get_section(config.config_ini_section), poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        def migrate(sync_connection):
            context.configure(connection=sync_connection, target_metadata=Base.metadata)
            with context.begin_transaction(): context.run_migrations()
        await connection.run_sync(migrate)
    await connectable.dispose()

if context.is_offline_mode(): run_migrations_offline()
else:
    import asyncio
    asyncio.run(run_async_migrations())
