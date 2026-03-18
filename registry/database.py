"""
Database Configuration — Async SQLAlchemy Engine & Session Factory

Uses SQLAlchemy 2.0 async with asyncpg for PostgreSQL or aiosqlite for SQLite.
This is the single source of truth for database connections across the platform.
Think of this as the "data source" config in a Splunk deployment — all queries route through here.
"""

import os
import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///agent_governance.db",
)

# Detect database type for conditional settings
_is_sqlite = DATABASE_URL.startswith("sqlite")

# Build engine kwargs based on database type
_engine_kwargs = {
    "echo": os.getenv("API_DEBUG", "false").lower() == "true",
}

if not _is_sqlite:
    # PostgreSQL-specific connection pool settings
    _engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 10,
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    })

# Create async engine
engine = create_async_engine(DATABASE_URL, **_engine_kwargs)

# Session factory — each request gets its own session via dependency injection
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


# Track whether tables have been verified this session
_tables_verified = False


def _db_file_exists() -> bool:
    """Check if the SQLite DB file physically exists (always True for PostgreSQL)."""
    if not _is_sqlite:
        return True
    import re
    match = re.search(r"sqlite.*?///(.+)", DATABASE_URL)
    if not match:
        return True
    import pathlib
    db_path = pathlib.Path(match.group(1))
    return db_path.exists() and db_path.stat().st_size > 0


async def _ensure_tables() -> None:
    """Auto-create tables if they don't exist (self-healing for SQLite).
    
    Resets the verified cache if the DB file has been deleted so a server
    restart is NOT required after removing agent_governance.db.
    """
    global _tables_verified
    # Invalidate cache if the SQLite file was deleted
    if _tables_verified and not _db_file_exists():
        _tables_verified = False
        logger.warning("SQLite DB file missing — recreating tables without restart")
    if _tables_verified:
        return
    try:
        async with engine.begin() as conn:
            from registry.models import Agent, AuditLog, AnomalyEvent  # noqa: F401
            await conn.run_sync(Base.metadata.create_all)
        _tables_verified = True
        logger.info("Database tables verified/created")
    except Exception as e:
        logger.error(f"Failed to ensure tables: {e}")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session per request.
    Automatically commits on success, rolls back on exception.
    Auto-creates tables if they don't exist (self-healing).

    Usage in routers:
        @router.post("/agents")
        async def create_agent(db: AsyncSession = Depends(get_db)):
            ...
    """
    await _ensure_tables()
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Initialize database tables. Called during FastAPI lifespan startup.
    In production, use Alembic migrations instead.
    """
    async with engine.begin() as conn:
        from registry.models import Agent, AuditLog, AnomalyEvent  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)

        # Create append-only trigger (PostgreSQL only — SQLite doesn't support triggers via SQL)
        if not _is_sqlite:
            from sqlalchemy import text
            await conn.execute(
                text("""
                    CREATE OR REPLACE FUNCTION prevent_audit_modification()
                    RETURNS TRIGGER AS $$
                    BEGIN
                        RAISE EXCEPTION 'Audit log is append-only. UPDATE and DELETE operations are prohibited.';
                        RETURN NULL;
                    END;
                    $$ LANGUAGE plpgsql;
                """)
            )

            await conn.execute(
                text("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_trigger WHERE tgname = 'audit_log_immutable'
                        ) THEN
                            CREATE TRIGGER audit_log_immutable
                                BEFORE UPDATE OR DELETE ON audit_log
                                FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
                        END IF;
                    END
                    $$;
                """)
            )
            logger.info("PostgreSQL append-only audit trigger created")
        else:
            logger.info("SQLite mode — append-only trigger skipped (enforced in application layer)")


async def close_db() -> None:
    """Dispose engine connections during shutdown."""
    await engine.dispose()
