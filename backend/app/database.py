"""SQLAlchemy engine/session setup.

Defaults to a local SQLite file so the lab runs without PostgreSQL;
docker-compose overrides ``LAB_DATABASE_URL`` to point at PostgreSQL.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_connect_args = (
    {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(_settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables for local/dev (Alembic owns real migrations)."""
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
