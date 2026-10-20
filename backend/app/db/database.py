from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.core.config import get_settings

from app.core.config import database_problem

settings = get_settings()

# PostgreSQL only -- refuse anything else with a clear message instead of failing later.
_why = database_problem(settings.DATABASE_URL)
if _why:
    raise RuntimeError(_why)

# pool_pre_ping: if PostgreSQL was restarted, a dead pooled connection is replaced instead of failing a request.
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
