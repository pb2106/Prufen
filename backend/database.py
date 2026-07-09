"""
Database configuration and session management for Prüfen backend.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import shutil

# Database URL from environment or default to SQLite for easy setup
DATABASE_URL = os.getenv("DATABASE_URL")

# Vercel Serverless workaround for Read-Only filesystem
if os.getenv("VERCEL") == "1" and not DATABASE_URL:
    tmp_db_path = "/tmp/prufen.db"
    if not os.path.exists(tmp_db_path):
        db_source = os.path.join(os.path.dirname(__file__), "prufen.db")
        if os.path.exists(db_source):
            shutil.copy2(db_source, tmp_db_path)
    DATABASE_URL = "sqlite:////tmp/prufen.db"
elif not DATABASE_URL:
    DATABASE_URL = "sqlite:///./prufen.db"

# Create engine
# For SQLite, we need to enable check_same_thread=False
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """
    Dependency for getting database sessions.
    Usage: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
