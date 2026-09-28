import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = os.getenv("SENTINELMESH_DB", os.path.join(os.path.dirname(__file__), "sentinelmesh.db"))
engine = create_engine(f"sqlite:///{DB_PATH.replace(os.sep, '/')}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass
