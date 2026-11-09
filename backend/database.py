import os
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = os.getenv("SENTINELMESH_DB", os.path.join(os.path.dirname(__file__), "sentinelmesh.db"))
engine = create_engine(
    f"sqlite:///{DB_PATH.replace(os.sep, '/')}",
    connect_args={"check_same_thread": False},
    hide_parameters=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass


def ensure_schema(db_engine):
    """Create the SQLite schema and upgrade existing local demo databases."""
    additions = {
        "emails": {
            "processed": "BOOLEAN NOT NULL DEFAULT 1",
            "reply_to": "VARCHAR(320) NOT NULL DEFAULT ''",
            "ml_analysis": "JSON",
        },
        "ledger": {"ml_analysis": "JSON"},
    }
    with db_engine.begin() as connection:
        # Serialize startup schema changes before inspecting existing columns.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        Base.metadata.create_all(connection)
        inspector = inspect(connection)
        for table, fields in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in fields.items():
                if name not in existing:
                    connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
