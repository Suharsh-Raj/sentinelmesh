import os
from pathlib import Path
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, sessionmaker

ROOT = Path(__file__).resolve().parents[1]
SIMULATED_DB = ROOT / "backend" / "sentinelmesh.db"
DEFAULT_GMAIL_DB = ROOT / ".gmail-data" / "gmail.db"
MAIL_SOURCE = os.getenv("MAIL_SOURCE", "simulated").strip().lower()
if MAIL_SOURCE not in ("simulated", "gmail"):
    raise RuntimeError("MAIL_SOURCE must be simulated or gmail.")


def configured_database(source):
    if source == "simulated":
        return os.getenv("SENTINELMESH_DB", str(SIMULATED_DB))
    if "SENTINELMESH_DB" in os.environ:
        raise RuntimeError("Gmail mode does not accept SENTINELMESH_DB. Use its separate database.")
    path = Path(os.getenv("SENTINELMESH_GMAIL_DB", DEFAULT_GMAIL_DB)).expanduser().resolve()
    if path.suffix.lower() not in (".db", ".sqlite", ".sqlite3"):
        raise RuntimeError("Use a persistent SQLite file for Gmail mode.")
    if path == SIMULATED_DB.resolve() or (
        path.is_file() and SIMULATED_DB.is_file() and path.samefile(SIMULATED_DB)
    ):
        raise RuntimeError("Gmail mode cannot use the simulated database.")
    return str(path)


DB_PATH = configured_database(MAIL_SOURCE)
engine = create_engine(
    URL.create("sqlite", database=DB_PATH),
    connect_args={"check_same_thread": False},
    hide_parameters=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass


def ensure_schema(db_engine, mail_source=None):
    """Create the SQLite schema and upgrade existing local demo databases."""
    additions = {
        "emails": {
            "processed": "BOOLEAN NOT NULL DEFAULT 1",
            "manually_quarantined": "BOOLEAN NOT NULL DEFAULT 0",
            "manual_quarantine_revision": "INTEGER NOT NULL DEFAULT 0",
            "reply_to": "VARCHAR(320) NOT NULL DEFAULT ''",
            "ml_analysis": "JSON",
            "source": "VARCHAR(20) NOT NULL DEFAULT 'simulated'",
            "account_key": "VARCHAR(64)",
            "external_message_id": "VARCHAR(255)",
            "source_label": "VARCHAR(20)",
            "received_at": "DATETIME",
            "content_limits": "JSON",
        },
        "ledger": {"ml_analysis": "JSON"},
    }
    with db_engine.begin() as connection:
        # Serialize startup schema changes before inspecting existing columns.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        if mail_source is not None:
            tables = set(inspect(connection).get_table_names())
            if "storage_mode" in tables:
                mode = connection.exec_driver_sql("SELECT mode FROM storage_mode WHERE id=1").scalar()
                if mode != mail_source:
                    raise RuntimeError("Database mail source does not match the configured mode.")
            elif mail_source == "gmail" and tables:
                raise RuntimeError("Gmail mode requires a fresh database or an existing Gmail database.")
            else:
                connection.exec_driver_sql(
                    "CREATE TABLE storage_mode (id INTEGER PRIMARY KEY CHECK (id=1), mode TEXT NOT NULL)"
                )
                connection.exec_driver_sql("INSERT INTO storage_mode VALUES (1, ?)", (mail_source,))
        Base.metadata.create_all(connection)
        inspector = inspect(connection)
        for table, fields in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in fields.items():
                if name not in existing:
                    connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        connection.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_email_external ON emails (source, account_key, external_message_id)"
        )


def initialize_database():
    if MAIL_SOURCE == "gmail":
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    ensure_schema(engine, MAIL_SOURCE)
