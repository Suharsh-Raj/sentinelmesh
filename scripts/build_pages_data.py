"""Export a Pages preview using only the repository's synthetic seed data."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def main():
    dist = Path(__file__).resolve().parents[1] / "dist"
    if not (dist / "index.html").is_file():
        raise SystemExit("Build the frontend before exporting the Pages preview.")

    # The seeders and route functions share this fresh database for the export.
    os.environ["SENTINELMESH_DB"] = ":memory:"
    from backend import main as api
    from backend.database import Base, engine
    from backend.seed import seed_database
    from backend.seed_links import seed_links

    Base.metadata.create_all(engine)
    seed_database()
    seed_links()
    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": api.get_stats(),
        "emails": api.get_emails(),
        "ledger": api.get_ledger(),
        "events": api.get_events(limit=500),
        "links": api.get_links(),
        "incidents": api.get_incidents(),
    }
    (dist / "pages-demo.json").write_text(
        json.dumps(snapshot, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
