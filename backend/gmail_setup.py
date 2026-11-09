"""Explicit CLI: python -m backend.gmail_setup."""
from .database import MAIL_SOURCE, SessionLocal, initialize_database
from .gmail_oauth import GmailError, authorize, read_config, write_authorization
from .gmail_sync import connect


def main():
    if MAIL_SOURCE != "gmail":
        print("Set MAIL_SOURCE=gmail before running Gmail setup.")
        return 1
    try:
        config = read_config()
        initialize_database()
        client, refresh = authorize(config)
        connect(SessionLocal, config, client)
        write_authorization(config, refresh)
    except GmailError as exc:
        print(str(exc))
        return 1
    except Exception:
        print("Gmail setup did not finish. Check the local paths and permissions, then retry.")
        return 1
    print("The Gmail profile matches the configured account. Read-only authorization saved locally.")
    print("Start SentinelMesh in Gmail mode to begin syncing. Setup did not list or import messages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
