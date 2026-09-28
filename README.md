# SentinelMesh

SentinelMesh is a local, key-free email and link-defense demo. It runs a FastAPI + SQLite backend and a React/Vite operations dashboard. MailAgent scores email evidence, LinkAgent performs static URL/file inspection and displays a **simulated** sandbox profile, and ChiefAgent's ledger records operator decisions and correlated incidents.

## Run locally

Requirements: Python 3.10+ and Node.js 20.19+ (or 22.12+). From this folder, run this one command in PowerShell, Terminal, or a command prompt:

```powershell
python run.py
```

The launcher creates a project-local Python virtual environment, installs dependencies on first run, starts both services, and stops them together with Ctrl+C.

- Dashboard: http://127.0.0.1:5173
- API docs: the URL and dynamically selected API port are printed by `python run.py`. The launcher tries port 8000 first, then selects a free port through 8099; the frontend proxies API and SSE requests to that selected port.
- SQLite database: `backend/sentinelmesh.db`

No credentials, external APIs, or secrets are needed. The UI uses a system-font fallback if network fonts are unavailable.

## Demo flow

Open **Demo controls** for five email scenarios and three link scenarios. Use **Link Lab** to analyze a URL or upload a file; choose a prebuilt behavior profile and watch its 10-second report timeline. The false-positive display-name scenario can be revoked from **Decision Ledger**; the email moves into Inbox and its sender is added to the allowlist. **Reset demo data** restores the seeded starting dataset.

Run the MailAgent unit cases with:

```powershell
.\.venv\Scripts\python.exe -m unittest backend.tests.test_mail_agent -v
```

On macOS/Linux use `.venv/bin/python -m unittest backend.tests.test_mail_agent -v`.

## Safety and scope

The demo never executes uploaded or downloaded content and never makes a network request to a submitted URL. Sandbox output is generated from fixed behavioral profiles; network addresses use documentation-only ranges. Uploaded files are limited to 10 MB and are analyzed in memory for metadata, SHA-256, and the EICAR test string. This is a project-evaluation prototype, not a production mail gateway or endpoint sandbox.

See [ARCHITECTURE.md](ARCHITECTURE.md) for event flow and future work.
