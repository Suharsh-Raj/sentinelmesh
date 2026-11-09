# SentinelMesh

SentinelMesh runs a local FastAPI and SQLite backend with a React/Vite dashboard. MailAgent scores simulated or read-only Gmail messages and records a local Inbox or Quarantine decision. LinkAgent inspects URLs and uploaded files and builds a simulated sandbox report from a preselected profile. ChiefAgent records evidence and operator decisions in the Decision Ledger.

## Run the application

Use Python 3.11 or later and Node.js 20.19.x or 22.12 or later with npm. From the project root in PowerShell, run:

~~~powershell
npm ci --cache .npm-cache
$env:MAIL_SOURCE = 'simulated'
python run.py
~~~

The launcher uses `.ml-venv` when it exists and ML is enabled. Otherwise it creates or reuses `.venv`. It installs the selected backend requirements on first run, starts the dashboard at [127.0.0.1:5173](http://127.0.0.1:5173), and prints the API address. Press Ctrl+C to stop the services. The default database is `backend/sentinelmesh.db`. Use `SENTINELMESH_DB` to select a separate SQLite file for local verification.

Simulated is the default mode. Open **Demo controls** to submit a mail or link scenario. **Link Lab** shows the simulation timeline and static findings. Uploaded files are inspected in memory, and the simulated sandbox does not execute them or visit submitted URLs. **Decision Ledger** shows the original score and evidence. Revoke updates the existing ledger entry, records a separate event, and moves linked mail back to the local Inbox while allowlisting its sender. Reset demo data clears local decisions and the allowlist before reseeding. [Architecture and event flow](ARCHITECTURE.md)

Run the application tests in an isolated PowerShell session:

~~~powershell
$env:MAIL_SOURCE = 'simulated'
$env:SENTINELMESH_DB = ':memory:'
& .\.venv\Scripts\python.exe -B -m unittest discover -s backend/tests -v
Remove-Item Env:SENTINELMESH_DB
~~~

## Advisory ML mail analysis

SentinelMesh loads the trusted local `mail-tfidf-v1` bundle once at startup. Newly processed mail gets an experimental prediction, including mail from allowlisted senders. Message details and the Decision Ledger show the model result separately from the rule score and evidence. The model uses an uncalibrated class-1 score and the threshold stored in its manifest. Rules determine the verdict, folder, and allowlist actions. Seeded and historical rows are displayed as “Not analyzed by ML.” Imported mail, Revoke, and allowlist changes do not train the model.

The default bundle directory is `ml/models/mail-tfidf-v1`. Restore the local Phase 1 bundle from a trusted backup or follow the training instructions below on a clean clone. Set `SENTINELMESH_MODEL_DIR` to use another trusted copy of that bundle. Set `SENTINELMESH_ML_ENABLED=0` before running the launcher to disable ML. With a missing, corrupt, or incompatible bundle, the dashboard and `GET /api/stats` show the model status and rules continue to process mail. The email, event, and ledger snapshots record whether an ML result was available.

The recorded run used CPython **3.13.8** in a dedicated `.ml-venv` and the [pinned ML requirements](ml/requirements.txt). From the project root, create the environment and install the pinned packages:

~~~powershell
$mlCache = Join-Path (Get-Location).Path '.ml-cache'
$env:TEMP = Join-Path $mlCache 'tmp'
$env:TMP = $env:TEMP
$env:PIP_CACHE_DIR = Join-Path $mlCache 'pip'
New-Item -ItemType Directory -Force -Path $env:TEMP,$env:PIP_CACHE_DIR | Out-Null
py -3.13 -B -m venv .ml-venv
& .\.ml-venv\Scripts\python.exe -B -m pip --isolated install --cache-dir $env:PIP_CACHE_DIR --only-binary=:all: --index-url https://pypi.org/simple -r backend/requirements-ml.txt
~~~

The application validates the exact Python patch and package versions against the manifest. Once the bundle and environment are in place, run `python run.py`. Run the application tests with `.ml-venv\Scripts\python.exe` in the isolated test command above to include the real model smoke test.

### Reproduce or inspect the offline bundle

Follow the verified CSV download commands in the [ML setup guide](ml/README.md). Then run the tests and train offline:

~~~powershell
& .\.ml-venv\Scripts\python.exe -B -m unittest discover -s ml/tests -v
& .\.ml-venv\Scripts\python.exe -B -m ml.train --report .ml-cache/training-report.json
~~~

The trainer saves the local bundle under `ml/models/mail-tfidf-v1`. If the local bundle or report already exists, use new output paths as shown in the [ML setup guide](ml/README.md). Score a local UTF-8 body file using the saved model:

~~~powershell
New-Item -ItemType Directory -Force -Path .ml-cache | Out-Null
'Please review the updated project schedule before tomorrow.' | Set-Content -Encoding utf8 .ml-cache/example.txt
& .\.ml-venv\Scripts\python.exe -B -m ml.infer --subject 'Project update' --body-file .ml-cache/example.txt
~~~

On the 3,339-message held-out set, phishing precision was **89.46%**, recall **99.66%**, F1 **94.29%**, average precision **0.9952**, false-positive rate **1.15%**, and accuracy **98.92%**. Every legitimate example came from Enron and every phishing example came from Nazario. The benchmark cannot separate corpus recognition from phishing detection, and performance on modern Gmail remains unmeasured. [Evaluation and limitations](ml/EVALUATION.md) · [Dataset provenance and fingerprints](ml/DATASET.md)

## Read-only Gmail setup

Gmail mode is for one explicitly configured mailbox. Gmail is only read from the local application. The browser is opened for sign-in only when you run the separate setup command. SentinelMesh requests only the [Gmail read-only scope](https://developers.google.com/workspace/gmail/api/auth/scopes). Local Block, Quarantine, and Revoke affect the SentinelMesh database and allowlist. They do not change labels, move, delete, send, or mark messages read in Gmail.

1. In Google Cloud Console, select or create a project and [enable the Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com). In **Google Auth Platform**, [configure Branding and Audience](https://developers.google.com/workspace/guides/configure-oauth-consent), choose **External** for a consumer Gmail account, keep the app in **Testing**, and add the intended mailbox under **Test users**. Under **Data Access**, add only the Gmail read-only scope for this app. External testing authorization [expires after seven days](https://support.google.com/cloud/answer/15549945).
2. Under **Google Auth Platform → Clients**, [create an OAuth client](https://developers.google.com/workspace/guides/create-credentials#desktop-app) of type **Desktop app**. Download its JSON. Keep it outside the repo in your user-local directory, with the default filename shown below. No web redirect URI registration is needed for the [Desktop loopback flow](https://developers.google.com/identity/protocols/oauth2/native-app).
3. From the project root, prepare the local files:

~~~powershell
$gmailHome = Join-Path $env:LOCALAPPDATA 'SentinelMesh\gmail'
New-Item -ItemType Directory -Force -Path $gmailHome | Out-Null
Copy-Item -LiteralPath .\gmail.toml.example -Destination (Join-Path $gmailHome 'gmail.toml')
~~~

   Edit the local config to set the intended address, and place the downloaded JSON in that folder as **oauth-client.json**. You can instead set **client_file** to an absolute path outside the repository. Set **SENTINELMESH_GMAIL_HOME** to an alternate user-local configuration directory if needed. Do not paste or share the JSON or token. The setup command writes **oauth-token.json** there after it verifies the Gmail profile. The address and these OAuth files stay outside project backups and GitHub.

4. Stop any running SentinelMesh instance. Use the existing application environment (substitute **.venv** if it is the environment used by the launcher):

~~~powershell
$env:MAIL_SOURCE = 'gmail'
Remove-Item Env:SENTINELMESH_DB -ErrorAction SilentlyContinue
& .\.ml-venv\Scripts\python.exe -B -m backend.gmail_setup
~~~

   In the browser opened by setup, personally select the configured mailbox and review the consent. If the verified profile differs, setup stops before listing or retrieving mail. After setup reports success, run **python run.py** in the same PowerShell window. To refresh expired or revoked authorization, stop the app and run the setup command again against the same Gmail database.

The separate Gmail database defaults to **.gmail-data/gmail.db**. Keep it to preserve the first connection cutoff, imported rows, and sync history. **SENTINELMESH_GMAIL_DB** overrides the path for isolated verification. The backend rejects a simulated database in Gmail mode and never falls back to simulated mail. Gmail mode disables demo injection, Reset, and seed data. Use the loopback launcher for private mail; the dashboard is intended for local use.

The first successful account connection records the cutoff in UTC. Gmail's internal received timestamp determines eligibility; the sender's Date header does not. The app polls roughly every 15 seconds, backs off on transient failures, and uses [Gmail history](https://developers.google.com/workspace/gmail/api/guides/sync) for later polls. An expired cursor triggers a paginated Inbox and Spam scan, still subject to the original cutoff. A message must be in Inbox or Spam when retrieved and cannot be Draft or Trash. Newly eligible post-cutoff messages can be imported when a label changes. Once imported, the source label is retained as a snapshot; later label changes and Gmail deletions do not alter or remove the local copy. A message moved out of Inbox/Spam before it can be retrieved may never be imported. Mail and the cursor are persisted before a poll is reported successful. Recovering a backup requires the same local account and may require reauthorization; it does not reset the cutoff.

The parser prefers plain text, extracts readable text and inert HTTP(S) URLs from HTML, and does not load images, visit links, or fetch ordinary file attachments. It caps downloaded data and stored text; messages with omissions or truncation show a notice in message details.

Phase 3 tests exercise Inbox and Spam, history recovery, account matching, and OAuth callback security with synthetic data and mocked Google requests. Live Google consent, Inbox/Spam arrival, and duplicate checking against the selected mailbox remain pending until the account owner completes setup. Model health is separate from Gmail connection health.

## Source and recovery

GitHub holds the reproducible source, dependency manifests and lockfile, tests, dataset provenance, and aggregate evaluation reports. Local timestamped snapshots hold the complete recovery copy, including installed environments, raw datasets, fitted models, SQLite, and Git metadata where present. Credentials, databases, downloaded datasets, fitted models, dependencies, caches, build output, and backups stay out of tracked source.

## GitHub Pages preview

The [public preview](https://suharsh-raj.github.io/sentinelmesh/) shows synthetic mail, example link reports, and ledger entries. GitHub Actions builds it from the repository's seed fixtures in a fresh in-memory database. The preview is read-only. Run SentinelMesh locally to submit scans, revoke decisions, or reset demo data.
