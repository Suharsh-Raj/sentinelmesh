# SentinelMesh

SentinelMesh runs a local FastAPI and SQLite backend with a React/Vite dashboard. MailAgent scores demo email with rules and records a local Inbox or Quarantine decision. LinkAgent inspects URLs and uploaded files and builds a simulated sandbox report from a preselected profile. ChiefAgent records evidence and operator decisions in the Decision Ledger.

## Run the application

Use Python 3.10 or later and Node.js 20.19.x or 22.12 or later with npm. From the project root in PowerShell, run:

~~~powershell
npm ci --cache .npm-cache
python run.py
~~~

The launcher creates the app's `.venv` and installs the backend requirements on first run. It starts the dashboard at [127.0.0.1:5173](http://127.0.0.1:5173) and prints the API address. Press Ctrl+C to stop the services. The default database is `backend/sentinelmesh.db`. Use `SENTINELMESH_DB` to select a separate SQLite file for local verification.

Open **Demo controls** to submit a mail or link scenario. **Link Lab** shows the simulation timeline and static findings. Uploaded files are inspected in memory, and the simulated sandbox does not execute them or visit submitted URLs. **Decision Ledger** shows the original score and evidence. Revoke updates the existing ledger entry, records a separate event, and moves linked mail back to the local Inbox while allowlisting its sender. Reset demo data clears local decisions and the allowlist before reseeding. Gmail ingestion is future work. [Architecture and event flow](ARCHITECTURE.md)

Run the application tests in an isolated PowerShell session:

~~~powershell
$env:SENTINELMESH_DB = ':memory:'
& .\.venv\Scripts\python.exe -B -m unittest discover -s backend/tests -v
Remove-Item Env:SENTINELMESH_DB
~~~

## Train and use the offline classifier

Phase 1 produced `mail-tfidf-v1`, a TF-IDF and logistic regression pipeline. The CLI scores local text separately from the running application. The model uses an uncalibrated class-1 score and a threshold chosen on validation data. MailAgent's live demo decisions continue to use its rules.

The recorded run used CPython **3.13.8** in a dedicated `.ml-venv` and the [pinned ML requirements](ml/requirements.txt). From the project root, create the environment and install the pinned packages:

~~~powershell
$mlCache = Join-Path (Get-Location).Path '.ml-cache'
$env:TEMP = Join-Path $mlCache 'tmp'
$env:TMP = $env:TEMP
$env:PIP_CACHE_DIR = Join-Path $mlCache 'pip'
New-Item -ItemType Directory -Force -Path $env:TEMP,$env:PIP_CACHE_DIR | Out-Null
py -3.13 -B -m venv .ml-venv
& .\.ml-venv\Scripts\python.exe -B -m pip --isolated install --cache-dir $env:PIP_CACHE_DIR --only-binary=:all: --index-url https://pypi.org/simple -r ml/requirements.txt
~~~

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

## Source and recovery

GitHub holds the reproducible source, dependency manifests and lockfile, tests, dataset provenance, and aggregate evaluation reports. Local timestamped snapshots hold the complete recovery copy, including installed environments, raw datasets, fitted models, SQLite, and Git metadata where present. Credentials, databases, downloaded datasets, fitted models, dependencies, caches, build output, and backups stay out of tracked source.
