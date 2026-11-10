# Phase 5A · Automatic Gmail link analysis

New Gmail imports create one job per stored MIME link in the same SQLite transaction as the email. The Gmail message-ID constraint and the unique pair of local email ID and link position keep polls and restarts idempotent. Pre-existing messages receive no backfill. One worker in the local API process leases one job at a time. A restart can reclaim an abandoned lease after 15 seconds. Only the current attempt can commit the terminal state, event, and ChiefAgent ledger entry. MailAgent and Gmail polling have separate tasks and do not wait for a scan.

MIME stores up to 30 unique URLs. The worker considers the first ten and records later positions as skipped. Message details flag omissions at the MIME extraction limit. The worker skips malformed or non-HTTP(S) URLs, recognized personalized actions, userinfo, and explicit local or non-public destinations. These checks make zero DNS or HTTP requests. URL-only recognition cannot identify every personalized link.

Static severity uses the existing URL indicators. A complete zero-indicator scan means the URL matched no static indicators. Page behavior remains unknown. Skipped, failed, and timed-out jobs have no severity. Static analysis runs a bounded, pure URL check in a worker thread and records a timeout if the check returns after its two-second measurement budget. The manual Link Lab retains its synthetic profiles. Link findings are advisory and separate from MailAgent rule verdicts and mail-tfidf-v1 predictions.

## Browser isolation gate

External browsing is disabled. Local checks found WSL with an existing Ubuntu distribution, but no disposable browser runner with a verified network boundary. The automatic worker never launches a browser. Validation used synthetic data and no real Gmail URLs.

The controlled HTTP responses are in [link_scan_responses.json](backend/tests/fixtures/link_scan_responses.json). To serve them inside a future disposable test guest, run `python -B -m backend.tests.link_scan_fixture_server`. It binds to the guest's loopback on a fresh port. Cases include a benign page, a fake password form, a harmless attachment response, redirects to IPv4 loopback, LAN, metadata and IPv6 loopback, and a 20-second response for the proposed 12-second browser budget.

Before enabling external browsing, verify fresh browser state per scan, absence of credentials and host integrations, and egress enforcement outside the browser for navigation, redirects, subresources, DNS changes and private networks. Verify eligible HTTP(S) navigation, skipping personalized actions, form observation without submission, download observation without saving or executing, and termination of the browser process tree at the 12-second budget. Browser isolation and browser observation tests remain pending.

## Verification

Run these commands using the existing ML environment from the project root. On Windows, asyncio and the HTTP fixtures need working loopback sockets. The suites use synthetic data and temporary SQLite.

~~~powershell
$env:MAIL_SOURCE = 'simulated'
$env:SENTINELMESH_DB = ':memory:'
& .\.ml-venv\Scripts\python.exe -B -m unittest discover -s backend/tests -v
& .\.ml-venv\Scripts\python.exe -B -m unittest discover -s ml/tests -v
npm.cmd run build
~~~

- 44 backend tests and 18 ML tests passed. The frontend production build passed.
- Two synthetic static checks took 0.170 ms and 0.259 ms. A delayed callback returned after 40.836 ms against a reduced 20 ms test budget and was recorded as timed out.
- A second synthetic Gmail import and MailAgent verdict completed in 33.3 ms while a separate scan was held open. The restart test reopened SQLite, reclaimed an abandoned lease, and retried the same Gmail ID. Each link produced one job, one event and one ledger entry.
- The HTTP fixture tests parsed the benign and fake-form markup, checked attachment headers without saving the payload, and rejected the four private redirect targets without following them. The fixture client was terminated in 12.027 seconds. This timed a single HTTP client process.
- An isolated Gmail-mode startup used a fresh SQLite database, an empty OAuth directory, and a mocked Gmail transport for import. In Chrome, the synthetic email showed a rule verdict, frozen v1 prediction, two completed static scans and one skipped link. The Decision Ledger showed separate static evidence and MailAgent records. Link Lab retained its simulation label.
