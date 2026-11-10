# Phase 5A · Automatic Gmail link analysis

New Gmail imports create one job per stored MIME link in the same SQLite transaction as the email. The Gmail message-ID constraint and the unique pair of local email ID and link position keep polls and restarts idempotent. Pre-existing messages receive no backfill. One worker in the local API process leases one job at a time. A restart can reclaim an abandoned lease after 15 seconds. Only the current attempt can commit the terminal state, event, and ChiefAgent ledger entry. MailAgent and Gmail polling have separate tasks and do not wait for a scan.

MIME stores up to 30 unique URLs. The worker considers the first ten and records later positions as skipped. Message details flag omissions at the MIME extraction limit. The worker skips malformed or non-HTTP(S) URLs, recognized personalized actions, userinfo, and explicit local or non-public destinations. These checks make zero DNS or HTTP requests. URL-only recognition cannot identify every personalized link.

Static severity uses the existing URL indicators. A complete zero-indicator scan means the URL matched no static indicators. Page behavior remains unknown. Skipped, failed, and timed-out jobs have no severity. Static analysis runs a bounded, pure URL check in a worker thread and records a timeout if the check returns after its two-second measurement budget. The manual Link Lab retains its synthetic profiles. Link findings are advisory and separate from MailAgent rule verdicts and mail-tfidf-v1 predictions.

## Browser isolation gate

External browsing is disabled. Phase 5A initially found an existing WSL Ubuntu distribution but had no verified disposable browser runner. Phase 5A.2 below records controlled VM tests. The automatic worker performs static analysis only.

The controlled HTTP responses are in [link_scan_responses.json](backend/tests/fixtures/link_scan_responses.json). To serve them inside a future disposable test guest, run `python -B -m backend.tests.link_scan_fixture_server`. It binds to the guest's loopback on a fresh port. Cases include a benign page, a fake password form, a harmless attachment response, redirects to IPv4 loopback, LAN, metadata and IPv6 loopback, and a 20-second response for the proposed 12-second browser budget.

Before enabling external browsing, verify fresh browser state per scan, absence of credentials and host integrations, and egress enforcement outside the browser for navigation, redirects, subresources, DNS changes and private networks. Verify eligible HTTP(S) navigation, skipping personalized actions, form observation without submission, download observation without saving or executing, and termination of the browser process tree at the 12-second budget. The controlled results below cover the fixture environment. Enabling external browsing would require separate verification with its own egress policy.

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

## Phase 5A.2 · Controlled browser verification

**VM isolation and real browser observation passed for the controlled fixtures. External Gmail URL browsing stays disabled.** This was a test-only runner. The automatic Gmail worker still records static findings, and the manual Link Lab still reports simulated behavior.

### Environment and isolation

The host ran Windows 11 Home Single Language and QEMU 10.1.94. Windows Sandbox is unavailable on Home. WHPX initialized in the diskless capability probe, but the Alpine guest stalled at the bootloader with an MSI injection error. QEMU TCG booted a separate Alpine 3.22.8 guest. No Windows setting changes or reboot were needed. See the [Windows Sandbox edition requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) and the [QEMU network options](https://www.qemu.org/docs/master/system/invocation.html).

The [official Alpine image](https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/) matched the publisher's SHA-512. Alpine packages were installed during a separate provisioning boot. The fixture boot used a fresh disk overlay, a read-only seed containing only the controlled fixture files and test harness, and QEMU with its virtual NIC, display, and host file integrations disabled. The guest had loopback only, no IPv4 or IPv6 default route, and no shared mounts. It received no Gmail credentials, personal browser profile, clipboard integration, or shared folders.

The test ran Chromium 142.0.7444.59 Alpine Linux as an unprivileged user with a new profile and process-control cgroup for every case. Linux nftables allowed that user to reach only the fixture service on its exact IPv4 loopback address and port. The controller used a DevTools pipe, so browser control required no network exception. The cases used literal IPs and the runner had no DNS path. DNS rebinding was outside these fixture checks.

### Observations

| Browser fixture | Result | Elapsed |
| --- | --- | ---: |
| Benign HTML | Zero forms, password fields, and download attempts observed during the test | 1.147 s |
| Fake credential form | One form and one password field observed. The fixture server received zero POSTs. | 0.737 s |
| Attachment offer | DevTools emitted a download attempt and cancellation. Zero bytes were saved. | 0.556 s |
| Redirects and subresources | All 16 browser requests failed and incremented the guest firewall counter. Each result was recorded as inconclusive. | 0.321–0.542 s |
| Slow page | Inconclusive. The watchdog fired at 12.004 s and the cgroup was verified empty. | 12.131 s |

Redirect and subresource cases used reachable guest-only canaries representing IPv4 and IPv6 host, LAN, metadata, and loopback destinations. The guest fixture server received a real Chromium request for the 20-second slow response. The elapsed values run from navigation through confirmed cleanup. Fresh-browser startup was measured separately at 4.035–11.143 s under a 35-second startup cap. Earlier attempts hit a debugger-socket timeout and a cgroup launcher error. The corrected launcher also missed the first 12-second launch-to-result deadline under software emulation. The measured 12-second watchdog applies to navigation after a fresh browser is ready.

### Separate SentinelMesh validation

While the guest was handling that actual slow browser request, isolated Gmail-mode Uvicorn imported a synthetic message via the existing mock Gmail transport in 10.7 ms. The regular MailAgent poller committed its ALLOW verdict and frozen v1 advisory prediction 139.5 ms from import start, before the guest browser deadline. The existing background queue produced a separate static result and ChiefAgent ledger entry. Browser observations stayed in the fixture report, and Link Lab simulations remained separate.

All 44 backend tests and 18 ML tests passed using the commands above. The Phase 5A.2 host-side callback and HTTP-client tests measured 37.3 ms for import plus verdict and 12.019 s for the HTTP-client watchdog. Those timings are separate from the VM browser measurements.
