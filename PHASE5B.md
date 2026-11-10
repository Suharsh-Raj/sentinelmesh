# Phase 5B · Controlled VM test

The controlled decoy-file fixtures ran inside the Phase 5A.2 Alpine 3.22.8 guest under QEMU TCG. The host runner used a fresh writable QCOW2 overlay and a read-only seed image with no virtual NIC, display, clipboard integration, or host folders. The guest verified loopback-only interfaces, absence of default routes and shared mounts, and absence of prior fixture state. It received only project fixture source and signed Alpine monitoring packages. Gmail remains read-only, and automatic scanning of Gmail links remains static. The fixture runner has no connection to the dashboard, automatic Gmail worker, or manual Link Lab simulation.

## Reproduce locally

From the repository root, point the host runner at the existing Phase 5A.2 provisioned Alpine disk, which supplies Python, nftables and iproute2. Keep VM assets and outputs outside the repository. The commands below use the existing Windows QEMU installation.

~~~powershell
$base = 'D:\PBL3-BACKUP\phase-05a2-fixture-vm\provisioned.qcow2'
$packages = 'D:\PBL3-BACKUP\phase-05b-tools'
New-Item -ItemType Directory -Force -Path $packages | Out-Null
foreach ($name in 'strace-6.13-r0.apk','libdw-0.193-r0.apk','libelf-0.193-r0.apk','musl-fts-1.2.7-r6.apk') {
    curl.exe -fsSL "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/$name" -o (Join-Path $packages $name)
    if ($LASTEXITCODE -ne 0) { throw "Download failed for $name" }
}
python -B scripts/phase5b/run.py --base $base --packages $packages --output-root 'D:\PBL3-BACKUP'
~~~

The runner checks the APK hashes on the host. Alpine verifies their signatures and installs the monitor offline inside the first disposable overlay. The guest monitor correlates process identities from procfs and cgroups with per-PID strace records. It counts positive-byte reads and writes on exact synthetic paths. For networking, it records the subject's connect result, the firewall counter, and bytes actually read from the guest-only receiver. [Alpine strace package](https://pkgs.alpinelinux.org/package/v3.22/main/x86_64/strace) · [strace descriptor decoding](https://strace.io/) · [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

## Measured results

Boot to the guest monitor took **179.3 s** for the observed overlay and **69.8 s** for the clean verification overlay, using 100 ms host sampling. Subject startup includes attaching the tracer and waiting for the fixture to report readiness. Execution runs from the start signal through process exit and verified cleanup.

| Case | Subject startup (ms) | Execution (ms) | Observed evidence |
| --- | ---: | ---: | --- |
| Benign baseline | 2544.476 | 123.098 | No decoy reads or writes, copies, or network connections. |
| Bulk copy | 2570.793 | 127.226 | 5 source decoys read, 0 source writes, and 5 verified copies. The tracer counted 203 bytes read and 203 bytes written. |
| Follow-up | 2277.544 | 232.825 | The guest-only receiver confirmed all 46 bytes. The canary connect returned ECONNREFUSED, with 1 firewall rejection and zero accepted connections or transferred bytes. The inert marker write was 26 bytes. |
| Watchdog control | 2256.122 | 2031.030 | Both subject PIDs (2146, 2147) were in the cgroup before execution. The 2-second deadline fired at 2001.503 ms and the cgroup was verified empty. The deliberately interrupted fixture was recorded as inconclusive. |

Each case ran an unprivileged **python3.12** subject under UID **1001**. The controller reached the canary before applying the subject's firewall policy, which supplied a positive reachability control. The rejected connect is evidence of an attempt. The receiver byte count establishes the separate completed transfer. The marker existed only under the fixture's mock directory, outside the guest's actual startup configuration. No fixture created a shell or registered a service.

All five copies and the marker existed immediately before shutdown, and the original synthetic decoys were intact. The host discarded the writable overlay and booted another fresh overlay from the same base. The guest found the fixture state absent, and both backing-image hashes matched their pre-run values. The second overlay was also discarded.

## Application verification and scope

- Two trace-parser tests (python -B -m unittest discover -s scripts/phase5b -v), 44 backend tests, and 18 ML tests passed.
- Isolated Gmail-mode Uvicorn started with a temporary SQLite database, empty OAuth directory, and mock Gmail transport. It produced one local MailAgent verdict with the frozen v1 advisory prediction, plus one separate static LinkAgent result with browser observation disabled.
- The monitor covers the selected fixture processes and syscalls. Real persistence, live external transfers, arbitrary malware, and monitoring of unrelated guest processes were outside this run.

The aggregate result and serial logs stay in the local run folder printed by the runner. Git holds the fixture source, parser tests and this aggregate report.
