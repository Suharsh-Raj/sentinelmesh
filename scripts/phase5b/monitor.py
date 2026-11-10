"""Observe controlled fixture syscalls and verify the guest boundary."""
import contextlib
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import time

from fixture import CANARY, COPIES, DECOYS, DOCUMENTS, MARKER, MARKER_BYTES, PAYLOAD, STATE

HERE = Path(__file__).resolve().parent
CGROUP = Path("/sys/fs/cgroup")
LABEL = "Controlled VM test"
LINE_PREFIX = "PHASE5B_RESULT "
IO = re.compile(r"^(read|write)\(\d+<([^>]+)>,.*\)\s+=\s+([1-9]\d*)$")
CONNECT = re.compile(
    r'^connect\(.*sin_port=htons\((\d+)\), sin_addr=inet_addr\("([0-9.]+)"\).*\)'
    r'\s+=\s+(0|-1 [A-Z0-9_]+)(?: .*)?$'
)
EXEC = re.compile(r'^execve\("([^"]+)",.*\)\s+=\s+0$')
WATCHDOG_SECONDS = 2


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, **options):
    return subprocess.run(args, text=True, check=True, **options)


def report(case, **values):
    print(LINE_PREFIX + json.dumps(dict(label=LABEL, case=case, **values)), flush=True)


def check_boundary():
    require(sys.platform == "linux" and os.geteuid() == 0, "Guest monitor requires Linux root")
    require({device.name for device in Path("/sys/class/net").iterdir()} == {"lo"}, "Unexpected NIC")
    for family in ("-4", "-6"):
        routes = command("ip", family, "route", "show", "default", capture_output=True)
        require(not routes.stdout.strip(), "Unexpected default route")
    filesystem_types = {
        line.split(" - ", 1)[1].split()[0]
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
    }
    require(not filesystem_types & {"9p", "virtiofs", "cifs", "nfs", "nfs4", "drvfs"}, "Shared mount present")
    require(not STATE.exists(), "Previous fixture state found")


def install_monitor():
    packages = sorted(str(path) for path in (HERE / "apk").glob("*.apk"))
    require(len(packages) == 4, "Expected the four Alpine monitor packages")
    offline = ("apk", "--no-network", "--repositories-file", "/dev/null")
    command(*offline, "verify", *packages)
    command(*offline, "add", "--no-cache", *packages)


def setup(user):
    DECOYS.mkdir(parents=True)
    for name, data in DOCUMENTS.items():
        path = DECOYS / name
        path.write_bytes(data)
        path.chmod(0o444)
    for folder in (COPIES, MARKER.parent):
        folder.mkdir()
        os.chown(folder, user.pw_uid, user.pw_gid)
    (STATE / "traces").mkdir(mode=0o700)
    command("ip", "link", "set", "lo", "up")
    command("ip", "addr", "add", f"{CANARY}/32", "dev", "lo")


def enter_scope(scope, uid, gid, case, receiver_port, canary_port):
    """Put the subject in the cgroup, drop privileges, then exec without a shell."""
    (Path(scope) / "cgroup.procs").write_text(str(os.getpid()))
    os.setgroups([])
    os.setgid(int(gid))
    os.setuid(int(uid))
    os.execv(sys.executable, [sys.executable, "-B", str(HERE / "fixture.py"),
                              case, receiver_port, canary_port])


def parse_trace(lines):
    reads, writes, connects, executables = {}, {}, [], []
    decoy_paths = {(DECOYS / name).as_posix(): name for name in DOCUMENTS}
    copy_paths = {(COPIES / name).as_posix(): name for name in DOCUMENTS}
    copy_paths[MARKER.as_posix()] = "marker"
    for line in lines:
        io = IO.match(line)
        if io:
            action, path, size = io.groups()
            names, totals = (decoy_paths, reads) if action == "read" else (decoy_paths | copy_paths, writes)
            if path in names:
                key = "source/" + names[path] if path in decoy_paths else names[path]
                totals[key] = totals.get(key, 0) + int(size)
        match = CONNECT.match(line)
        if match:
            port, host, status = match.groups()
            connects.append({"host": host, "port": int(port), "result": status})
        match = EXEC.match(line)
        if match:
            executables.append(match[1])
    return {"reads": reads, "writes": writes, "connects": connects, "executables": executables}


def run_subject(case, user, receiver_port, canary_port):
    scope = CGROUP / f"sentinelmesh-{case}"
    scope.mkdir()
    trace_prefix = STATE / "traces" / case
    require((scope / "cgroup.kill").is_file(), "Guest kernel lacks cgroup.kill")
    started = time.monotonic()
    with subprocess.Popen([
        "strace", "-ff", "-qq", "-yy", "-s", "0", "-o", str(trace_prefix),
        "-e", "trace=execve,read,write,connect",
        sys.executable, "-B", __file__, "_enter", str(scope), str(user.pw_uid),
        str(user.pw_gid), case, str(receiver_port), str(canary_port),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as tracer:
        try:
            ready, _, _ = select.select([tracer.stdout], [], [], 15)
            require(ready and tracer.stdout.readline() == b"READY\n", "Fixture readiness timed out")
            pids = [int(value) for value in (scope / "cgroup.procs").read_text().split()]
            require(len(pids) == (2 if case == "watchdog" else 1), "Unexpected fixture process count")
            identities = []
            for pid in pids:
                proc = Path("/proc") / str(pid)
                executable = os.readlink(proc / "exe")
                require(executable == str(Path(sys.executable).resolve()), "Unexpected subject executable")
                require(proc.stat().st_uid == user.pw_uid, "Fixture did not drop privileges")
                identities.append({"pid": pid, "exe": Path(executable).name, "uid": user.pw_uid})
            executing = time.monotonic()
            tracer.stdin.write(b"G")
            tracer.stdin.close()
            deadline = WATCHDOG_SECONDS if case == "watchdog" else 8
            timed_out = False
            try:
                tracer.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                timed_out = True
                watchdog_fired = time.monotonic()
                (scope / "cgroup.kill").write_text("1")
                tracer.wait(timeout=5)
            if case == "watchdog":
                require(timed_out, "Watchdog fixture exited before the timeout")
            else:
                require(not timed_out and tracer.returncode == 0, "Fixture failed or timed out")
            require("populated 0" in (scope / "cgroup.events").read_text().splitlines(), "Fixture tree still alive")
            finished = time.monotonic()
        finally:
            (scope / "cgroup.kill").write_text("1")
            if tracer.poll() is None:
                try:
                    tracer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tracer.kill()
                    tracer.wait(timeout=2)
    scope.rmdir()
    traces = {}
    for pid in pids:
        trace = parse_trace(Path(f"{trace_prefix}.{pid}").read_text().splitlines())
        traces[pid] = trace
    if case != "watchdog":
        require(traces[pids[0]]["executables"].count(sys.executable) == 2,
                "Missing launch and fixture exec evidence")
    values = {"startup_ms": round((executing-started)*1000, 3),
              "execution_ms": round((finished-executing)*1000, 3),
              "processes": identities, "process_tree_empty": True}
    if timed_out:
        values.update(watchdog_ms=round((watchdog_fired-executing)*1000, 3),
                      timeout=True, status="inconclusive")
    return traces[pids[0]] if len(pids) == 1 else traces, values


def configure_firewall(uid, receiver_port, canary_port):
    command("nft", "-f", "-", input=f"""table inet phase5b {{
      counter blocked {{ }}
      chain output {{
        type filter hook output priority filter; policy accept;
        meta skuid {uid} oifname "lo" ip daddr 127.0.0.1 tcp dport {receiver_port} accept
        meta skuid {uid} ip daddr {CANARY} tcp dport {canary_port} counter name blocked reject with tcp reset
        meta skuid {uid} reject with icmpx type admin-prohibited
      }}
    }}""")


def blocked_packets():
    output = command("nft", "-j", "list", "counter", "inet", "phase5b", "blocked", capture_output=True)
    return next(row["counter"]["packets"] for row in json.loads(output.stdout)["nftables"] if "counter" in row)


def run_cases():
    import pwd

    install_monitor()
    if not (CGROUP / "cgroup.controllers").exists():
        command("mount", "-t", "cgroup2", "none", str(CGROUP))
    command("adduser", "-D", "-H", "-s", "/sbin/nologin", "phase5b-subject")
    user = pwd.getpwnam("phase5b-subject")
    setup(user)
    with contextlib.closing(socket.create_server(("127.0.0.1", 0))) as receiver, \
            contextlib.closing(socket.create_server((CANARY, 0))) as canary:
        receiver_port, canary_port = receiver.getsockname()[1], canary.getsockname()[1]
        with socket.create_connection((CANARY, canary_port), timeout=1), canary.accept()[0]:
            pass
        configure_firewall(user.pw_uid, receiver_port, canary_port)
        report("boundary", loopback_only=True, shared_mounts=False, canary_reachable_to_controller=True)

        trace, timing = run_subject("baseline", user, receiver_port, canary_port)
        require(not (trace["reads"] or trace["writes"] or trace["connects"] or list(COPIES.iterdir())
                     or MARKER.exists() or select.select([receiver, canary], [], [], 0)[0]),
                "Baseline touched a controlled resource")
        report("baseline", **timing, decoy_reads=0, decoy_writes=0, copy_count=0)

        trace, timing = run_subject("bulk-copy", user, receiver_port, canary_port)
        require(trace["reads"] == {"source/" + name: len(data) for name, data in DOCUMENTS.items()},
                "Decoy read trace did not match the fixture")
        require(trace["writes"] == {name: len(data) for name, data in DOCUMENTS.items()},
                "Copy write trace did not match the fixture")
        require({item.name: item.read_bytes() for item in COPIES.iterdir()} == DOCUMENTS,
                "On-disk copy verification failed")
        require(not (trace["connects"] or MARKER.exists() or select.select([receiver, canary], [], [], 0)[0]),
                "Bulk copy used an unexpected resource")
        report("bulk-copy", **timing, decoy_reads=len(trace["reads"]), source_decoy_writes=0,
               copied_file_writes=len(trace["writes"]), copy_count=len(DOCUMENTS),
               bytes_read=sum(trace["reads"].values()), bytes_written=sum(trace["writes"].values()))

        before = blocked_packets()
        trace, timing = run_subject("follow-up", user, receiver_port, canary_port)
        receiver.settimeout(1)
        with receiver.accept()[0] as connection:
            connection.settimeout(1)
            data = connection.makefile("rb")
            with data:
                received = data.read(len(PAYLOAD) + 1)
        require(received == PAYLOAD, "Receiver did not confirm the complete synthetic transfer")
        require(trace["connects"] == [
            {"host": "127.0.0.1", "port": receiver_port, "result": "0"},
            {"host": CANARY, "port": canary_port, "result": "-1 ECONNREFUSED"},
        ], "Connect trace did not match")
        blocked = blocked_packets() - before
        require(blocked >= 1 and not select.select([receiver, canary], [], [], 0)[0],
                "Canary rejection not corroborated or extra connection observed")
        require(trace["writes"] == {"marker": len(MARKER_BYTES)} and not trace["reads"]
                and MARKER.read_bytes() == MARKER_BYTES, "Marker trace or content check failed")
        report("follow-up", **timing, completed_transfer_bytes=len(received),
               blocked_connection_attempts=1, canary_connect_errno="ECONNREFUSED",
               firewall_rejected_packets=blocked,
               canary_accepted_connections=0, canary_transferred_bytes=0, marker_write_bytes=len(MARKER_BYTES))

        traces, timing = run_subject("watchdog", user, receiver_port, canary_port)
        require(len(traces) == 2 and all(not (trace["reads"] or trace["writes"] or trace["connects"])
                                        for trace in traces.values()), "Unexpected watchdog evidence")
        report("watchdog", **timing, tree_processes_before_deadline=len(traces))
    require({item.name: item.read_bytes() for item in DECOYS.iterdir()} == DOCUMENTS,
            "Original synthetic decoys changed")
    os.sync()
    report("pre-discard-state", copies_present=len(list(COPIES.iterdir())),
           marker_present=MARKER.is_file(), original_decoys_intact=True)


if __name__ == "__main__":
    mode, *arguments = sys.argv[1:]
    if mode == "_enter":
        enter_scope(*arguments)
    elif mode in ("run", "clean"):
        check_boundary()
        print("PHASE5B_BOOT_READY", flush=True)
        if mode == "run":
            run_cases()
        else:
            report("post-discard-state", fixture_state_present=False)
    else:
        raise SystemExit("Use run or clean")
