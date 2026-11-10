"""Fixed, harmless subjects for the controlled Alpine VM test."""
import errno
import os
from pathlib import Path
import socket
import sys
import time

STATE = Path("/var/lib/sentinelmesh-phase5b")
DECOYS = STATE / "decoys"
COPIES = STATE / "copies"
MARKER = STATE / "mock-autostart" / "fixture.marker"
MARKER_BYTES = b"SentinelMesh inert marker\n"
PAYLOAD = b"SentinelMesh synthetic receiver test payload.\n"
CANARY = "192.0.2.20"
DOCUMENTS = {
    name + ".txt": f"SentinelMesh synthetic document: {name}\n".encode()
    for name in ("agenda", "budget", "inventory", "invoice", "notes")
}


def main():
    case, receiver_port, canary_port = sys.argv[1:]
    if (
        not Path("/etc/alpine-release").is_file()
        or os.geteuid() == 0
        or {device.name for device in Path("/sys/class/net").iterdir()} != {"lo"}
        or not STATE.is_dir()
    ):
        raise SystemExit("Fixture requires the isolated Alpine test guest")
    if case == "watchdog" and os.fork() == 0:
        time.sleep(60)
        os._exit(0)

    os.write(1, b"READY\n")
    if os.read(0, 1) != b"G":
        raise SystemExit("Fixture controller did not start the case")

    if case == "baseline":
        sum(range(1000))
    elif case == "bulk-copy":
        for name in DOCUMENTS:
            (COPIES / name).write_bytes((DECOYS / name).read_bytes())
    elif case == "follow-up":
        with socket.socket() as connection:
            connection.connect(("127.0.0.1", int(receiver_port)))
            connection.sendall(PAYLOAD)
        try:
            with socket.socket() as connection:
                connection.connect((CANARY, int(canary_port)))
                raise RuntimeError("Blocked canary was reachable")
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise
        MARKER.write_bytes(MARKER_BYTES)
    elif case == "watchdog":
        os.wait()
    else:
        raise SystemExit("Unknown fixture")


if __name__ == "__main__":
    main()
