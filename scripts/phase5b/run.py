"""Run the Phase 5B fixtures in the Phase 5A.2 QEMU Alpine environment."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
RESULT_PREFIX = "PHASE5B_RESULT "
PACKAGES = {
    "libdw-0.193-r0.apk": "c0b46c47f501c57e02d3c454fddad9f2ada0bf9d58bca1ccd575c428257e3b35",
    "libelf-0.193-r0.apk": "b8df03bd86f172aa1741790592056e6d6588247ddf6473920fa32cd7cc681f6a",
    "musl-fts-1.2.7-r6.apk": "7e4ed22290aba56fb0f4534164d424e1b7e6d2da576837dd9ef12afee929fd1d",
    "strace-6.13-r0.apk": "ccda738aa2e679d5732f61adaec8ee6340c3a2eeb4285c6dde50adcc5856f91c",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def external_path(value):
    path = value.resolve(strict=True)
    if path.is_relative_to(PROJECT):
        raise ValueError("VM images, packages and results must stay outside the repository")
    return path


def make_seed(qemu_img, folder, mode, files):
    source = folder / "seed"
    source.mkdir()
    (source / "meta-data").write_text(
        f"instance-id: phase5b-{uuid4().hex}\nlocal-hostname: sentinel-fixture\n",
        encoding="ascii", newline="\n",
    )
    config = "#cloud-config\nwrite_files:\n"
    for dest, path in files.items():
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        config += f"  - path: /opt/phase5b/{dest}\n    encoding: b64\n    content: {encoded}\n"
    config += (
        'runcmd:\n  - [sh, -c, "python3 -B -u /opt/phase5b/monitor.py '
        f'{mode} >/dev/ttyS0 2>&1; result=$?; echo PHASE5B_EXIT=$result >/dev/ttyS0; poweroff"]\n'
    )
    (source / "user-data").write_text(config, encoding="ascii", newline="\n")
    media = folder / "seed.img"
    # Same offline FAT conversion and CIDATA volume label as the Phase 5A.2 runner.
    subprocess.run([qemu_img, "convert", "-f", "vvfat", "-O", "raw",
                    "fat:ro:" + source.as_posix(), media], check=True)
    with media.open("r+b") as stream:
        mbr = stream.read(512)
        partition = struct.unpack_from("<I", mbr, 454)[0]
        stream.seek(partition * 512)
        boot = stream.read(512)
        bps, _, reserved, fats, _, _, _, sectors_per_fat = struct.unpack_from("<HBHBHHBH", boot, 11)
        if bps != 512 or boot[43:62] != b"QEMU VVFAT FAT16   ":
            raise RuntimeError("Unexpected QEMU FAT boot sector")
        root_offset = (partition + reserved + fats * sectors_per_fat) * bps
        stream.seek(root_offset)
        label = stream.read(32)
        if label[:11] != b"QEMU VVFAT " or not label[11] & 8:
            raise RuntimeError("Unexpected QEMU FAT volume label")
        for offset in (partition * 512 + 43, root_offset):
            stream.seek(offset)
            stream.write(b"CIDATA     ")
    return media


def boot(qemu, qemu_img, base, folder, mode, files):
    folder.mkdir()
    disk = folder / "test.qcow2"
    media = folder / "seed.img"
    try:
        media = make_seed(qemu_img, folder, mode, files)
        log = folder / "serial.log"
        subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "qcow2",
                        "-b", base, disk, "6G"], check=True)
        args = [
            qemu, "-no-user-config", "-nodefaults", "-machine", "q35", "-accel", "tcg,thread=multi",
            "-cpu", "max", "-m", "4096", "-smp", "4", "-nic", "none", "-display", "none",
            "-vga", "none", "-monitor", "none", "-parallel", "none", "-no-reboot",
            "-serial", f"file:{log.as_posix()}",
            "-drive", f"file={disk.as_posix()},if=virtio,format=qcow2",
            "-drive", f"file={media.as_posix()},if=virtio,format=raw,readonly=on",
        ]
        with (folder / "qemu.log").open("wb") as trace:
            started = time.monotonic()
            with subprocess.Popen(args, stdout=trace, stderr=subprocess.STDOUT) as process:
                ready = None
                try:
                    while process.poll() is None:
                        now = time.monotonic()
                        if ready is None and log.exists() and b"PHASE5B_BOOT_READY" in log.read_bytes():
                            ready = now
                        if now - started > 300:
                            raise TimeoutError("Disposable QEMU guest exceeded 300 seconds")
                        time.sleep(0.1)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                total_seconds = time.monotonic() - started
            serial = log.read_text(encoding="utf-8", errors="replace")
            if process.returncode or "PHASE5B_EXIT=0" not in serial or ready is None:
                raise RuntimeError(f"{mode} guest failed. See {log}")
            results = [json.loads(line[len(RESULT_PREFIX):])
                       for line in serial.splitlines() if line.startswith(RESULT_PREFIX)]
            return {"boot_to_monitor_seconds": round(ready-started, 3),
                    "boot_to_poweroff_seconds": round(total_seconds, 3), "records": results}
    finally:
        # The runner created this exact file in a new directory.
        disk.unlink(missing_ok=True)
        media.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path, help="Verified Phase 5A.2 provisioned.qcow2")
    parser.add_argument("--packages", required=True, type=Path, help="Folder of signed Alpine monitor packages")
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--qemu-dir", type=Path, default=Path(r"C:\Program Files\qemu"))
    args = parser.parse_args()
    base, packages, output_root = map(external_path, (args.base, args.packages, args.output_root))
    qemu = args.qemu_dir / "qemu-system-x86_64.exe"
    qemu_img = args.qemu_dir / "qemu-img.exe"
    files = {name: HERE / name for name in ("monitor.py", "fixture.py")}
    installed_files = dict(files)
    for name, expected in PACKAGES.items():
        path = (packages / name).resolve(strict=True)
        if path.parent != packages or digest(path) != expected:
            raise RuntimeError(f"Alpine monitor package hash mismatch for {name}")
        installed_files["apk/" + name] = path
    layers = json.loads(subprocess.check_output([qemu_img, "info", "--backing-chain", "--output=json", base]))
    images = {external_path(Path(layer["filename"])) for layer in layers}
    hashes = {path: digest(path) for path in images}
    root = Path(tempfile.mkdtemp(prefix="phase-05b-vm-", dir=output_root))
    print(f"Local results folder {root}", flush=True)
    measured = boot(qemu, qemu_img, base, root / "observed", "run", installed_files)
    if [item["case"] for item in measured["records"]] != [
        "boundary", "baseline", "bulk-copy", "follow-up", "watchdog", "pre-discard-state"
    ]:
        raise RuntimeError("Incomplete measured fixture results")
    print("Observed overlay discarded. Verifying absence in a fresh overlay.", flush=True)
    clean = boot(qemu, qemu_img, base, root / "clean", "clean", files)
    if clean["records"] != [{"label": "Controlled VM test", "case": "post-discard-state", "fixture_state_present": False}]:
        raise RuntimeError("Clean overlay did not prove state absence")
    if hashes != {path: digest(path) for path in images}:
        raise RuntimeError("A backing image changed")
    results = {"label": "Controlled VM test", "measured": measured, "fresh_overlay": clean,
               "backing_images_unchanged": True, "test_overlays_discarded": True}
    content = json.dumps(results, indent=2) + "\n"
    (root / "result.json").write_text(content, encoding="utf-8")
    print(content, end="")


if __name__ == "__main__":
    main()
