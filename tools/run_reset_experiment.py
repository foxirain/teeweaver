#!/usr/bin/env python3
from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "tools"))

from run_qemu_experiment import (  # noqa: E402
    QemuConsole,
    core_count,
    git_head,
    qemu_command,
    sha256_file,
)
from teeweaver.events import Event  # noqa: E402
from teeweaver.oracles import evaluate  # noqa: E402
from teeweaver.trace import write_jsonl  # noqa: E402


MINIMAL_PROMPT = "TWPROMPT> "


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(value for value in root.rglob("*") if value.is_file()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def prepare_shared(project_root: Path, output: Path) -> None:
    persist = output / "persist"
    persist.mkdir()
    persist.chmod(0o777)
    for name, source in {
        "libteeweaver.so": PROJECT / "instrumentation/supplicant_preload/libteeweaver.so",
        "storage_probe": PROJECT / "instrumentation/storage_probe/storage_probe",
    }.items():
        if not source.exists():
            raise RuntimeError(f"build {source} first")
        shutil.copy2(source, output / name)
    (output / "storage_probe").chmod(0o755)
    conf = project_root / "optee_os/out/arm/conf.mk"
    if conf.exists():
        shutil.copy2(conf, output / "optee-conf.mk")


def prepare_phase(phase: Path) -> None:
    phase.mkdir(parents=True, exist_ok=False)
    trace = phase / "trace.jsonl"
    trace.write_text("", encoding="utf-8")
    trace.chmod(0o666)


def setup_minimal_guest(console: QemuConsole) -> None:
    console.expect("=>", 30)
    console.send("qfw load ${kernel_addr_r} ${ramdisk_addr_r}")
    console.expect("=>", 15)
    console.send("booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr}")
    console.expect("~ # ", 120)
    # rdinit has no controlling TTY, so stty cannot disable serial echo. Build
    # the prompt from octal escapes so its literal bytes are absent from the
    # echoed command and can only be matched after command completion.
    console.send(
        "PS1=$(printf '\\124\\127\\120\\122\\117\\115\\120\\124\\076\\040')"
    )
    console.expect(MINIMAL_PROMPT, 10)
    console.send(
        "mount -t devtmpfs devtmpfs /dev; "
        "mount -t proc proc /proc; "
        "mount -t sysfs sysfs /sys; "
        "mkdir -p /mnt/host; "
        "mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/host || exit 90"
    )
    console.expect(MINIMAL_PROMPT, 30)


def start_supplicant(console: QemuConsole, phase_name: str) -> None:
    console.send(
        "LD_PRELOAD=/mnt/host/libteeweaver.so "
        f"TEEWEAVER_TRACE=/mnt/host/{phase_name}/trace.jsonl "
        "/usr/sbin/tee-supplicant -f /mnt/host/persist /dev/teepriv0 "
        f">/mnt/host/{phase_name}/supplicant.log 2>&1 & "
        "sleep 1; p=$(pidof tee-supplicant | awk '{print $1}'); "
        "test -n \"$p\" && grep -q libteeweaver /proc/$p/maps || exit 91"
    )
    console.expect(MINIMAL_PROMPT, 30)


def boot_phase(
    root: Path,
    output: Path,
    phase: Path,
    action: str,
    value: str | None = None,
) -> None:
    console = QemuConsole(
        qemu_command(
            root,
            phase,
            core_count(root),
            None,
            host_share=output,
            kernel_extra="rdinit=/bin/sh",
        ),
        root / "out/bin",
        phase / "normal.log",
    )
    try:
        setup_minimal_guest(console)
        start_supplicant(console, phase.name)
        if action == "write":
            if value is None or not value.isalnum():
                raise ValueError("storage token must be non-empty ASCII alphanumeric")
            command = (
                f"/mnt/host/storage_probe write {value} "
                f">/mnt/host/{phase.name}/storage-write.log 2>&1; "
                f"echo $? >/mnt/host/{phase.name}/storage-status; sync"
            )
        elif action == "read":
            command = (
                "/mnt/host/storage_probe read "
                f">/mnt/host/{phase.name}/storage-read.log 2>&1; "
                f"echo $? >/mnt/host/{phase.name}/storage-status; sync"
            )
        else:
            raise ValueError(action)
        console.send(command)
        console.expect(MINIMAL_PROMPT, 180)
    finally:
        console.stop()


def extract_token(path: Path, marker: str) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(marker):
            return line.split("value_hex=", 1)[1].strip()
    raise RuntimeError(f"missing {marker!r} in {path}")


def require_success(phase: Path) -> None:
    status = phase / "storage-status"
    if not status.exists() or status.read_text().strip() != "0":
        raise RuntimeError(f"storage phase failed: {phase.name}")


def snapshot_tree(source: Path, destination: Path) -> str:
    shutil.copytree(source, destination)
    return tree_digest(destination)


def restore_tree(snapshot: Path, destination: Path) -> None:
    # Both paths are children of a newly-created result directory. Replacing
    # this experiment-local image is the deliberate REE replay operation.
    if destination.parent != snapshot.parent:
        raise ValueError("snapshot and persistent image must share a result root")
    shutil.rmtree(destination)
    shutil.copytree(snapshot, destination)
    destination.chmod(0o777)


def config_value(path: Path, key: str) -> str | None:
    if not path.exists():
        return None
    prefix = f"{key}="
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    return None


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate persistent-storage freshness across a QEMU reset"
    )
    parser.add_argument(
        "--optee-root",
        type=Path,
        default=PROJECT.parent / "optee-qemu-v8",
    )
    parser.add_argument("--value", default="TEEWEAVER260926")
    parser.add_argument("--old-value", default="TEEWEAVEROLD260926")
    parser.add_argument(
        "--mode", choices=("clean", "ree-replay"), default="clean"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = (args.output or PROJECT / "results" / f"reset-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = args.optee_root.resolve()
    prepare_shared(root, output)
    if args.mode == "clean":
        phase1 = output / "phase-1-write"
        phase2 = output / "phase-2-read"
        prepare_phase(phase1)
        boot_phase(root, output, phase1, "write", args.value)
        require_success(phase1)
        acknowledged = extract_token(
            phase1 / "storage-write.log", "TEEWEAVER_STORAGE_ACK"
        )
        durable_digest = tree_digest(output / "persist")
        reset_evidence = {
            "kind": "cold-restart",
            "persist_sha256": durable_digest,
        }
        prepare_phase(phase2)
        boot_phase(root, output, phase2, "read")
        require_success(phase2)
        observed = extract_token(
            phase2 / "storage-read.log", "TEEWEAVER_STORAGE_OBSERVE"
        )
        workload = "storage-reset-clean-control"
        expected_ground_truth = False
    else:
        old_phase = output / "phase-1-old-write"
        new_phase = output / "phase-2-new-write"
        read_phase = output / "phase-3-replayed-read"
        prepare_phase(old_phase)
        boot_phase(root, output, old_phase, "write", args.old_value)
        require_success(old_phase)
        old_ack = extract_token(
            old_phase / "storage-write.log", "TEEWEAVER_STORAGE_ACK"
        )
        old_digest = snapshot_tree(output / "persist", output / "snapshot-old")

        prepare_phase(new_phase)
        boot_phase(root, output, new_phase, "write", args.value)
        require_success(new_phase)
        acknowledged = extract_token(
            new_phase / "storage-write.log", "TEEWEAVER_STORAGE_ACK"
        )
        durable_digest = snapshot_tree(
            output / "persist", output / "snapshot-new"
        )
        restore_tree(output / "snapshot-old", output / "persist")

        prepare_phase(read_phase)
        boot_phase(root, output, read_phase, "read")
        require_success(read_phase)
        observed = extract_token(
            read_phase / "storage-read.log", "TEEWEAVER_STORAGE_OBSERVE"
        )
        reset_evidence = {
            "kind": "cold-restart-with-ree-image-replay",
            "acknowledged_image_sha256": durable_digest,
            "replayed_image_sha256": old_digest,
            "old_acknowledged_hex": old_ack,
        }
        workload = "storage-reset-ree-replay-ground-truth"
        expected_ground_truth = (
            config_value(output / "optee-conf.mk", "CFG_INSECURE") == "y"
            and config_value(
                output / "optee-conf.mk", "CFG_REE_FS_INTEGRITY_RPMB"
            ) == "n"
        )

    observed_image_digest = tree_digest(output / "persist")

    events = [
        Event(1, "storage_ack", "storage-probe", {
            "key": "teeweaver-reset-token-v1", "digest": acknowledged,
        }),
        Event(2, "reset", "qemu-reset-controller", reset_evidence),
        Event(3, "storage_observe", "storage-probe", {
            "key": "teeweaver-reset-token-v1", "digest": observed,
        }),
    ]
    violations, stimuli, states = evaluate(events)
    write_jsonl(output / "epoch-history.jsonl", events)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workload": workload,
        "instrumentation_level": "L0",
        "mode": args.mode,
        "expected_ground_truth": expected_ground_truth,
        "acknowledged_hex": acknowledged,
        "observed_hex": observed,
        "persistent_image_sha256": durable_digest,
        "post_observation_image_sha256": observed_image_digest,
        "semantic_state_ids": states,
        "stimuli": [dataclasses.asdict(item) for item in stimuli],
        "violations": [dataclasses.asdict(item) for item in violations],
        "commits": {
            name: git_head(root / path)
            for name, path in {
                "optee_os": "optee_os",
                "optee_client": "optee_client",
                "linux": "linux",
                "qemu": "qemu",
                "build": "build",
            }.items()
        },
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(output)
    if args.mode == "clean":
        return 1 if violations else 0
    return 0 if expected_ground_truth and violations else 2


if __name__ == "__main__":
    raise SystemExit(main())
