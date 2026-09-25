#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.oracles import evaluate  # noqa: E402
from teeweaver.trace import read_jsonl  # noqa: E402
from teeweaver.workloads import Workload, load_workloads  # noqa: E402


WORKLOADS = load_workloads(PROJECT / "scenarios/workloads.json")


class QemuConsole:
    def __init__(self, command: list[str], cwd: Path, log_path: Path) -> None:
        self.log = log_path.open("wb")
        self.process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        assert self.process.stdout is not None
        self.fd = self.process.stdout.fileno()
        self.buffer = b""

    def expect(self, needle: str, timeout: float) -> bytes:
        wanted = needle.encode()
        deadline = time.monotonic() + timeout
        while wanted not in self.buffer:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited with {self.process.returncode} while waiting for {needle!r}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for {needle!r}")
            readable, _, _ = select.select([self.fd], [], [], min(0.5, remaining))
            if not readable:
                continue
            chunk = os.read(self.fd, 65536)
            if not chunk:
                continue
            self.log.write(chunk)
            self.log.flush()
            self.buffer = (self.buffer + chunk)[-262144:]
        found = self.buffer
        self.buffer = self.buffer[self.buffer.index(wanted) + len(wanted) :]
        return found

    def send(self, command: str) -> None:
        if self.process.stdin is None:
            raise RuntimeError("QEMU stdin is closed")
        self.process.stdin.write(command.encode() + b"\n")
        self.process.stdin.flush()

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


def git_head(path: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def git_status(path: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(path), "status", "--short"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def core_count(root: Path) -> int:
    conf = root / "optee_os/out/arm/conf.mk"
    if conf.exists():
        for line in conf.read_text(encoding="utf-8").splitlines():
            if line.startswith("CFG_TEE_CORE_NB_CORE="):
                return int(line.split("=", 1)[1])
    return 2


def qemu_command(
    root: Path,
    output: Path,
    cpus: int,
    fault: str | None,
    loader_debug: bool = False,
    client_trace: bool = False,
    host_share: Path | None = None,
    kernel_extra: str = "",
) -> list[str]:
    kernel_append = (
        "console=ttyAMA0,115200 earlycon=pl011,0x9000000 root=/dev/ram "
        "LD_PRELOAD=/mnt/host/libteeweaver.so "
        "TEEWEAVER_TRACE=/mnt/host/trace.jsonl"
    )
    if fault:
        kernel_append += f" TEEWEAVER_FAULT={fault}"
    if client_trace:
        kernel_append += " TEEWEAVER_TRACE_CLIENT=1"
    if loader_debug:
        kernel_append += " LD_DEBUG=bindings LD_DEBUG_OUTPUT=/mnt/host/lddebug"
    if kernel_extra:
        kernel_append += f" {kernel_extra}"
    shared_output = (host_share or output).resolve()
    return [
        str(root / "qemu/build/qemu-system-aarch64"),
        "-display",
        "none",
        "-monitor",
        "none",
        "-smp",
        str(cpus),
        "-cpu",
        "max,sme=off,pauth-impdef=on",
        "-d",
        "unimp",
        "-semihosting-config",
        "enable=on,target=native",
        "-m",
        "1057",
        "-bios",
        "bl1.bin",
        "-initrd",
        "rootfs.cpio.gz",
        "-kernel",
        "Image",
        "-append",
        kernel_append,
        "-machine",
        "virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false",
        "-object",
        "rng-random,filename=/dev/urandom,id=rng0",
        "-device",
        "virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000",
        "-netdev",
        "user,id=vmnic",
        "-device",
        "virtio-net-device,netdev=vmnic",
        "-fsdev",
        f"local,id=twsrc,path={PROJECT},security_model=none,readonly=on",
        "-device",
        "virtio-9p-device,fsdev=twsrc,mount_tag=teeweaver",
        "-fsdev",
        f"local,id=twout,path={shared_output},security_model=none",
        "-device",
        "virtio-9p-device,fsdev=twout,mount_tag=host",
        "-serial",
        "stdio",
        "-serial",
        f"file:{output / 'secure.log'}",
    ]


def setup_guest(console: QemuConsole) -> None:
    console.expect("=>", 30)
    console.send("qfw load ${kernel_addr_r} ${ramdisk_addr_r}")
    console.expect("=>", 15)
    console.send("booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr}")
    console.expect("buildroot login:", 120)
    console.send("root")
    console.expect("# ", 10)
    # The serial console normally echoes commands.  Completion tokens embedded
    # in an echoed command would otherwise satisfy expect() before the command
    # has run, producing a false successful experiment with empty artifacts.
    console.send("stty -echo")
    console.expect("# ", 10)
    console.send(
        "mkdir -p /mnt/tw && "
        "mount -t 9p -o trans=virtio,version=9p2000.L,ro teeweaver /mnt/tw && "
        "echo __TEEWEAVER_MOUNTED__"
    )
    console.expect("__TEEWEAVER_MOUNTED__", 20)


def verify_supplicant(console: QemuConsole) -> None:
    console.send(
        "p=$(pidof tee-supplicant | awk '{print $1}'); "
        "test -n \"$p\" && grep -q libteeweaver /proc/$p/maps && "
        "echo __TEEWEAVER_READY__"
    )
    console.expect("__TEEWEAVER_READY__", 20)


def prepare_ffa_driver(root: Path, output: Path) -> None:
    source = root / "out/linux-arm-ffa-user"
    required = ("arm-ffa-user.ko", "load_module.sh", "sp_uuid_list.txt")
    missing = [name for name in required if not (source / name).is_file()]
    if missing:
        raise RuntimeError(
            "FF-A workload requires built linux-arm-ffa-user artifacts: "
            + ", ".join(missing)
        )
    target = output / "out/linux-arm-ffa-user"
    target.mkdir(parents=True, exist_ok=False)
    for name in required:
        shutil.copy2(source / name, target / name)


def prepare_workload_programs(output: Path, workload: Workload) -> None:
    if any(test.program == "ffa_probe" for test in workload.tests):
        source = PROJECT / "instrumentation/ffa_probe/ffa_probe"
        if not source.is_file():
            raise RuntimeError(f"build {source} before running this workload")
        shutil.copy2(source, output / "ffa_probe")


def capture_supplicant_layout(console: QemuConsole) -> None:
    console.send(
        "p=$(pidof tee-supplicant | awk '{print $1}'); "
        "cat /proc/$p/maps >/mnt/host/supplicant.maps; "
        "for f in /proc/$p/fd/*; do "
        "printf '%s ' \"$f\"; readlink \"$f\"; done "
        ">/mnt/host/supplicant-fds.txt; "
        "sync; echo __TEEWEAVER_LAYOUT__"
    )
    console.expect("__TEEWEAVER_LAYOUT__", 20)


def run_workload(
    console: QemuConsole, workload: Workload, ffa_fault: str | None = None
) -> None:
    environment = (
        "env LD_PRELOAD=/mnt/host/libteeweaver.so "
        "TEEWEAVER_TRACE=/mnt/host/trace.jsonl"
    )
    if workload.ffa_trace:
        environment += " TEEWEAVER_TRACE_FFA=1"
    if ffa_fault:
        environment += f" TEEWEAVER_FFA_FAULT={shlex.quote(ffa_fault)}"
    commands = []
    for test in workload.tests:
        if test.program == "xtest":
            suite = f" -t {shlex.quote(test.suite)}" if test.suite else ""
            invocation = f"xtest{suite} {shlex.quote(test.test_id)}"
        else:
            invocation = " ".join(
                ["/mnt/host/ffa_probe"]
                + [shlex.quote(value) for value in test.arguments]
            )
        commands.append(
            f"{environment} {invocation} "
            f">/mnt/host/xtest-{test.label}.log 2>&1; "
            f"echo $? >/mnt/host/status-{test.label}"
        )
    if workload.mode == "parallel":
        jobs = " & ".join(f"({command})" for command in commands) + " & "
        ready = " || ".join(
            f"[ ! -s /mnt/host/status-{test.label} ]"
            for test in workload.tests
        )
        command = (
            jobs + f"while {ready}; do sleep 1; done; "
            "sync; echo __TEEWEAVER_DONE__"
        )
    else:
        command = "; ".join(commands) + "; sync; echo __TEEWEAVER_DONE__"
    console.send(command)
    console.expect("__TEEWEAVER_DONE__", workload.timeout)


def validate_artifacts(output: Path, workload: Workload) -> None:
    trace = output / "trace.jsonl"
    if not trace.exists() or trace.stat().st_size == 0:
        raise RuntimeError("experiment completed without a non-empty trace.jsonl")

    expected = tuple(
        name
        for test in workload.tests
        for name in (f"status-{test.label}", f"xtest-{test.label}.log")
    )
    missing = [name for name in expected if not (output / name).exists()]
    if missing:
        raise RuntimeError(f"experiment completed without artifacts: {', '.join(missing)}")
    if workload.ffa_trace:
        events = read_jsonl(trace)
        if not any(event.op.startswith("ffa_") for event in events):
            raise RuntimeError(
                "FF-A workload produced no FF-A transition; the test was likely skipped"
            )


def summarize(
    root: Path,
    output: Path,
    workload: str,
    cpus: int,
    fault: str | None,
    client_trace: bool,
    ffa_trace: bool,
    workload_timeout: int,
    run_error: str | None = None,
) -> None:
    trace_path = output / "trace.jsonl"
    events = read_jsonl(trace_path) if trace_path.exists() else []
    violations, stimuli, state_ids = evaluate(events)
    statuses = {}
    for path in sorted(output.glob("status-*")):
        statuses[path.name.removeprefix("status-")] = path.read_text().strip()
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workload": workload,
        "fault": fault,
        "instrumentation_level": "+".join(
            ["L0"]
            + (["client"] if client_trace else [])
            + (["ffa"] if ffa_trace else [])
        ),
        "client_trace": client_trace,
        "ffa_trace": ffa_trace,
        "cpus": cpus,
        "workload_timeout": workload_timeout,
        "events": len(events),
        "semantic_states": len(state_ids),
        "semantic_state_ids": state_ids,
        "statuses": statuses,
        "run_error": run_error,
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
        "workspace_status": {
            name: git_status(root / path)
            for name, path in {
                "optee_os": "optee_os",
                "optee_client": "optee_client",
                "linux": "linux",
                "qemu": "qemu",
                "build": "build",
            }.items()
        },
        "artifact_sha256": {
            name: sha256_file(path)
            for name, path in {
                "interposer": output / "libteeweaver.so",
                "optee_config": output / "optee-conf.mk",
                "bl1": root / "out/bin/bl1.bin",
                "linux_image": root / "out/bin/Image",
                "rootfs": root / "out/bin/rootfs.cpio.gz",
                "qemu": root / "qemu/build/qemu-system-aarch64",
            }.items()
        },
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--optee-root",
        type=Path,
        default=PROJECT.parent / "optee-qemu-v8",
    )
    parser.add_argument(
        "--workload",
        choices=tuple(sorted(WORKLOADS)),
        default="baseline",
    )
    parser.add_argument(
        "--fault",
        default="auto",
        help="interposer rule, 'none', or 'auto' for the workload default",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--loader-debug",
        action="store_true",
        help="capture dynamic-loader bindings (diagnostic; very verbose)",
    )
    parser.add_argument(
        "--client-trace",
        action="store_true",
        help="trace client INVOKE/CANCEL ioctls (experimental; validate observer effect)",
    )
    parser.add_argument(
        "--timeout-override",
        type=int,
        help="override workload timeout (useful for bounded nontermination probes)",
    )
    args = parser.parse_args()
    root = args.optee_root.resolve()
    library = PROJECT / "instrumentation/supplicant_preload/libteeweaver.so"
    if not library.exists():
        raise SystemExit(f"build {library} first")
    output = args.output
    if output is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = PROJECT / "results" / f"{stamp}-{args.workload}"
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if args.loader_debug:
        output.chmod(0o777)
    shutil.copy2(library, output / "libteeweaver.so")
    optee_conf = root / "optee_os/out/arm/conf.mk"
    if optee_conf.exists():
        shutil.copy2(optee_conf, output / "optee-conf.mk")
    workload = WORKLOADS[args.workload]
    if args.timeout_override is not None:
        if args.timeout_override < 1:
            parser.error("--timeout-override must be positive")
        workload = dataclasses.replace(workload, timeout=args.timeout_override)
    if workload.ffa_trace:
        prepare_ffa_driver(root, output)
    prepare_workload_programs(output, workload)
    trace_path = output / "trace.jsonl"
    trace_path.write_text("", encoding="utf-8")
    trace_path.chmod(0o666)
    cpus = core_count(root)
    if args.fault == "auto":
        fault = "swap_pair:0" if args.workload == "load-ta-swap" else None
    elif args.fault == "none":
        fault = None
    else:
        fault = args.fault
    ffa_fault = fault if fault and fault.startswith("ffa_") else None
    rpc_fault = None if ffa_fault else fault
    console = QemuConsole(
        qemu_command(
            root, output, cpus, rpc_fault, args.loader_debug, args.client_trace
        ),
        root / "out/bin",
        output / "normal.log",
    )
    run_error = None
    try:
        setup_guest(console)
        verify_supplicant(console)
        capture_supplicant_layout(console)
        run_workload(console, workload, ffa_fault)
        validate_artifacts(output, workload)
    except Exception as error:
        run_error = f"{type(error).__name__}: {error}"
        raise
    finally:
        console.stop()
        summarize(
            root, output, args.workload, cpus, fault, args.client_trace,
            workload.ffa_trace,
            workload.timeout,
            run_error
        )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
