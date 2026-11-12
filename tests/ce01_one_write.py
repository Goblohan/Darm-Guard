#!/usr/bin/env python3
"""Draft CE-01: one admitted Guard write, broker traced from process launch.

Place this file at tests/ce01_one_write.py in the Darm-Guard checkout.
Review against the pinned checkout before running. It creates only --out.
The trace uses raw read/write arguments so file contents and key buffers are
not rendered into the retained trace.
"""
import argparse
import atexit
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import darm_guard.broker as B


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def traced_child_pid(tracer_pid):
    p = Path(f"/proc/{tracer_pid}/task/{tracer_pid}/children")
    try:
        ids = p.read_text().split()
        return int(ids[0]) if len(ids) == 1 else None
    except (OSError, ValueError):
        return None


def require(condition, reason, checks):
    checks[reason] = bool(condition)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    out = args.out.expanduser().absolute()
    if out.exists():
        raise SystemExit(f"refusing to overwrite: {out}")
    if shutil.which("strace") is None:
        raise SystemExit("strace is required; no files created")

    out.mkdir(parents=True, mode=0o700)
    workspace = out / "workspace"
    reports = workspace / "reports"
    reports.mkdir(parents=True)
    suffix = uuid.uuid4().hex
    leaf = f"ce01-{suffix}.txt"
    virtual_target = f"/workspace/reports/{leaf}"
    target = reports / leaf
    payload = f"CE01{suffix}".encode("ascii")
    payload_text = payload.decode("ascii")
    private_dir = Path(tempfile.mkdtemp(prefix="ce01-broker-private-"))
    private_dir.chmod(0o700)
    atexit.register(shutil.rmtree, private_dir, ignore_errors=True)
    audit = private_dir / "audit.jsonl"
    registry = out / "registry.txt"
    intents = out / "intents.txt"
    config = out / "config.json"
    trace = out / "trace.log"
    sock = f"/tmp/dc{os.getpid()}{suffix[:8]}.sock"

    policy = {
        "policy": {"tools": [{"tool": "write_file", "rules": [
            {"key": "path", "allowedValues": [],
             "allowedPrefixes": ["/workspace/reports/"]},
            {"key": "content", "allowedValues": [],
             "allowedPrefixes": [""], "payload": True},
        ]}]},
        "credential_tools": ["write_file"],
        "workspace": str(workspace),
    }
    config.write_text(json.dumps(policy, sort_keys=True) + "\n")
    registry.write_text(virtual_target + "\n")
    intent_line = f"write_file path={virtual_target} content={payload_text}"
    intents.write_text(intent_line + "\n")

    # Decode file names and descriptor paths, but never decode I/O buffers.
    trace_args = [
        "strace", "-f", "-yy", "-o", str(trace),
        "-e", "trace=openat,read,write,readv,writev,fsync,fdatasync,"
              "renameat2,renameat,setxattr,fsetxattr,unlinkat,close",
        "-e", "raw=read,write,readv,writev",
        sys.executable, "-c", "from darm_guard.broker import main; main()",
        "--config", str(config), "--registry", str(registry),
        "--socket", sock, "--audit", str(audit), "--intents", str(intents),
    ]
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    tracer = subprocess.Popen(trace_args, cwd=ROOT, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               start_new_session=True)
    broker_pid = None
    response = None
    stop_error = None
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if tracer.poll() is not None:
                err = tracer.stderr.read().decode(errors="replace")[-2000:]
                raise RuntimeError(f"tracer/broker exited during startup: {err}")
            broker_pid = traced_child_pid(tracer.pid)
            if audit.exists() and '"start"' in audit.read_text(errors="replace"):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("broker startup timed out")

        if target.exists():
            raise RuntimeError("target was not absent before request")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(sock)
            request = {"tool": "write_file", "args": [
                ["path", virtual_target], ["content", payload_text]]}
            client.sendall((json.dumps(request) + "\n").encode())
            chunks = bytearray()
            while b"\n" not in chunks:
                part = client.recv(65536)
                if not part:
                    raise RuntimeError("broker closed socket without a response")
                chunks.extend(part)
            response = json.loads(bytes(chunks).split(b"\n", 1)[0])
    finally:
        if broker_pid is None:
            broker_pid = traced_child_pid(tracer.pid)
        if broker_pid is not None:
            try:
                os.kill(broker_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            tracer.wait(timeout=12)
        except subprocess.TimeoutExpired:
            stop_error = "tracer did not exit after broker SIGTERM"
            try:
                os.killpg(tracer.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            tracer.wait(timeout=5)
        if os.path.exists(sock):
            os.unlink(sock)

    checks = {}
    records = read_json_lines(audit)
    rid = (response or {}).get("request_id")
    pair = [e for e in records if e.get("request_id") == rid]
    prepared = [e for e in pair if e.get("event") == "prepared"]
    outcomes = [e for e in pair if e.get("event") == "outcome"]
    disk = target.read_bytes() if target.is_file() else None
    expected_digest = sha(payload)
    raw_att = os.getxattr(target, B.XATTR) if target.is_file() else None
    auditor = B.Keys(B.KeyRing.load(None, str(audit) + ".pub.json"))
    att = B._check_attestation(auditor, raw_att) if raw_att else None
    cfg = B.BrokerConfig.load(str(config), str(registry))
    world = B.verify_world(cfg, str(audit), auditor)

    trace_lines = trace.read_text(errors="replace").splitlines()
    io_lines = [line for line in trace_lines
                if re.search(r"\b(read|write|readv|writev)\(", line)]
    buffers_redacted = bool(io_lines) and all('"' not in line for line in io_lines)
    tmp_mark = f".{leaf}.darm-tmp-"
    tmp_open = next((i for i, line in enumerate(trace_lines)
                     if "openat(" in line and tmp_mark in line
                     and "O_CREAT" in line and "O_EXCL" in line
                     and " = " in line and " = -1 " not in line), None)
    tmp_fd = None
    if tmp_open is not None:
        fd_match = re.search(r"=\s*(\d+)<[^>]*" + re.escape(tmp_mark),
                             trace_lines[tmp_open])
        if fd_match:
            tmp_fd = int(fd_match.group(1))
    tmp_write = next((i for i, line in enumerate(trace_lines)
                      if tmp_fd is not None
                      and f"write(0x{tmp_fd:x}," in line
                      and f"= 0x{len(payload):x}" in line), None)
    tmp_xattr = next((i for i, line in enumerate(trace_lines)
                      if "fsetxattr(" in line and tmp_mark in line
                      and "user.darm" in line and " = 0" in line), None)
    tmp_fsync = next((i for i, line in enumerate(trace_lines)
                      if "fsync(" in line and tmp_mark in line and " = 0" in line), None)
    rename = next((i for i, line in enumerate(trace_lines)
                   if "renameat2(" in line and tmp_mark in line and leaf in line
                   and "RENAME_NOREPLACE" in line and " = 0" in line), None)
    dir_fsync = next((i for i, line in enumerate(trace_lines)
                      if "fsync(" in line and "reports" in line and " = 0" in line
                      and rename is not None and i > rename), None)

    require(response and response.get("effect") == "succeeded"
            and response.get("evidence") == "recorded", "request_succeeded", checks)
    require(rid and len(prepared) == 1 and len(outcomes) == 1
            and pair.index(prepared[0]) < pair.index(outcomes[0]),
            "prepared_then_outcome_same_request", checks)
    require(prepared and prepared[0].get("target") == virtual_target
            and (prepared[0].get("before_state") or [None])[0] == "absent",
            "prepared_record_names_absent_target", checks)
    require(disk == payload, "final_bytes_match_unique_payload", checks)
    require(att and att.get("rid") == rid and att.get("target") == virtual_target
            and att.get("digest") == expected_digest,
            "signature_binds_request_target_digest", checks)
    require(not world.get("findings"), "verify_world_clean", checks)
    require(buffers_redacted and payload_text not in "\n".join(trace_lines),
            "trace_io_buffers_redacted", checks)
    require(tmp_open is not None and tmp_write is not None and tmp_open < tmp_write,
            "trace_temp_create_then_write", checks)
    require(tmp_xattr is not None and tmp_write is not None and tmp_write < tmp_xattr,
            "trace_attestation_after_write", checks)
    require(tmp_fsync is not None and tmp_xattr is not None and tmp_xattr < tmp_fsync,
            "trace_file_sync_after_attestation", checks)
    require(rename is not None and tmp_fsync is not None and tmp_fsync < rename,
            "trace_noreplace_rename_after_file_sync", checks)
    require(dir_fsync is not None, "trace_parent_directory_sync", checks)
    require(stop_error is None and tracer.returncode == 0, "tracer_stopped_cleanly", checks)

    verdict = "CE01_BOUNDED_CAUSAL_EFFECT_SUPPORTED" if all(checks.values()) else "NOT_QUALIFIED"
    evidence = {
        "schema": "DARM_CE01_ONE_WRITE_v0.1",
        "scope": "single-request host fixture; observer is launched strace; host trusted",
        "verdict": verdict,
        "request_id": rid,
        "target": virtual_target,
        "payload_sha256": expected_digest,
        "response": response,
        "prepared_records": prepared,
        "outcome_records": outcomes,
        "attestation": att,
        "world_findings": world.get("findings"),
        "trace_checks": checks,
        "trace_read_write_buffers_redacted": buffers_redacted,
        "limitations": [
            "does not prove against compromised host or root",
            "does not establish deployment-wide agent confinement",
            "one controlled operation, no claim of complete host event coverage",
        ],
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out / "report.md").write_text(
        "# CE-01 one-write causal-effect fixture\n\n"
        f"**Verdict:** {verdict}\n\n"
        + "\n".join(f"- {k}: {'PASS' if v else 'FAIL'}" for k, v in checks.items())
        + "\n\nBounded single-request host fixture. No production custody or warrant claim.\n"
    )
    # Retain the audit and public verifier key, never the private signing key.
    shutil.copyfile(audit, out / "audit.jsonl")
    shutil.copyfile(str(audit) + ".pub.json", out / "audit.jsonl.pub.json")
    shutil.rmtree(private_dir, ignore_errors=True)
    files = [p for p in out.rglob("*") if p.is_file() and p.name != "manifest.json"]
    manifest = {str(p.relative_to(out)): sha(p.read_bytes()) for p in sorted(files)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("CE01_CHECKS=", json.dumps(checks, sort_keys=True))
    print("CE01_VERDICT=", verdict)
    print("CE01_OUTPUT=", out)
    return 0 if verdict != "NOT_QUALIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
