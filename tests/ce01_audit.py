#!/usr/bin/env python3
"""Independent CE-01 post-run auditor. Does not import the CE-01 runner."""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pid_of(line):
    m = re.match(r"^(\d+)\s+", line)
    return int(m.group(1)) if m else None


def audit(root):
    root = root.expanduser().resolve()
    findings = []
    checks = {}

    def check(name, ok):
        checks[name] = bool(ok)
        if not ok:
            findings.append(name)

    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    safe_manifest = bool(manifest) and all(
        isinstance(name, str) and isinstance(digest, str)
        and len(digest) == 64 and re.fullmatch(r"[0-9a-f]{64}", digest)
        and not PurePosixPath(name).is_absolute()
        and ".." not in PurePosixPath(name).parts
        for name, digest in manifest.items()
    )
    check("manifest_paths_and_hashes_well_formed", safe_manifest)
    hash_results = {}
    if safe_manifest:
        for name, expected in manifest.items():
            p = root.joinpath(*PurePosixPath(name).parts)
            hash_results[name] = p.is_file() and sha(p.read_bytes()) == expected
    check("manifest_hashes_match", bool(hash_results) and all(hash_results.values()))
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob("*")
                    if p.is_file() and p.name != "manifest.json"}
    check("manifest_covers_all_retained_files", actual_files == set(manifest))
    check("no_private_key_archived", not any(
        p.is_file() and (p.name.endswith(".key") or "private" in p.name.lower())
        for p in root.rglob("*")
    ))

    evidence = json.loads((root / "evidence.json").read_text())
    check("evidence_schema", evidence.get("schema") == "DARM_CE01_ONE_WRITE_v0.1")
    target_name = evidence.get("target")
    target_match = re.fullmatch(r"/workspace/reports/(ce01-[0-9a-f]{32}\.txt)",
                                target_name or "")
    check("target_is_unique_fixture_name", target_match is not None)
    if not target_match:
        target = None
        payload = None
        digest = None
    else:
        target = root / "workspace" / "reports" / target_match.group(1)
        payload = target.read_bytes() if target.is_file() else None
        digest = sha(payload) if payload is not None else None
    check("target_file_exists", target is not None and target.is_file())
    check("payload_has_fixture_nonce_shape",
          payload is not None and re.fullmatch(rb"CE01[0-9a-f]{32}", payload) is not None)
    check("payload_hash_matches_evidence",
          digest is not None and digest == evidence.get("payload_sha256"))

    response = evidence.get("response") or {}
    rid = evidence.get("request_id")
    check("response_names_same_request", bool(rid) and response.get("request_id") == rid)
    check("response_succeeded", response.get("effect") == "succeeded"
          and response.get("evidence") == "recorded")

    audit_path = root / "audit.jsonl"
    records = load_json_lines(audit_path)
    pair = [e for e in records if e.get("request_id") == rid]
    prepared = [e for e in pair if e.get("event") == "prepared"]
    outcome = [e for e in pair if e.get("event") == "outcome"]
    check("one_prepared_one_outcome", len(prepared) == 1 and len(outcome) == 1)
    if len(prepared) == 1 and len(outcome) == 1:
        check("prepared_precedes_outcome", pair.index(prepared[0]) < pair.index(outcome[0]))
        check("prepared_target_and_absent_before_state",
              prepared[0].get("target") == target_name
              and (prepared[0].get("before_state") or [None])[0] == "absent")
        check("outcome_succeeded", outcome[0].get("effect") == "succeeded")
        intended = prepared[0].get("intended_state") or []
        check("intended_state_digest_matches_payload",
              len(intended) > 1 and intended[0] == "present" and intended[1] == digest)
        check("saved_request_records_match_audit",
              evidence.get("prepared_records") == prepared
              and evidence.get("outcome_records") == outcome)

    config = json.loads((root / "config.json").read_text())
    registry = (root / "registry.txt").read_text().splitlines()
    check("registry_names_only_fixture_target", registry == [target_name])
    workspace = config.get("workspace")
    check("config_workspace_matches_saved_fixture",
          workspace is not None and Path(workspace).resolve() == (root / "workspace").resolve())

    # Use Guard's public key verifier and world checker, not the runner's verdict.
    import darm_guard.broker as B
    pub = root / "audit.jsonl.pub.json"
    ring = B.KeyRing.load(None, str(pub))
    auditor = B.Keys(ring)
    raw_att = os_getxattr(target, B.XATTR) if target is not None and target.is_file() else None
    att = B._check_attestation(auditor, raw_att) if raw_att else None
    check("xattr_attestation_binds_request_target_digest",
          bool(att) and att.get("rid") == rid and att.get("target") == target_name
          and att.get("digest") == digest)
    check("saved_attestation_matches_recomputed",
          evidence.get("attestation") == att)
    cfg = B.BrokerConfig.load(str(root / "config.json"), str(root / "registry.txt"))
    world = B.verify_world(cfg, str(audit_path), auditor)
    check("verify_world_has_no_findings", not world.get("findings"))
    check("saved_world_findings_match_recalculation",
          evidence.get("world_findings") == world.get("findings"))

    trace_lines = (root / "trace.log").read_text(errors="replace").splitlines()
    target_leaf = target_match.group(1) if target_match else ""
    tmp_mark = "." + target_leaf + ".darm-tmp-"
    opened = next(((i, line) for i, line in enumerate(trace_lines)
                   if "openat(" in line and tmp_mark in line
                   and "O_CREAT" in line and "O_EXCL" in line
                   and " = " in line and " = -1 " not in line), None)
    check("trace_has_successful_private_temp_open", opened is not None)
    broker_pid = pid_of(opened[1]) if opened else None
    fd_match = (re.search(r"=\s*(\d+)<[^>]*" + re.escape(tmp_mark), opened[1])
                if opened else None)
    temp_fd = int(fd_match.group(1)) if fd_match else None
    check("trace_temp_descriptor_recovered", temp_fd is not None)

    expected_len = len(payload) if payload is not None else -1
    written = next(((i, line) for i, line in enumerate(trace_lines)
                    if broker_pid is not None and pid_of(line) == broker_pid
                    and temp_fd is not None and f"write(0x{temp_fd:x}," in line
                    and f"= 0x{expected_len:x}" in line), None)
    check("trace_same_broker_wrote_exact_payload_length",
          opened is not None and written is not None and written[0] > opened[0])

    xattr = next(((i, line) for i, line in enumerate(trace_lines)
                  if broker_pid is not None and pid_of(line) == broker_pid
                  and "fsetxattr(" in line and tmp_mark in line
                  and "user.darm" in line and " = 0" in line), None)
    fsync_file = next(((i, line) for i, line in enumerate(trace_lines)
                       if broker_pid is not None and pid_of(line) == broker_pid
                       and temp_fd is not None and f"fsync({temp_fd}<" in line
                       and tmp_mark in line and " = 0" in line), None)
    rename = next(((i, line) for i, line in enumerate(trace_lines)
                   if broker_pid is not None and pid_of(line) == broker_pid
                   and "renameat2(" in line and tmp_mark in line and target_leaf in line
                   and "RENAME_NOREPLACE" in line and " = 0" in line), None)
    parent_sync = next(((i, line) for i, line in enumerate(trace_lines)
                        if broker_pid is not None and pid_of(line) == broker_pid
                        and "fsync(" in line and "workspace/reports" in line
                        and " = 0" in line and rename is not None
                        and i > rename[0]), None)
    broker_exit_zero = any(
        broker_pid is not None and pid_of(line) == broker_pid
        and "+++ exited with 0 +++" in line for line in trace_lines
    )
    check("trace_attests_after_write", written is not None and xattr is not None
          and written[0] < xattr[0])
    check("trace_syncs_attested_temp", xattr is not None and fsync_file is not None
          and xattr[0] < fsync_file[0])
    check("trace_noreplace_rename_after_temp_sync",
          fsync_file is not None and rename is not None and fsync_file[0] < rename[0])
    check("trace_syncs_parent_after_rename", parent_sync is not None)
    check("trace_broker_exited_zero", broker_exit_zero)
    io_lines = [line for line in trace_lines
                if re.search(r"\b(read|write|readv|writev)\(", line)]
    check("trace_io_buffers_not_decoded",
          bool(io_lines) and all('"' not in line for line in io_lines)
          and payload is not None and payload.decode("ascii") not in "\n".join(trace_lines))

    recorded_checks = evidence.get("trace_checks", {})
    recomputed_runner_checks = {
        "request_succeeded": checks.get("response_succeeded", False),
        "prepared_then_outcome_same_request": checks.get("one_prepared_one_outcome", False)
            and checks.get("prepared_precedes_outcome", False)
            and checks.get("response_names_same_request", False),
        "prepared_record_names_absent_target": checks.get("prepared_target_and_absent_before_state", False),
        "final_bytes_match_unique_payload": checks.get("payload_hash_matches_evidence", False)
            and checks.get("payload_has_fixture_nonce_shape", False),
        "signature_binds_request_target_digest": checks.get("xattr_attestation_binds_request_target_digest", False),
        "verify_world_clean": checks.get("verify_world_has_no_findings", False),
        "trace_io_buffers_redacted": checks.get("trace_io_buffers_not_decoded", False),
        "trace_temp_create_then_write": checks.get("trace_has_successful_private_temp_open", False)
            and checks.get("trace_same_broker_wrote_exact_payload_length", False),
        "trace_attestation_after_write": checks.get("trace_attests_after_write", False),
        "trace_file_sync_after_attestation": checks.get("trace_syncs_attested_temp", False),
        "trace_noreplace_rename_after_file_sync": checks.get("trace_noreplace_rename_after_temp_sync", False),
        "trace_parent_directory_sync": checks.get("trace_syncs_parent_after_rename", False),
        "tracer_stopped_cleanly": checks.get("trace_broker_exited_zero", False),
    }
    check("runner_check_set_exact",
          set(recorded_checks) == set(recomputed_runner_checks))
    for name, result in recomputed_runner_checks.items():
        check("runner_check_recomputed:" + name,
              recorded_checks.get(name) is result and result)
    recomputed_pass = all(checks.values())
    verdict = ("CE01_BOUNDED_CAUSAL_EFFECT_SUPPORTED" if recomputed_pass
               else "NOT_QUALIFIED")
    check("recorded_verdict_matches_recomputation",
          evidence.get("verdict") == verdict)
    report = (root / "report.md").read_text()
    check("report_verdict_matches_recomputation", f"**Verdict:** {verdict}" in report)
    print("CE01_INDEPENDENT_AUDIT_CHECKS=", json.dumps(checks, sort_keys=True))
    for finding in findings:
        print("FINDING:", finding)
    print("CE01_INDEPENDENT_AUDIT=" + ("PASS" if not findings else "FAIL"))
    print("Scope: saved local fixture artifacts, Guard verifier, and retained strace only")
    return findings


def os_getxattr(path, name):
    try:
        return os.getxattr(path, name)
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, type=Path)
    args = ap.parse_args()
    try:
        return 0 if not audit(args.run) else 1
    except Exception as exc:
        print("CE01_INDEPENDENT_AUDIT=FAIL")
        print("FINDING: audit_exception:" + repr(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
