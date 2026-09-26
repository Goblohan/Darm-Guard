"""External audit checkpoints.

The broker signs the audit log's chain head (its genesis, entry count and
head hash) with its Ed25519 key and publishes it to a sink. A verifier holding
only public keys checks that the log it is shown extends every published
checkpoint: truncation below a checkpoint, or rewriting any entry before it
(even with the whole hash chain recomputed), is detected. Entries appended
after the most recent checkpoint can still be removed undetected, so the
checkpoint interval is a security parameter.

Keeping the sink out of the broker host's reach is a deployment property that
this code cannot provide: a sink the broker's host can rewrite protects nothing
against an attacker who controls that host."""
import json, os


def _entries(audit_path: str) -> list:
    return [json.loads(line) for line in open(audit_path) if line.strip()]


def make_checkpoint(audit_path: str, ring) -> dict:
    entries = _entries(audit_path)
    if not entries:
        raise ValueError("empty log: nothing to checkpoint")
    return ring.sign_checkpoint(entries[0]["entry_hash"], len(entries), entries[-1]["entry_hash"])


def publish(cp: dict, sink_dir: str) -> str:
    """Append the checkpoint to <sink>/<genesis prefix>.checkpoints.jsonl."""
    os.makedirs(sink_dir, exist_ok=True)
    path = os.path.join(sink_dir, cp["genesis"][:16] + ".checkpoints.jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(cp, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return path


def load_published(path: str) -> list:
    return [json.loads(line) for line in open(path) if line.strip()] if os.path.exists(path) else []


def check_log(audit_path: str, checkpoints: list, ring) -> dict:
    """Check a log against published checkpoints, with public keys only."""
    entries = _entries(audit_path)
    genesis = entries[0]["entry_hash"] if entries else None
    findings, covered = [], 0
    for cp in checkpoints:
        n = cp.get("count")
        ok, why = ring.verify_checkpoint(cp)
        if not ok:
            findings.append({"checkpoint": n, "finding": f"checkpoint signature {why}"})
            continue
        if cp["genesis"] != genesis:
            findings.append({"checkpoint": n, "finding":
                             "checkpoint is for a different log (or the log's first entry was rewritten)"})
            continue
        if len(entries) < n:
            findings.append({"checkpoint": n, "finding": "log truncated below a published checkpoint"})
        elif entries[n - 1]["entry_hash"] != cp["head"]:
            findings.append({"checkpoint": n, "finding": "log rewritten before a published checkpoint"})
        else:
            covered = max(covered, n)
    return {"ok": not findings, "findings": findings, "covered": covered, "entries": len(entries)}


class Checkpointer:
    """Publishes a signed checkpoint every `every` audit records, and on demand
    (startup, shutdown). The newest records since the last published checkpoint,
    fewer than `every` of them, are not yet protected. A failure to publish is
    returned to the caller, which records it; it never blocks the broker. After a
    failure, the next attempt waits another interval."""

    def __init__(self, ring, sink_dir: str, every: int):
        if every < 1:
            raise ValueError("checkpoint interval must be at least 1")
        self.ring, self.sink_dir, self.every = ring, sink_dir, every
        self.last_count = self.last_attempt = self.failures = self.published = 0

    def path_for(self, genesis: str) -> str:
        return os.path.join(self.sink_dir, genesis[:16] + ".checkpoints.jsonl")

    def maybe(self, genesis: str, count: int, head: str, force: bool = False):
        """None if nothing was due or it was published; otherwise the error."""
        if force:
            if count == self.last_count:
                return None
        elif count - max(self.last_count, self.last_attempt) < self.every:
            return None
        self.last_attempt = count
        try:
            publish(self.ring.sign_checkpoint(genesis, count, head), self.sink_dir)
        except OSError as e:
            self.failures += 1
            return f"{type(e).__name__}: {e}"
        self.last_count, self.published = count, self.published + 1
        return None
