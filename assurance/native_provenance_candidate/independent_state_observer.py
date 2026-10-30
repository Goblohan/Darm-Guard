#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import stat
import time

def snapshot(path, root):
    row = {
        "time_ns": time.time_ns(),
        "path": str(path.relative_to(root)),
    }
    try:
        info = path.stat()
        row.update({
            "exists": True,
            "inode": info.st_ino,
            "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode),
            "bytes": info.st_size,
        })
        if stat.S_ISREG(info.st_mode) and info.st_size <= 16 * 1024 * 1024:
            row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        row["exists"] = False
    except OSError as exc:
        row["snapshot_error"] = str(exc)
    return row

def stable(row):
    return {key: value for key, value in row.items() if key != "time_ns"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seconds", type=float, default=15)
    parser.add_argument("--interval", type=float, default=0.02)
    parser.add_argument("--target", action="append", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    targets = [root / value for value in args.target]
    previous = {}

    with Path(args.output).open("w", encoding="utf-8", buffering=1) as stream:
        stream.write(json.dumps({
            "event": "poll_observer_started",
            "time_ns": time.time_ns(),
            "root": str(root),
            "targets": args.target,
        }) + "\n")

        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            for relative, path in zip(args.target, targets):
                current = snapshot(path, root)
                if stable(previous.get(relative, {})) != stable(current):
                    stream.write(json.dumps({
                        "event": "state_change",
                        **current,
                    }) + "\n")
                    previous[relative] = current
            time.sleep(args.interval)

        stream.write(json.dumps({
            "event": "poll_observer_stopped",
            "time_ns": time.time_ns(),
        }) + "\n")

if __name__ == "__main__":
    main()
