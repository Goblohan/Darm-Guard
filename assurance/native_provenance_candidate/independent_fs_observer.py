#!/usr/bin/env python3
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import time

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ISDIR = 0x40000000
WATCH_MASK = (
    IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM |
    IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF
)
LABELS = {
    IN_MODIFY: "MODIFY", IN_ATTRIB: "ATTRIB",
    IN_CLOSE_WRITE: "CLOSE_WRITE", IN_MOVED_FROM: "MOVED_FROM",
    IN_MOVED_TO: "MOVED_TO", IN_CREATE: "CREATE",
    IN_DELETE: "DELETE", IN_DELETE_SELF: "DELETE_SELF",
    IN_MOVE_SELF: "MOVE_SELF", IN_ISDIR: "ISDIR",
}

libc = ctypes.CDLL(None, use_errno=True)
libc.inotify_init1.argtypes = [ctypes.c_int]
libc.inotify_init1.restype = ctypes.c_int
libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
libc.inotify_add_watch.restype = ctypes.c_int
stopping = False


def stop(_signum, _frame):
    global stopping
    stopping = True


def snapshot(path, root):
    row = {"time_ns": time.time_ns(), "path": str(path.relative_to(root))}
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seconds", type=float, default=15)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1 failed")

    watched = {}

    def add_watch(directory):
        if directory.is_dir():
            wd = libc.inotify_add_watch(fd, os.fsencode(directory), WATCH_MASK)
            if wd >= 0:
                watched[wd] = directory

    for directory, _subdirs, _files in os.walk(root):
        add_watch(Path(directory))

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    with output.open("w", encoding="utf-8", buffering=1) as stream:
        stream.write(json.dumps({
            "event": "observer_started",
            "time_ns": time.time_ns(),
            "root": str(root),
            "watch_count": len(watched),
        }) + "\n")

        deadline = time.monotonic() + args.seconds
        while not stopping and time.monotonic() < deadline:
            ready, _, _ = select.select(
                [fd], [], [], min(0.5, max(0, deadline - time.monotonic()))
            )
            if not ready:
                continue
            try:
                data = os.read(fd, 1024 * 1024)
            except BlockingIOError:
                continue

            offset = 0
            while offset + 16 <= len(data):
                wd, mask, cookie, name_len = struct.unpack_from(
                    "iIII", data, offset
                )
                offset += 16
                raw = data[offset:offset + name_len]
                offset += name_len
                name = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
                directory = watched.get(wd, root)
                path = directory / name if name else directory
                stream.write(json.dumps({
                    "event": "filesystem",
                    "mask": mask,
                    "mask_names": [
                        label for bit, label in LABELS.items() if mask & bit
                    ],
                    "cookie": cookie,
                    **snapshot(path, root),
                }) + "\n")
                if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                    add_watch(path)

        stream.write(json.dumps({
            "event": "observer_stopped",
            "time_ns": time.time_ns(),
        }) + "\n")

    os.close(fd)


if __name__ == "__main__":
    main()
