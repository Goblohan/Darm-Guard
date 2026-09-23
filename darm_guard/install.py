"""Install the CI-built DARM decision kernel, pinned by SHA-256.

The binary is built by darm-monitor's Kernel Release workflow from a
tagged commit whose proofs CI checked. This module downloads exactly
that artifact and refuses to install or use anything whose SHA-256
differs from the pin below.
"""
from __future__ import annotations

import hashlib
import os
import platform
import sys
import tempfile
import urllib.request
from pathlib import Path

KERNEL_VERSION = "kernel-v0.2.0"
KERNEL_SHA256 = "3f05980f6fe49225557d22ae1def57cdb9946e2d852816d27eaaff0fd51b0ca7"
KERNEL_URL = ("https://github.com/Goblohan/darm-monitor/releases/download/"
              f"{KERNEL_VERSION}/darmkernel-linux-x86_64")


def kernel_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "darm-guard" / KERNEL_VERSION


def kernel_path() -> Path:
    return kernel_dir() / "darmkernel"


def sha256_of(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def supported_platform() -> bool:
    return sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64")


def _download(url: str, dest: str, timeout: float = 30.0) -> None:
    """Download with progress; a stall longer than `timeout` seconds aborts."""
    req = urllib.request.Request(url, headers={"User-Agent": "darm-guard"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r  downloading {done >> 20} / {total >> 20} MB",
                      end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)


def verified_kernel_path() -> str:
    """Installed kernel path if present and its hash matches the pin, else ''."""
    p = kernel_path()
    if p.is_file() and sha256_of(p) == KERNEL_SHA256:
        return str(p)
    return ""


def install_kernel() -> str:
    if not supported_platform():
        raise RuntimeError("prebuilt kernel is linux x86_64 only; "
                           "build darmkernel from darm-monitor instead")
    existing = verified_kernel_path()
    if existing:
        return existing
    d = kernel_dir()
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d)
    os.close(fd)
    try:
        _download(KERNEL_URL, tmp)
        got = sha256_of(tmp)
        if got != KERNEL_SHA256:
            raise RuntimeError(f"kernel hash mismatch: expected {KERNEL_SHA256}, got {got}")
        os.chmod(tmp, 0o755)
        os.replace(tmp, kernel_path())
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return str(kernel_path())


def main() -> None:
    try:
        path = install_kernel()
    except Exception as e:
        print(f"darm-guard: kernel install failed: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"DARM kernel {KERNEL_VERSION} installed and verified: {path}")
    print(f"sha256: {KERNEL_SHA256}")


if __name__ == "__main__":
    main()
