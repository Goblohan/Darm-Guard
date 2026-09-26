#!/usr/bin/env bash
# Build, upload and verify a release from PyPI, stopping at the first failure,
# so no step (the upload especially) can be skipped. Usage: scripts/release.sh X.Y.Z
# Run after the version bump, the commit and the tag.
set -euo pipefail
V="${1:?usage: scripts/release.sh X.Y.Z}"
cd "$(dirname "$0")/.."
grep -q "version = \"$V\"" pyproject.toml || { echo "STOP: pyproject.toml is not at $V"; exit 1; }
grep -q "__version__ = \"$V\"" darm_guard/__init__.py || { echo "STOP: darm_guard/__init__.py is not at $V"; exit 1; }
{ git diff --quiet && git diff --cached --quiet; } || { echo "STOP: uncommitted changes; commit first"; exit 1; }
git rev-parse "v$V" > /dev/null 2>&1 || { echo "STOP: tag v$V does not exist"; exit 1; }
rm -rf dist build darm_guard.egg-info
python3 -m build 2>&1 | tail -1
python3 -m twine upload dist/*
for i in $(seq 1 10); do
  rm -rf /tmp/e2e
  if python3 -m pip install --no-cache-dir --quiet --target /tmp/e2e "darm-guard==$V" 2>/dev/null; then
    echo "installed $V from PyPI"; break
  fi
  [ "$i" = 10 ] && { echo "STOP: $V not in the index after 10 tries"; exit 1; }
  echo "not in the index yet, retrying in 30 s ($i/10)"; sleep 30
done
./tests/setup_demo.sh > /dev/null
PYTHONPATH=/tmp/e2e python3 tests/e2e_published.py "$V"
tests/e2e_deploy.sh "$V"
