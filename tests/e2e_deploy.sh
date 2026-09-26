#!/usr/bin/env bash
# End-to-end deployment check: a fresh venv, darm-guard from PyPI, the
# installed darm-broker command, a real broker, an agent, an auditor.
# Usage: tests/e2e_deploy.sh [version]   (default: the version in pyproject.toml)
set -euo pipefail
cd "$(dirname "$0")/.."
V="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)}"
REPO=$(pwd)
rm -rf /tmp/e2e_venv
python3 -m venv /tmp/e2e_venv > /dev/null 2>&1 || { rm -rf /tmp/e2e_venv; python3 -m virtualenv --quiet /tmp/e2e_venv; }
/tmp/e2e_venv/bin/pip install --quiet --no-cache-dir "darm-guard==$V"
./tests/setup_demo.sh > /dev/null
cd /tmp
PATH="/tmp/e2e_venv/bin:$PATH" /tmp/e2e_venv/bin/python "$REPO/tests/e2e_deploy.py"
