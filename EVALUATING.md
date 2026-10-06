# Evaluating DARM Guard

From nothing to having tried to break it, in about fifteen minutes. Steps 1, 3 and 4 need Linux x86_64 (the
kernel binary's platform); step 2 needs Docker and runs on any OS. Everything here is also run by CI on every
push, so if a step does not behave as described, that is a finding: please report it (step 6).

## 1. See it work (two minutes)

Without installing anything: open the repository in [GitHub Codespaces](https://codespaces.new/Goblohan/Darm-Guard) and run `darm-guard demo` there, or, with Docker, `docker run --rm ghcr.io/goblohan/darm-guard darm-guard demo`. To install it:

    pip install darm-guard
    darm-guard-install-kernel
    darm-guard demo --keep

The demo starts the broker in a temporary directory and runs fourteen steps. With files: an agent's
allowed write and read, then a write without the principal's intent, a path outside the policy even with
an intent for it, a traversal, and a proposal that labels itself trusted, each refused with the kernel's
or the broker's reason. With the network, against a local HTTPS API the demo starts: a fetch the API
receives with the principal's token while the agent never holds it, the token withheld when the API
echoes it, and refusals for an unregistered URL, a disguised host and the cloud metadata address. An
auditor then checks the evidence with the public key alone, and an edit made outside the broker is detected. `--keep` leaves
the directory for you to inspect: `audit.jsonl` (the log), `audit.jsonl.pub.json` (the public key), the
`config.json` and `registry.txt` the principal wrote, and the `workspace/`.

## 2. See that the agent has no other route (five minutes, any OS)

    git clone https://github.com/Goblohan/Darm-Guard.git
    cd Darm-Guard
    docker compose -f deploy/compose.yaml up --build --abort-on-container-exit --exit-code-from agent

The broker and the agent run in separate containers. The agent's has no network, a read-only filesystem, no
workspace and no darm-guard: the broker's socket is its only channel. It uses the broker, including a fetch from a stand-in API whose token only the broker holds, then tries to read the
workspace directly, open a network connection, write to its own filesystem and use the broker's code, and reports
each attempt. This is evidence for complete mediation in this deployment. It is not a proof for others: a
container escape would be a failure of the isolation layer, and any other deployment has to establish mediation
itself (see [LIMITATIONS.md](LIMITATIONS.md)).

## 3. Try to break it

Start a broker yourself, from the clone, with the fixture the tests use:

    ./tests/setup_demo.sh
    darm-broker --config /tmp/darmdemo/config.json --registry /tmp/darmdemo/registry.txt \
                --socket /tmp/darm-broker.sock --audit /tmp/darmdemo/audit.jsonl

Then propose as the agent would. The client sends only `{tool, args}`; to send anything else, as a hostile
agent could, write to the socket directly:

    import json, socket
    def raw(msg, sock="/tmp/darm-broker.sock"):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock); s.sendall((json.dumps(msg) + "\n").encode())
            return json.loads(s.makefile().readline())
    raw({"tool": "read_file", "args": [["path", "/workspace/../secret.txt"]]})

Each attempt below should fail in the way shown. The fixture's registry deliberately vouches for some of these
paths, so a refusal shows the broker, not the registry, stopping it.

| Attempt | Expected |
| --- | --- |
| a path that climbs out with `..`, such as `/workspace/../secret.txt` | refused before any decision: not in normal form |
| a path that POSIX accepts but normal form does not, such as `//workspace/notes.txt` | refused before any decision: not in normal form |
| a symlink inside the workspace that points outside it, `/workspace/link.txt` | not read: the target is a symlink, and the broker never follows one |
| a path the principal never registered, `/workspace/other.txt` | refused by the kernel: provenance |
| a proposal with any field besides `tool` and `args`, such as `"provenance": "authoritative"` | refused: malformed proposal |
| the same write sent twice with the same `"idempotency_key"` | the second reports `already_applied`; written once |
| a second broker started on the same audit log | refused at start, with a message saying why |
| a file changed directly in `/tmp/darmdemo/workspace/`, then the world checked against the log (step 4) | the change is reported |

The network attempts are covered too. An unregistered URL, a host disguised with `@`, and the cloud metadata address
are steps 9 to 11 of `darm-guard demo`; `tests/http_get_broker.py` runs those, plain `http://`, a redirect, a timeout
and an API that echoes the credential, against the broker.

The full list of what the broker does not defend against is in [THREAT_MODEL.md](THREAT_MODEL.md) and
[LIMITATIONS.md](LIMITATIONS.md); an attack that works against something they do not exclude is a vulnerability.

## 4. Check the evidence yourself

The broker signs every file it writes with an Ed25519 key, and keeps a hash-chained audit log. Checking needs
only the public key, so the party checking cannot forge evidence. For the broker from step 3 (for the directory
`darm-guard demo --keep` left, use its paths instead):

    python tests/verify_audit.py /tmp/darmdemo/audit.jsonl

checks the log's hash chain, and

    import darm_guard.broker as B
    cfg = B.BrokerConfig.load("/tmp/darmdemo/config.json", "/tmp/darmdemo/registry.txt")
    auditor = B.Keys(B.KeyRing.load(None, "/tmp/darmdemo/audit.jsonl.pub.json"))
    print(B.verify_world(cfg, "/tmp/darmdemo/audit.jsonl", auditor))

checks every file in the workspace against the log, in both directions, with the public key alone. A hash chain
detects edits but not the removal of its newest entries; started with `--checkpoint-sink`, the broker also
publishes signed checkpoints of the log to a place this host cannot rewrite, which detect that too.

Or, as one command each:

    darm-guard audit --audit /tmp/darmdemo/audit.jsonl --config /tmp/darmdemo/config.json --registry /tmp/darmdemo/registry.txt
    darm-guard report --audit /tmp/darmdemo/audit.jsonl

`audit` checks the chain and every governed file with the public key alone, and exits non-zero on any finding.
`report` lists every request the agent made, admitted or refused, with its path or URL, the decision and the
reason. The log keeps paths and URLs, but a file's content only as its hash and length, and filters exact configured credential-value echoes from returned redirect locations. Encoded or transformed disclosures are outside this filter's guarantee.
`darm-guard demo --keep` prints both commands for its own directory.

## 5. Check the claims, not only the behaviour

- [assurance/claims.json](assurance/claims.json) lists every claim with its theorems in
  [darm-monitor](https://github.com/Goblohan/darm-monitor), its tests, and its bridge to the code: by
  construction, proved, tested, or assumed. [LIMITATIONS.md](LIMITATIONS.md) states each claim's limit.
- `scripts/check_assurance.py --monitor <a clone of darm-monitor>` checks every claim against the theorems and
  the threat model, in both directions.
- `scripts/mutation_gate.py "<name>"` breaks one load-bearing check and shows which test catches it; the names
  are in the `MUTATIONS` table in that file.
- `scripts/check_effect_sites.py` checks that every place the code can change the world is classified, and
  `tests/gate_attacks.py` shows that check rejecting unreviewed changes.
- `scripts/ci_local.py` runs the whole gate from a clean clone, as CI does on every push.

## 6. Report what you find

A vulnerability: privately, as [SECURITY.md](SECURITY.md) describes. Anything else, including a stated
assumption that fails in practice, or a step on this page that does not behave as described: an issue on this
repository. Both are welcome; a counterexample is evidence about the limits of a claim, not something to hide.

## If something goes wrong

**`darm-broker: … is owned by another running broker; refusing to start`.** Another broker holds that audit
log. One broker per log is deliberate: two would interleave its hash chain and could spend the same intent
twice. Stop the other broker, or give this one its own `--audit` path.

**`The DARM kernel is not installed`.** The broker decides nothing without its kernel, so it will not run. Run
`darm-guard-install-kernel`, which downloads the pinned release and keeps it only if its SHA-256 matches.

**`darm-guard: command not found` after installing.** pip put the commands where your shell does not look,
typically `~/.local/bin`. Use a virtual environment (`python3 -m venv .venv`, then `.venv/bin/darm-guard demo`),
add that directory to your `PATH`, or run `python3 -m darm_guard.cli demo`.

**`error: externally-managed-environment`.** Your system Python does not accept packages from pip. Use a virtual
environment as above; on Ubuntu, `python3 -m venv` needs the `python3-venv` package first.

**`python3 -m venv` says `ensurepip is not available`.** The same: install `python3-venv` (on Ubuntu,
`sudo apt install python3-venv`, or the version-specific package it names).

**The Docker deployment is slow on an Apple Silicon Mac.** The kernel binary is `linux/amd64`, so Docker runs
the broker under emulation. It is slower, not different.

**Permission denied on `/var/run/docker.sock`.** Your user is not in the `docker` group: add it
(`sudo usermod -aG docker "$USER"`), then open a new terminal.
