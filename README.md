# DARM Guard

**Runtime authorization for AI agents, decided by a kernel compiled from a machine-checked model.**

An agent proposes tool calls. A broker that holds the tools asks the DARM decision kernel, executes only the invocation the kernel admits, and leaves signed evidence of every effect. The kernel is a Lean 4 model, compiled; its theory is in [darm-monitor](https://github.com/Goblohan/darm-monitor).

*PerceptraAI Lab* · [Evaluating it](EVALUATING.md) · [Limitations](LIMITATIONS.md) · [Threat model](THREAT_MODEL.md) · [Formal backing](FORMAL_BACKING.md) · [Broker design](docs/broker-design.md) · [Changelog](CHANGELOG.md) · [Earlier APIs](docs/legacy-api.md)

```
agent ── {tool, args} ──▶ DARM broker ── proposal + nonce ──▶ darmkernel (the Lean model, compiled)
          (a socket only)    │  ◀── decision + canonical invocation ──┘
                             ├─ executes exactly that invocation, inside the workspace
                             └─ evidence: signed attestations, a hash-chained audit log, external checkpoints
```

## What it is, and what it is not

**It is** an enforcement point between an agent and its tools. The agent holds only a socket and can only propose `{tool, args}`. The broker assigns provenance itself, from a registry the principal writes; asks the kernel; executes the invocation the kernel returns, cross-checked against its own; and records evidence before and after every effect.

**It is not:**

- **a sandbox.** It assumes complete mediation: the agent reaches governed files only through the broker. A deployment has to provide that, for example with a container or kernel-level enforcement. The reference deployment is tested in CI.
- **a content filter.** A file's content must satisfy its policy rule, but is not checked for truth, harm or sensitive data. Information flow is out of scope.
- **proved end to end.** The decision path is the model compiled, with theorems covering the replies the broker accepts. The Python broker's correspondence to the model is tested, and each claim says which (below).
- **general purpose yet.** It governs a filesystem domain (`read_file`, `list_dir`, `write_file`, `delete_file`, `rename_file`) and one network tool, `http_get`: a `GET` to a URL the principal registered, with the principal's credential attached by the broker and never seen by the agent.

## Evidence

<!-- figures:start -->
| | |
| --- | --- |
| Package / kernel | 0.25.0 / kernel-v0.4.0 |
| Claims, each citing its theorems and tests | 31 |
| Threat-model guarantees, each backed by a claim | 29 |
| Bridges from model to code | 1 construction, 1 proved, 29 tested, 0 assumed |
| Effect sites | 53 found, 53 classified (13 closed, 7 continuation, 33 exception, 0 open) |
| Mutations, each caught by a test | 19 |
| Gate steps run on every push | 62 |
<!-- figures:end -->

Every claim in [`assurance/claims.json`](assurance/claims.json) names its theorems in darm-monitor, its tests, and its **bridge** to the code: by construction, proved, tested, or assumed. `scripts/check_assurance.py` checks every claim against the theorems and the threat model in both directions on each build, and `scripts/mutation_gate.py` breaks each load-bearing check to show a test catches it. The table above is generated from the repository by `scripts/readme_figures.py`, and CI fails if it falls out of date.

## Install

    pip install darm-guard
    darm-guard-install-kernel
    darm-guard demo

The second command downloads the kernel binary that darm-monitor's CI built from a tagged commit, and installs it only if its SHA-256 matches the value pinned in this package. Linux x86_64 only; elsewhere, build it with `lake build darmkernel` in darm-monitor and set `DARM_KERNEL_PATH`. A kernel is never downloaded during an authorization decision. The third command runs the broker against an agent, step by step, in a temporary directory: what the agent tries, what happens, and why, ending with an auditor checking the evidence using only the public key.

## Quick start: the broker

From a clone of this repository, `tests/setup_demo.sh` writes a working configuration, registry and workspace under `/tmp/darmdemo`:

    ./tests/setup_demo.sh
    darm-broker --config /tmp/darmdemo/config.json --registry /tmp/darmdemo/registry.txt \
                --socket /tmp/darm-broker.sock --audit /tmp/darmdemo/audit.jsonl

Then, as the agent:

    from darm_guard.broker import BrokerClient
    agent = BrokerClient("/tmp/darm-broker.sock")
    agent.propose("write_file", {"path": "/workspace/reports/q3.md", "content": "hello"})
    agent.propose("read_file", {"path": "/workspace/reports/q3.md"})

Each response reports the kernel's decision separately from the effect (`none`, `succeeded`, `failed` or `unknown`), the evidence status, and its basis: the claims it rests on, each with its theorems and assumptions.

| Option | What it does |
|---|---|
| `--config` | the policy, the credential's tools, the workspace, and optionally a credential lifetime |
| `--registry` | values the principal vouches for, one per line; a line ending in `*` vouches for a prefix |
| `--socket`, `--audit` | where the agent connects; where the hash-chained audit log is written |
| `--intents` | principal-held, single-use authorizations; per tool, or per exact arguments |
| `--revocations` | an append-only file the principal writes to revoke intents, in force for every later decision |
| `--checkpoint-sink`, `--checkpoint-every` | publish a signed checkpoint of the log's head every N records, to a place this host cannot rewrite |

The principal's files (config, registry, intents, revocations) belong where the agent cannot write. File permissions are the deployer's responsibility.

## Try it without installing anything

In a browser: [open this repository in GitHub Codespaces](https://codespaces.new/Goblohan/Darm-Guard), wait
for it to finish setting up, and run `darm-guard demo` in its terminal. With Docker, on any OS:

    docker run --rm ghcr.io/goblohan/darm-guard darm-guard demo

The image is the one the deployment below uses. Each release builds it and runs the demo inside it before
publishing it, and every push to this repository builds it and runs the demo too.

## Try it in Docker, on any OS

The same broker, with the agent in a second container that has no network, a read-only filesystem, no
workspace and no darm-guard: its only channel is the broker's socket. From a clone of this repository:

    docker compose -f deploy/compose.yaml up --build --abort-on-container-exit --exit-code-from agent

The agent uses the broker, for files and for an API whose token only the broker holds, then tries every way around it, and says what happened. This is the evidence for
complete mediation in this deployment, and CI runs it on every push. The broker image is `linux/amd64`; on an
Apple Silicon Mac, Docker runs it under emulation.

## How a request is decided

1. **The proposal is exactly `{tool, args}`.** A proposal with any other field, such as a provenance label, is refused rather than ignored. Paths must be in normal form.
2. **The broker assigns provenance** from the principal's registry, never from the proposal.
3. **The kernel decides**, on the raw proposal: well-formedness, canonicalization, then the policy, the credential, its expiry and provenance. Every request carries a fresh nonce, and a reply that does not carry it is refused.
4. **Intents and premises**, when configured: the action also needs a principal-held intent, reserved at admission and spent only once the effect is durable.
5. **Evidence before effect.** A prepared record is written and synced before anything happens; if it cannot be written, nothing is done.
6. **The broker executes exactly the kernel's invocation**, through paths resolved without following symlinks, with compare-and-swap writes and crash-safe renames, and refuses if its own canonicalization disagrees with the kernel's.
7. **Every written file is attested** with an Ed25519 signature naming the request that wrote it, and the outcome is recorded.

## What is established, and how

| Claim | Evidence | Bridge |
|---|---|---|
| The decision is the model's | the kernel is the Lean model compiled; theorems cover the server's replies from raw proposal to accepted reply (darm-monitor K5 to K7) | construction, proved |
| What executes is what was decided | the kernel returns the canonical invocation (K6); the broker cross-checks it on every request and never modifies it | tested |
| A reply answers only its own request | a fresh nonce per request (K7, `reply_names_its_request`) | proved |
| Content cannot buy authority | K4, `payload_cannot_buy_authority` | proved, tested |
| No action without the principal's intent | E24 to E24d; three-state consumption, revocation, premises | tested |
| No effect without prior evidence | B4, `no_silent_effect_ever` | tested |
| Writes apply only from the recorded state | B6, `cas_applies_iff` | tested |
| A keyed retry performs at most one effect | B7b, `at_most_once_with_failures` | tested |
| A rename never loses or duplicates a file, across a crash | B8, B9; recovery rolls forward only on a signed attestation for that request | tested |
| No governed effect bypasses the kernel's decision | every effect site classified and bound to the code it was reviewed against (E34); the build fails on an unreviewed change | tested |
| An HTTP request goes only to a URL the principal registered, and the agent never holds its credential | URL normal form before the decision; private and metadata addresses refused; the URL recorded before the call; the response is the broker's attestation, the remote state is not (E31) | tested |
| Evidence is checkable with public keys alone | Ed25519 attestations and signed checkpoints | tested, not modelled |

The full list, with every assumption, is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Checking other gates: darm-verify

Check any authorization gate against the DARM kernel. Wrap the gate in an adapter, a function from a DARM request to a Verdict. Verify runs seeded scenarios through both the gate and the kernel and reports every disagreement:

- **false admit**: the gate allows what the kernel rejects, labeled with the kernel's reason (T, O, A, S, or P)
- **false reject**: the gate blocks what the kernel admits

    darm-verify --adapter darmguard-v0.1 --n 1000 --json report.json

**Worked example: DARM Guard's own v0.1**, 1,000 scenarios, seed 20260922:

| Kernel's reason | False admits | Mechanism |
|---|---|---|
| Authority | 196 | tool in policy but not in credential: v0.1 admits the union |
| Observation | 101 | tool in credential but not in policy: the same union |
| Semantic | 169 | v0.1 never sees arguments (R22) |
| Provenance | 21 | v0.1 never sees provenance |
| Temporal | 0 | v0.1 checks expiry |

No false rejects. Every false admit matches a mechanism stated in darm-monitor's formalization of v0.1 (IC1RuntimeSemantics, R22), checked case by case against the saved report.

**Writing an adapter for your own gate:**

    from darm_guard.verify import verify, Verdict

    def my_gate(req):     # req has "policy", "credential", "invocation"
        ...               # translate req into your gate's terms and ask it
        return Verdict(admitted, reason)

    print(verify("my-gate", my_gate, n=1000).summary())

**Third-party adapters.** darm-verify includes adapters for AgentLock and Agent-Airlock, each probed against a specific release and translating only what the probes confirmed; scenarios a gate cannot express are declined with a reason rather than forced. Their results are shared with each project's maintainers before any publication.

**Scope.** Divergences are measured against the kernel's semantics and against your adapter's translation of each scenario, so a divergence can mean a gap in the gate or a limit of the translation. The JSON report includes every scenario so a person can tell which. Scenarios are generated from a small vocabulary: they test decision logic, not real workloads. Verify requires the kernel (darm-guard-install-kernel) and stops if the kernel errors, rather than reporting without a referee.

## Composing DARM Guard with other defenses

DARM Guard is meant to sit beneath other agent defenses (prompt-injection filters, label trackers, planners), not to replace them. Two rules follow from how layered defenses fail:

- **A layer backs up another only in a dimension it also checks, from an independent input.** A defense that tracks where data came from cannot catch a broker fault in credentials, expiry or policy: in those cases every provenance check passes. Those dimensions rest on DARM Guard alone, which is why each of them is guarded by a test that fails when the check is removed (`scripts/mutation_gate.py`).
- **Never populate DARM Guard's registry from another layer's labels.** Provenance is the one dimension where a second layer genuinely helps, and only while the two compute it independently. If the broker trusted what an upstream layer labeled, one corrupted label would get past both at once.

## Limitations

Every claim's own limitation, with what all of them assume, is in [LIMITATIONS.md](LIMITATIONS.md). In short:

- **Mediation is assumed**, and tested only in the reference deployment. Any other deployment has to establish it.
- **The Python broker is tested against the model, not proved.** Its effect surface is audited and gated, and the audit rests on stated assumptions: correct review, static analysis of the package, collision-resistant fingerprints.
- **The kernel's trusted base** includes the Lean compiler and runtime, its JSON parser and I/O loop, and the broker's decoding of replies.
- **Payload, information flow and physical effects are out of scope.**

## Roadmap

- Next -- delegation of intents; deletes as authorized effects (attributed from the log alone, since an absence carries no attestation); certifying the broker's execution, logging and attestation beyond tests (the decision path is already the proved kernel, compiled); publishing third-party comparisons with their maintainers.
- Later -- credential-holding enforcement broker for one domain; gated credential expansion.

## License

Apache License 2.0 from the next release: see [LICENSE](LICENSE) and [NOTICE](NOTICE). Versions 0.22.0 and earlier were published under the MIT License, and remain so. Contributions are accepted under the [Developer Certificate of Origin](CONTRIBUTING.md). The names DARM, DARM Guard and PerceptraAI are not licensed under it (Apache-2.0, section 6).

---

**Olusanya Gbolahan V** · PerceptraAI Lab
