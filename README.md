# DARM Guard

**See what your agent is doing. Then govern it.**

An agent tool-authorization guard, grounded in a machine-checked Lean 4 theory of assurance transfer.

*PerceptraAI Lab*

## Install

    pip install darm-guard

## Quick Start

    from darm_guard import DARMGuard, Policy, Credential

    guard = DARMGuard(
        policy=Policy(authorized_tools=frozenset(["file_read", "web_search"])),
        credential=Credential(tools=frozenset(["file_read"])),
    )

    guard.check({"file_read"})   # admitted, within credential
    guard.check({"code_exec"})   # admitted in OBSERVE mode, but reported

## Kernel-backed guard (v0.3, recommended)

KernelGuard checks the tool, its arguments, and where each argument came from. Every allow/deny decision is computed by the DARM decision kernel: a Lean 4 function with machine-checked properties (darm-monitor K4RoleKernel, which decides exactly as K1DecisionKernel on policies without payload rules), compiled to a native binary (K4DecisionServer). The Python side only formats requests.

    from darm_guard import KernelGuard, KernelPolicy, ToolRule, ArgRule

    policy = KernelPolicy(tools=(
        ToolRule("file_read", (ArgRule("path", allowed_prefixes=("/workspace/",)),)),
    ))
    guard = KernelGuard(policy, tools={"file_read"},
                        default_provenance="untrusted",
                        kernel_path="/path/to/darmkernel")

    guard.check("file_read", {"path": "/workspace/notes.txt"},
                provenance={"path": "authoritative"})         # admitted
    guard.check("file_read", {"path": "/etc/passwd"},
                provenance={"path": "authoritative"})         # rejected: semantic
    guard.check("file_read", {"path": "/workspace/notes.txt"})  # rejected: provenance

Proved about the kernel's decision function: an admitted invocation passed all five checks, and an expired credential, a tool outside the credential, or any untrusted argument value can never be admitted.

**Install the kernel.** After pip install darm-guard, run darm-guard-install-kernel. It downloads the kernel binary that darm-monitor's CI built from tag kernel-v0.2.0 and installs it only if its SHA-256 matches the value pinned in this package. Linux x86_64 only; elsewhere, build it with lake build darmkernel and set DARM_KERNEL_PATH. Kernels are never downloaded during an authorization check.

**Limits.** Not proved: this Python module, JSON encoding, argument-to-string conversion, expiry computation, the kernel's JSON parser and I/O loop, and the Lean compiler. The guard fails closed if the kernel is missing, crashes, or times out. Provenance labels come from the caller; the guard does not infer lineage.

## DARM Broker: the enforcement point

KernelGuard answers "is this authorized?" The broker makes the answer binding. It is a separate process that holds the tools and their credentials; the agent holds only a socket and can only propose. The broker builds one canonical invocation, asks the kernel, and executes that same invocation only if admitted.

    darm-broker --config broker.json --registry registry.txt --socket /tmp/darm-broker.sock

    from darm_guard.broker import BrokerClient
    agent = BrokerClient("/tmp/darm-broker.sock")
    agent.propose("read_file", {"path": "/workspace/notes.txt"})

The config holds the policy, the credential's tools, the workspace directory, and optionally a credential lifetime (issued_at, ttl_seconds). The registry lists the values the principal vouches for, one per line, in a file the agent cannot write. A line ending in * is a pattern: /workspace/reports/* vouches for every value under that prefix, which gets provenance derived. A policy rule marked "payload": true (a file's content, say) must satisfy its rule but is not provenance-gated: the kernel proves payload cannot buy authority.

**Intents (E24).** Started with --intents, the broker also requires a principal-held, single-use authorization for each kind of action: a file listing tool names, one per line, in a place the agent cannot write. Each admitted action consumes one; a rejected attempt keeps it; the file is rewritten so a restart cannot resurrect a spent authorization. The agent cannot supply a reason for acting: proposals have no such field, and E24 proves the claimed reason cannot affect the outcome. This closes a gap that per-argument provenance leaves open: content that manipulates *whether* the agent acts, using values the principal supplied.

**Design rules.** Proposals are exactly {tool, args}: a proposal carrying any other field, such as a provenance label, is refused rather than ignored, and the broker assigns provenance itself. The invocation that executes is exactly the one the kernel decided; execution itself can still fail, and responses say so. Path arguments must be in normal form, because kernel prefix rules compare strings, and the real path is re-checked before touching disk. Responses report the kernel's decision separately from whether execution happened. Evidence comes before effect: a prepared record is written and synced to disk before any action, and if it cannot be written, nothing is performed; the outcome is recorded afterwards, so an unrecorded outcome always shows as prepared-without-outcome. Responses report the effect (none, succeeded, failed, unknown) and the evidence status. A client that sent a request but got no valid reply reports unknown, never reject. The audit log is hash-chained, starts with fingerprints of the config and registry, and is verified at startup: the broker refuses to run on a broken chain. Hash chaining detects edits, but not truncation of the most recent entries without an external checkpoint.

| Claim | Evidence |
|---|---|
| Decision correctness | Kernel proved (K4, a conservative extension of K1, so K3's correspondence carries over); shipped binary kernel-v0.2.0 certified on 1,000 answers |
| Executed invocation = decided invocation | Proved in darm-monitor B3BrokerModel, patterns and payload included; this broker certified against B3 on 2,000 kernel-checked facts, with coverage floors for every outcome, untrusted payload, and pattern-derived provenance |
| Content cannot buy authority | Proved in K4 (payload_cannot_buy_authority); attack-tested: a registered value used as content cannot buy an unregistered path |
| No action without the principal's intent | Proved in E24 (execution requires a registered, single-use intent; the agent's claimed reason is irrelevant); this broker certified against E24 on 300 three-step sequences; attack-tested: a hijacked third write is blocked |
| No effect without prior evidence | Proved in B4 (no_silent_effect_ever, on propext alone); tested: an unwritable log means nothing is performed, a tampered log stops the broker from starting, a request with no reply reports unknown |
| Writes apply only from the recorded state; conflicts leave the other writer's change intact | Proved in B6 (cas_applies_iff, cas_conflict_preserves); probe P2 |
| A keyed request, retried any number of times, performs at most one effect; 'already applied' is reported only when that effect occurred | Proved in B7b (already_applied_sound, at_most_once_with_failures); probes P7, P11, P12. Without an idempotency key, a retry performs the write again |
| A deletion removes a file only from its recorded state; legitimate deletions verify clean, foreign ones are detected | Proved in B6 Part 1b (casOpt_applies_iff, delete_only_from_recorded) and B8 (legitimate_ops_never_flagged); tests/delete_tool.py, tests/b8_correspondence.py |
| A rename moves a file without losing or duplicating it, even across a crash, and re-attests it | Proved in B8 Part 2 (rename_preserves) and B9 (our_file_never_lost_or_duplicated, recovery_normal, late_occupation_restores); tests/rename_tool.py, tests/rename_crash.py. The implementation is tested against B9, not certified |
| Changes outside the broker, and dropped log entries, are detected | Proved in B6 (tamper_detected, truncation_detected); probes P8 and P9; a CI canary shows a bypass of the broker being caught |
| Reconciliation reports state, not causation | Proved in B5 (success_is_state_confirmation); probe P3 |
| The agent cannot vouch for itself | Proved in B1; enforced at the interface; attack-tested |
| No other route to the effect | CI: an agent in a container with no network, a read-only filesystem, and only the broker socket reads and writes through the broker, and five bypass attempts fail (tests/confined_agent.py) |
| The agent cannot change the rules | Config and registry fingerprints logged at startup; file permissions are the deployer's responsibility |

**Adversarial hardening (0.8).** Paths are resolved by walking from a handle on the workspace, one directory at a time, never following symlinks, so a path cannot be redirected between check and use. Writes are compare-and-swap: the new file is exchanged in atomically (renameat2), the displaced content is checked against the recorded before-state, and on a mismatch the exchange is undone, restoring the other writer's change. Exclusive locks stop a second broker from sharing the audit log or intents; the audit log acts as a clock witness; each connection's caller is identified by the kernel. At startup the broker reconciles any request left without an outcome. A proposal may carry an idempotency_key, so a retry after an unknown result reports already_applied instead of writing twice. Each written file carries an attestation (an HMAC under a broker-held key) naming the request that wrote it, and verify_world checks the files against the log in both directions, catching changes made outside the broker and log entries that were dropped. Every response carries a basis: its claims, each with the theorems and assumptions it rests on, and a claim with no theorem behind it says so. Eleven adversarial probes (tests/adversarial_probes.py) must all hold on every push.

**Limits.** Tools: read_file, list_dir, write_file, delete_file, rename_file. Registry patterns widen what the principal vouches for, and pattern breadth is the principal's responsibility. Payload is not checked for truth, harm, or sensitive data: information flow is out of scope. Without --intents, argument provenance alone does not address intent manipulation. Intents are per tool: an authorized intent does not fix which content is sent beyond what the policy's rules fix. The kernel's prefix rules compare strings and assume canonical input, which the broker supplies; the bare kernel alone would pass a traversal such as /ws/../etc. The mediation evidence covers the reference deployment only; any other deployment has to establish mediation itself, and a container escape is a failure of the isolation layer, not of DARM. The Python broker is certified against the model, not proved. The full list, including the limits of the 0.8 defences, is in THREAT_MODEL.md.

## DARM Verify (v0.4)

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

## Three Modes

**OBSERVE (default)** -- logs and classifies every call. Never blocks. Prints a warning saying so.

**GOVERN** -- returns a rejection with a typed diagnosis. Your code must honour it.

**ENFORCE** -- as GOVERN, plus an append-only JSON-lines audit file.

    from darm_guard import Mode
    guard = DARMGuard(policy=p, credential=c, mode=Mode.GOVERN)
    result = guard.check({"code_exec"})
    # result.admitted == False
    # O-failure: code_exec -- not in observation model

## Claim strata

Each layer's claim is weaker than the one above it, and none inherits another's.

| Stratum | Established | How | Not inherited |
|---|---|---|---|
| S1 Obligations | ODATS necessity, conservation, IC1/R22 correspondence | Lean proofs, CI-audited (darm-monitor) | Anything about a specific implementation |
| S2 Kernel | kernelDecide's own properties: admission soundness; expired, uncredentialed, or untrusted invocations never admitted | Lean proofs, kernel-checked (K1); correspondence to S1 proved in K3a/K3b: exact agreement with E17's gate, admission-level agreement with E18 ODATS, sound refinement of R22 for every invocation (no false admits; complete on the governed tool) | E15's causal lift (rests on TMC); E18 diagnosis order (kernel T-first, E18 O-first); domain completeness, which the kernel assumes rather than checks |
| S3 Binary | Built by CI from the tagged, verified commit; SHA-256 pinned in this package; 1,000 of its answers (every outcome, and admitted untrusted payload, at least 10 each) confirmed by Lean's kernel evaluating K4's kernelDecide | Provenance, tests, and kernel-checked differential certificates | Correct compilation in general: certificates cover sampled inputs only; the JSON parser, I/O loop, and Lean compiler remain trusted |
| S4 Runtime | KernelGuard asks the kernel for every decision and fails closed; the broker holds the tools, assigns provenance itself, and executes only what the kernel admitted | Tests; broker certified against the B3 model and E24's intent gate; CI bypass tests in the reference deployment | For KernelGuard alone: complete mediation, and caller-supplied provenance. For the broker: mediation outside the reference deployment, and config file permissions |
| S5 World | Nothing | -- | Physical safety: an explicit assumption (TMC), not a result |

## What is and is not guaranteed

The full threat model, trusted computing base, and assumption list are in [THREAT_MODEL.md](THREAT_MODEL.md).

The v0.1 DARMGuard API operates at the **tool-name** level, and the notes below apply to it. For argument-level, kernel-computed decisions, use KernelGuard (above). It is grounded in a machine-checked Lean theory, but the Python runtime itself is not formally verified.

**Guaranteed by the runtime:**

- Credentials and policies are immutable once constructed.
- The delta (requested tools not in the credential) is computed exactly.
- Decisions are deterministic: the same inputs give the same result.
- Within one process, every check is appended to the session audit log.

**Proved in Lean about this runtime** (darm-monitor):

- The v0.1.0 decision rule is formalized exactly and proved equivalent to a single inclusion condition (IC1RuntimeSemantics).
- Because v0.1.x observes only tool names, no authorizer built on its observations can separate a safe call from a forbidden call to the same tool (R22RuntimeImplementationCorrespondence).
- A runtime that also observes arguments recovers that distinction (R22). This is the specification for v0.2.

**Not guaranteed -- assumed:**

- Complete mediation: calls that bypass the guard are invisible to it.
- Enforcement: in GOVERN mode the guard returns a decision; it cannot stop code that ignores it.
- Argument-level or effect-level safety: file_read on any path is treated the same.
- Authorization of credential expansion: update_credential is not access-controlled.
- Freshness at execution time: expiry is checked when check() runs, not when the tool runs.
- Session state across processes or restarts.
- The D (domain) and S (semantic) conditions: classified in the theory, not enforced at runtime.

## ODATS Diagnosis

| Code | Condition | v0.1.x runtime |
|------|-----------|----------------|
| O | Observation -- tool unknown to the policy | enforced |
| D | Domain completeness | not enforced |
| A | Authority -- tool known but not authorized | enforced |
| T | Temporal freshness -- credential expired | enforced at check time |
| S | Semantic boundary | not enforced |

Each condition is proved independently necessary in the Lean theory: removing any one admits a countermodel.

## Session Scope Tracking

Tracks cumulative scope across a session, within one process.

    guard.check({"file_read"})
    guard.check({"web_search"})
    print(guard.scope())   # cumulative scope and drift

## Temporal Freshness

    from datetime import datetime, timedelta
    cred = Credential(tools=frozenset(["file_read"]),
                      issued_at=datetime(2026, 9, 1), ttl=timedelta(hours=4))

## LangChain Integration

    from darm_guard.integrations import guard_tools
    guarded = guard_tools(agent.tools, guard=my_guard)

## Formal Backing

The conditions behind each check are proved in [darm-monitor](https://github.com/Goblohan/darm-monitor). See [FORMAL_BACKING.md](FORMAL_BACKING.md) for the theorem map. 1,100+ theorems, zero sorry, CI-audited for sorryAx.

## Roadmap

- v0.3 -- KernelGuard: invocation-level, provenance-aware, decisions computed by the Lean kernel.
- v0.4 -- DARM Verify; proved kernel correspondence to E17, E18, and R22 (K3); kernel-checked certification of the shipped binary.
- v0.5 -- DARM Broker for the filesystem domain (read-only): B1 model and certificates, credential lifetime, CI mediation tests.
- v0.6 -- writes: registry patterns (B2a); role-aware kernel K4, where payload cannot buy authority; write_file; the complete broker model B3 with 2,000 certified facts; kernel-v0.2.0.
- v0.7 -- intents: E24 epistemic premise transfer and the single-use intent gate, certified against the broker; darm-verify adapters for AgentLock and Agent-Airlock.
- v0.7.1 -- evidence before effect: fail-closed prepared records, explicit effect states, startup chain verification, atomic writes. Fixes a 0.7.0 gap in which an effect could occur with no record and the client was told it was rejected.
- v0.8 -- adversarial hardening: race-free paths, compare-and-swap writes, single-owner locks, a clock witness, kernel-verified callers, startup reconciliation, idempotency keys, file attestation with verify_world, and an evidence basis in every response; B4, B5 and B6 proved; eleven adversarial probes gate every push.
- v0.8.1 -- corrects an overclaim: retry non-repetition was attributed to B6's final-state theorem; it holds for keyed requests and is now proved in B7.
- v0.8.2 -- fixes 'already applied' being reported after a failed or unresolved keyed attempt (probes P11, P12); proved sound in B7b.
- v0.9.0 -- delete_file, the first new tool since the hardening: compare-and-delete, a typed audit log so legitimate deletions verify clean (B8), and deletion covered by the compare-and-swap model (B6 Part 1b).
- v0.10.0 (this release) -- rename_file: the claim, inspect, re-attest, place protocol (B9), with startup recovery at every phase; a rename is a source delete and a destination write in the typed log (B8 Part 2).
- Next -- an external audit checkpoint; in-flight revocation; per-resource intents and delegation; certifying the Python broker against B4-B6; publishing third-party comparisons with their maintainers.
- Later -- credential-holding enforcement broker for one domain; gated credential expansion.

## License

MIT

---

**Olusanya Gbolahan V** -- **PerceptraAI Lab**
