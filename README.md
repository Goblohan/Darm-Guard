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

KernelGuard checks the tool, its arguments, and where each argument came from. Every allow/deny decision is computed by the DARM decision kernel: a Lean 4 function with machine-checked properties (darm-monitor K1DecisionKernel), compiled to a native binary (K2DecisionServer). The Python side only formats requests.

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

**Requirements and limits.** pip install does not yet include the kernel binary: build it from darm-monitor with lake build darmkernel, then pass its path or set DARM_KERNEL_PATH. Not proved: this Python module, JSON encoding, argument-to-string conversion, expiry computation, the kernel's JSON parser and I/O loop, and the Lean compiler. The guard fails closed if the kernel is missing, crashes, or times out. Provenance labels come from the caller; the guard does not infer lineage.

## Three Modes

**OBSERVE (default)** -- logs and classifies every call. Never blocks. Prints a warning saying so.

**GOVERN** -- returns a rejection with a typed diagnosis. Your code must honour it.

**ENFORCE** -- as GOVERN, plus an append-only JSON-lines audit file.

    from darm_guard import Mode
    guard = DARMGuard(policy=p, credential=c, mode=Mode.GOVERN)
    result = guard.check({"code_exec"})
    # result.admitted == False
    # O-failure: code_exec -- not in observation model

## What is and is not guaranteed

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

- v0.3 (this release) -- KernelGuard: invocation-level, provenance-aware, decisions computed by the Lean kernel.
- Next -- prebuilt kernel binaries so pip install is self-contained; DARM Verify, conformance testing of other gates against the kernel.
- Later -- credential-holding enforcement broker for one domain; gated credential expansion.

## License

MIT

---

**Olusanya Gbolahan V** -- **PerceptraAI Lab**
