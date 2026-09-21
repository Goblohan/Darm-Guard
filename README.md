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

DARM Guard v0.1.x operates at the **tool-name** level. It is grounded in a machine-checked Lean theory, but the Python runtime itself is not formally verified.

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

- v0.2 -- invocation-level authorization (tool + arguments), gated credential expansion, invocation-bound decision tokens.
- v0.3 -- decision computed by a Lean kernel via the existing C-ABI.
- v0.4 -- credential-holding enforcement broker for one domain.

## License

MIT

---

**Olusanya Gbolahan V** -- **PerceptraAI Lab**
