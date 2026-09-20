# DARM Guard

**See what your agent is doing. Then govern it.**

Formally verified agent tool-authorization governance, backed by 1,001 Lean 4 theorems.

*PerceptraAI Lab*

## Install

From source:

    git clone https://github.com/Goblohan/Darm-Guard.git
    cd Darm-Guard
    pip install -e .

## Quick Start

    from darm_guard import DARMGuard, Policy, Credential

    guard = DARMGuard(
        policy=Policy(authorized_tools=frozenset(["file_read", "web_search"])),
        credential=Credential(tools=frozenset(["file_read"])),
    )

    result = guard.check({"file_read"})   # admitted, within credential
    result = guard.check({"code_exec"})   # admitted (OBSERVE), but alerts drift

## Three Modes

**OBSERVE (default)** -- Agent runs normally. Every tool call logged. Drift detected and alerted. Nothing blocked.

**GOVERN** -- Unauthorized tools blocked with typed ODATS diagnosis.

**ENFORCE** -- Same as GOVERN plus signed audit trail to log file.

    from darm_guard import Mode

    guard = DARMGuard(policy=p, credential=c, mode=Mode.GOVERN)
    result = guard.check({"code_exec"})
    # admitted=False
    # Rejected:
    #   O-failure: code_exec -- not in observation model

## ODATS Diagnosis

Every rejection identifies WHICH condition failed:

| Code | Condition | Meaning |
|------|-----------|---------|
| **O** | Observation | Tool not in the observation model |
| **D** | Domain Completeness | Dependency outside represented domain |
| **A** | Authority | Tool known but not authorized |
| **T** | Temporal Freshness | Credential expired |
| **S** | Semantic Boundary | Resolution mismatch |

Each condition is backed by a deletion-minimality witness proving it independently necessary.

## Session Scope Tracking

Tracks cumulative scope across a session, not just per-call. Individually authorized calls can compose into unauthorized workflows.

    guard.check({"file_read"})       # within credential
    guard.check({"web_search"})      # outside credential, authorized by policy
    print(guard.scope())             # shows cumulative drift

## Temporal Freshness

Credentials can expire. DARM Guard detects stale credentials automatically.

    from datetime import datetime, timedelta

    cred = Credential(
        tools=frozenset(["file_read"]),
        issued_at=datetime(2026, 9, 1),
        ttl=timedelta(hours=4),
    )
    guard = DARMGuard(policy=p, credential=cred, mode=Mode.GOVERN)

    guard.check({"file_read"}, now=datetime(2026, 9, 1, 2))   # admitted (within TTL)
    guard.check({"file_read"}, now=datetime(2026, 9, 1, 5))   # rejected (T-failure)

## Credential Escalation

    guard.update_credential({"code_exec"})   # human-approved expansion

## Audit Trail

    import json
    for entry in guard.audit():
        print(json.dumps(entry))

## LangChain Integration

    from darm_guard.integrations import guard_tools
    guarded = guard_tools(agent.tools, guard=my_guard)

## Formal Backing

Every check maps to a Lean 4 theorem in [darm-monitor](https://github.com/Goblohan/darm-monitor):

| Theorem | What it proves | File |
|---------|---------------|------|
| target_assured_of_source_and_delta | Conservation: Source + Delta -> Target | R5AssuranceConservation |
| ag_is_satisfied + causal_safety_fails | O is necessary | E14AGContractComparison |
| unsupported_authority_substitution | A is necessary | R4bAuthoritySubstitution |
| temporal_freshness_independently_necessary | T is necessary | E16TemporalFreshness |
| proposal_authority_separation | Proposal != Authority | E17ProposalAuthoritySeparation |
| check_true_implies_obligation | Bool check == Prop obligation | E21ExecutableObligationBridge |

167 modules. 31,553 lines. 1,001 theorems. Zero sorry.

## What Makes DARM Guard Different

**Formally verified rejection logic.** Not tested -- proved.

**Session scope tracking.** Cumulative drift, not per-call.

**ODATS diagnostic vocabulary.** Typed diagnoses, not "permission denied."

**Three-mode progressive adoption.** Visibility first, governance when ready.

**Intent-agnostic.** Same structural rejection for benign and malicious agents.

## License

MIT

---

**Olusanya Gbolahan V** -- **PerceptraAI Lab**

[darm-monitor](https://github.com/Goblohan/darm-monitor) | [Darm-Guard](https://github.com/Goblohan/Darm-Guard)
