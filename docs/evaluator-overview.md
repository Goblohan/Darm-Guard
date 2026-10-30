# Evaluator overview

## What DARM Guard is

DARM Guard is an open-source runtime authorization layer for AI-agent tool
calls. An agent proposes an operation, the decision kernel evaluates it, and
the broker executes only the admitted effect.

The system is designed to make authority decisions and resulting effects
inspectable.

## Stable reference

The current stable repository line is package version `0.28.0`.

The formal model is maintained in the
[DARM Monitor repository](https://github.com/Goblohan/darm-monitor).

## How to evaluate it

Start with:

1. [README.md](../README.md)
2. [EVALUATING.md](../EVALUATING.md)
3. [FORMAL_BACKING.md](../FORMAL_BACKING.md)
4. [THREAT_MODEL.md](../THREAT_MODEL.md)
5. [LIMITATIONS.md](../LIMITATIONS.md)
6. [Assurance claims](../assurance/claims.json)

## Assurance categories

The project distinguishes:

- **Construction**: implementation or structural evidence.
- **Proved**: claims supported by the formal model.
- **Tested**: claims supported by executable evaluation.
- **Assumed**: dependencies or boundaries not independently established.

These categories should not be treated as interchangeable.

## Native multi-agent provenance candidate

The separate candidate PR tests signed delegation, scope restriction, replay
rejection, provenance-bearing gateway audit records, and independent
persistent-state observation.

It is candidate-level evidence only. The campaign intentionally made zero model
calls so that the observed behavior could be attributed to the gateway and
bridge path rather than model behavior.

See [PR #1](https://github.com/Goblohan/Darm-Guard/pull/1).

## Boundaries

DARM Guard is not presented as:

- a general sandbox;
- a content filter;
- a complete end-to-end proof of agent safety;
- universal prompt-injection protection;
- kernel-floor production qualification;
- universal multi-agent security.

## Reproduction

Use the repository's evaluation instructions and preserve the exact source
revision, runtime scope, claim matrix, and evidence limits when reporting
results.
