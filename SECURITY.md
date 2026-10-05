# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately, to **gbolahan@perceptra.ai**, not in a public issue.
Include what you found, how to reproduce it, and the version or commit. We aim to acknowledge a report
within five working days, and to agree a disclosure date with you before anything is published.

## In scope

- The broker: any way an agent can cause a governed effect the kernel did not admit, act without the
  principal's intent, or leave an effect without its evidence.
- The evidence: forging an attestation, or rewriting the audit log below a published checkpoint undetected.
- The kernel client: any way a reply can be accepted for a request it does not answer.
- A gap between a claim in [THREAT_MODEL.md](THREAT_MODEL.md) or `assurance/claims.json` and what the code does.

## Out of scope

What the threat model states as an assumption, such as complete mediation outside the reference deployment,
the deployer's file permissions, or the trusted base (the Lean compiler and runtime, the operating system).
A report that one of these fails in practice is still welcome, as a limitation rather than a vulnerability.

## Supported versions

The latest release on PyPI. Fixes are released as a new version, and the changelog says what was fixed.
