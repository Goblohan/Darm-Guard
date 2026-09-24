# DARM Guard: threat model and trusted computing base (0.7.x)

Every guarantee below rests on stated assumptions. Each assumption names its evidence, or says that there is none yet. A guarantee is only as strong as the weakest assumption it depends on.

## The adversary

The agent: arbitrarily capable and possibly adversarial, including an agent steered by content it has read. It may compose any proposal with any values, send arbitrary bytes to the broker's socket, retry, and flood. It does not hold the tools' credentials, and (by assumption A1 below) it has no route to a governed effect other than the broker.

## What is guaranteed, given the assumptions

- No governed effect without kernel admission (K4, K3; the shipped binary certified on 1,000 answers).
- The executed invocation is the decided one (B3; the broker certified on 2,000 facts).
- The agent cannot vouch for its own values; payload cannot buy authority (B1, B2a, K4).
- With --intents, no action without a principal-held, single-use intent; the agent's stated reason is irrelevant (E24; certified on 300 sequences).
- Evidence before effect: every effect has a prior durable record, and no effect reads as "none" in the log (B4, proved; tests/evidence_attacks.py).

## Trusted computing base

| Component | Status |
|---|---|
| Lean proofs of K1, K3, K4, B1–B4, E24 | Checked by Lean's kernel; CI audits for sorryAx |
| Lean compiler, runtime, and JSON parser in the kernel binary | Trusted; the binary's answers are differentially certified against the Lean model |
| Python broker | Trusted; certified against B3 and E24 on sampled inputs, not proved |
| Python interpreter and standard library | Trusted |
| Operating system: process isolation, file permissions, Unix sockets | Trusted |
| Filesystem: fsync durability, rename atomicity | Trusted (assumptions A3, A4) |
| Container runtime, for the reference deployment | Trusted (assumption A1) |
| System clock | Trusted (assumption A6) |

## Assumptions

| | Assumption | Needed for | Evidence |
|---|---|---|---|
| A1 | The agent's only route to a governed effect is the broker socket | Every guarantee | CI bypass tests, reference deployment only |
| A2 | The agent cannot write the config, registry, intents, audit log, or kernel binary | Every guarantee | Deployer's file permissions; config and registry fingerprints logged at startup; kernel pinned by SHA-256 |
| A3 | An append that returns after fsync has reached durable storage | B4 | Operating system guarantee; not tested under power loss |
| A4 | Renaming within one filesystem is atomic | B4, atomic writes | POSIX guarantee; does not hold on some network filesystems |
| A5 | One broker process owns the intents file and audit log | E24 single use, audit chain | A lock within one process; several brokers sharing these files is unsupported |
| A6 | The system clock is trustworthy | Credential expiry | None; clock rollback is not detected |
| A7 | Whoever can connect to the socket is the agent being governed | Identity of the caller | Socket permissions 0600; no caller authentication |

## Out of scope by design

- A compromised host, operating system, or privileged process; hardware and firmware.
- Whether payload is true, harmless, or free of sensitive data; information flow and declassification.
- What an effect causes downstream (a written config file that another system reloads).
- Supply chain beyond the pinned kernel hash.

## Known limitations, not yet addressed

- Time-of-check to time-of-use on paths: another process can change the filesystem between the real-path check and the file operation. The kernel reasons about path strings, not file identities.
- Truncation of the most recent audit entries is not detectable without an external checkpoint; entries are hash-chained but not signed.
- Credential expiry is checked at decision time, not when the effect completes.
- Intents are per tool, not per resource or per content.
- No revocation of in-flight requests; no delegation or attenuation model.
- Availability: a 1 MB request limit and a connection backlog, nothing more.
