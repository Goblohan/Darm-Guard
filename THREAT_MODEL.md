# DARM Guard: threat model and trusted computing base (0.8.x)

Every guarantee below rests on stated assumptions, and every assumption has a status: **enforced** (made structural), **witnessed** or **monitored** (violations become visible), or **declared** (still trusted, and said so). Each broker response carries a `basis` naming the theorems and assumptions its own claims rest on; a claim with no theorem behind it says so.

## Adversaries

**The agent**: arbitrarily capable and possibly adversarial, including an agent steered by content it has read. It may compose any proposal, send arbitrary bytes to the broker's socket, retry, and flood. It holds no tool credentials and, under A1, has no route to a governed effect other than the broker.

**Other local processes**: not confined and not trusted. They may modify the workspace concurrently: swap directories for symlinks, overwrite files between the broker's record and its write, edit governed files afterwards, or truncate the audit log. They are not assumed absent; the defences below either make these actions ineffective or make them visible.

## What is guaranteed, given the assumptions

| Guarantee | Basis | Evidence against the implementation |
|---|---|---|
| No governed effect without kernel admission | K4, K3 | Binary certified on 1,000 answers |
| The executed invocation is the decided one | B3 | Broker certified on 2,000 facts |
| The agent cannot vouch for its own values; payload cannot buy authority | B1, B2a, K4 | Certified; attack tests |
| No action without a principal-held, single-use intent | E24 | Certified on 300 sequences |
| A durable record precedes every effect; no effect reads as "none" | B4 | Evidence tests |
| Reconciliation reports state correspondence, never causation | B5 | Probe P3 |
| Writes apply only from the recorded state; conflicts leave the foreign state intact | B6 | Probe P2 |
| A keyed request, submitted any number of times, performs at most one effect, and 'already applied' is reported only when that effect occurred | B7, B7b | Probes P7, P11, P12 |
| A broker deletion removes a file only from its recorded state; a conflicting change is restored and nothing is deleted | B6 Part 1b (casOpt_applies_iff, delete_only_from_recorded) | Delete race test; tests/b8_correspondence.py |
| Legitimate deletions verify clean, while foreign deletions and tampering are detected | B8 | tests/delete_typed_log.py, tests/delete_tool.py |
| A rename never loses or duplicates the file, including across a crash, and rolls back with the original attestation on conflict | B9; B8 Part 2 (tested against the implementation, not certified) | tests/rename_tool.py, tests/rename_crash.py |
| A governed file changed outside the broker, or a dropped log entry whose file survives, is detected | B6 | Probes P8, P9; CI canary |
| Evidence can be verified without the power to forge it: attestations are Ed25519 signatures checked against a public key ring; a legacy v1 file is re-attested only if it still verifies and nothing else is wrong with it | Tested, not modelled | tests/attest_ring.py, attest_broker.py, attest_stage4.py; re-attestation refuses tampered files |
| Truncating the audit log below a published checkpoint, or rewriting any entry before one (even with the whole hash chain recomputed), is detected with public keys only | Tested, not modelled; depends on A8 | tests/checkpoint_test.py, checkpoint_broker.py |
| A path cannot be redirected between check and use | By construction (handle walk, no symlinks followed) | Probes P1a, P1b; not modeled formally |

## Trusted computing base

| Component | Status |
|---|---|
| Lean proofs (K1, K3, K4, B1–B6, E24) | Checked by Lean's kernel; CI audits for sorryAx |
| Lean compiler, runtime and JSON parser in the kernel binary | Trusted; answers differentially certified against K4 |
| Python broker | Trusted; certified against B3 and E24 on sampled inputs; B4–B6 behaviour tested by probes, not certified |
| Python interpreter, standard library, and libc (renameat2 via ctypes) | Trusted |
| The cryptography library (Ed25519 signing and verification) | Trusted; the first declared dependency (0.11.0) |
| Operating system: process isolation, permissions, Unix sockets, flock, SO_PEERCRED | Trusted |
| Filesystem: fsync, rename atomicity, RENAME_EXCHANGE, user extended attributes | Trusted (A3, A4) |
| Container runtime, for the reference deployment | Trusted (A1) |

## Assumptions

| | Assumption | Status | Evidence, and what is not covered |
|---|---|---|---|
| A1 | The agent's only route to a governed effect is the broker | **Monitored** | CI bypass tests in the reference deployment; verify_world detects a bypass that changes a governed file (CI canary). Not detected: bypasses that only read, or that create files the broker never wrote (proved undetectable by B6's verification in R23, uncovered_creation_undetected) |
| A2 | The agent cannot read or write the config, registry, intents, audit log, kernel binary, or the broker's private signing key | **Declared** | Deployer's file permissions; the private key is owner-only (0600); CI confirms the confined agent cannot read it. Verification needs only the public key ring, which may be published |
| A3 | An append or write that returns after fsync is durable | **Declared** | Operating system guarantee; not tested under power loss |
| A4 | Rename and exchange within one filesystem are atomic | **Declared** | POSIX and Linux guarantees; RENAME_EXCHANGE requires filesystem support |
| A5 | One broker owns the audit log and intents file | **Enforced** | Exclusive locks at startup; a second broker refuses to start (probe P4) |
| A6 | The system clock is trustworthy | **Witnessed** | Requests earlier than the latest audit record (5 s tolerance) are refused (probe P5). Not detected: forward jumps, or rollback before the first record |
| A7 | The caller is identified correctly | **Enforced** (process identity) | pid, uid and gid read from the kernel (probe P6). This identifies an operating-system process, not a cryptographically authenticated principal |
| A8 | The checkpoint sink is outside the broker host's control | **Declared** | Deployment only: the broker publishes signed chain heads to --checkpoint-sink but cannot keep them out of reach. A sink the broker's host can rewrite protects nothing against an attacker who controls that host |

## Out of scope by design

- A compromised host, operating system, or privileged process; hardware and firmware.
- Whether payload is true, harmless, or free of sensitive data; information flow and declassification.
- What an effect causes downstream.
- Reconciliation of effects outside the local filesystem: for external systems it requires the target's cooperation (idempotency keys or queryable state), which the broker cannot supply alone.
- Supply chain beyond the pinned kernel hash.

## Known limitations

- **Untested fallbacks.** Without renameat2, writes fall back to compare-then-rename, with a small window not covered by B6; without user extended attributes, files carry no attestation. Both are reported in responses (`attested: false`; the write mechanism in the basis) but neither path is exercised by the tests.
- **ABA.** A foreign writer that restores the exact recorded state between the record and the write is indistinguishable from no change. One that restores both content and attestation defeats verification.
- **Key compromise.** Anyone who can read the private signing key (violating A2) can forge attestations under it; public keys cannot forge. v1 (HMAC) attestations remain forgeable by anyone holding the legacy secret until it is retired.
- **Key rotation.** rotate_keys (with the broker stopped; refused while one holds the lock) keeps old public keys in the ring, so earlier attestations keep verifying, from the public ring alone too. An attestation under a key not in the ring is reported as an unknown key, not a forgery. The rotated private key and the retired legacy secret are removed by file deletion, not secure erasure. Re-attestation of legacy files has a small window between its digest check and the attribute write.
- **Audit checkpoints.** The broker publishes a signed checkpoint every N records (--checkpoint-every) and at startup and clean shutdown. Fewer than N of the newest records are unprotected at any time; a SIGKILL or a crash publishes nothing, leaving the records since the last checkpoint unprotected; a failure to publish is recorded in the log, not prevented. Without --checkpoint-sink, an effect-free tail remains detectable only through surviving governed files.
- **Timing of authority.** Credential expiry is checked at decision time, not when the effect completes; in-flight requests cannot be revoked.
- **Retries without a key.** A retry that carries no idempotency key performs the write again. It lands in the same state, so it is harmless for writes, but it is a second effect; non-repetition holds only for keyed requests (B7). B6's cas_retry_idempotent is a final-state property and does not establish it.
- **Unresolved keys.** A key whose attempt reconciliation leaves unresolved stays pending, and every retry with it is refused, so the caller must use a fresh key. This is deliberate (the broker never guesses whether an unknown write happened), but the key is unusable until an operator resolves it. The mapping from reconciliation verdicts to key states is tested, not modelled, and confirmedSuccess is state correspondence, not attribution.
- **The crash window.** The model's write changes the file and appends its log entry atomically (B6, R23). The implementation can crash between them, leaving an attested file whose request has a prepared record but no outcome; until startup reconciliation appends its confirmedSuccess record, the model's Honest invariant does not hold of the running system. Across the crash, write plus reconciliation corresponds to exactly one model step (tests/r23_crash.py).
- **What verify_world counts as logged.** verify_world treats any record of a request, including a prepared record alone, as logged, which is more permissive than the model's log (successful outcomes and reconciled successes). A prepared record is written only after admission (B4), and a request left without an outcome is reconciled again at the next startup, so the difference self-heals; but the verifier alone will not flag an outcome record that has been removed.
- **Rename.** Without renameat2, rename refuses rather than run unprotected, and it does not cross filesystems. If a roll-back cannot complete at startup (for example, something now occupies the source), the file stays at its private name, which the evidence names, and the verdict is unresolved: recorded, not resolved automatically. B9 assumes no foreign process guesses the private name.
- **Granularity.** Intents are per tool, not per resource or content; there is no delegation or attenuation model.
- **Availability.** A 1 MB request limit and a backlog of 64; a 100-client burst is tested (probe P10). No stronger availability guarantee.
- **Evidence basis.** The check that cited theorems exist matches names, not meanings; that each theorem supports its claim is established by review.
