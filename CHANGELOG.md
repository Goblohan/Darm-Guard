# Changelog

Every release of DARM Guard, newest first. Each entry says what changed and, where a release fixed a flaw or corrected an overclaim in an earlier one, says so.

Versions 0.22.0 and earlier were published under the MIT License; later versions under Apache-2.0 (see [NOTICE](NOTICE)).

## 0.25.0

Governed GET. A new tool, `http_get`, lets an agent fetch a URL through the broker, only if the kernel admits it. The URL must be in normal form, checked before the decision (https, a lowercase host, no credentials, no dot segments, a canonical IPv4 address only), and is recorded before the call; the status, the body's hash and the server's certificate are recorded after. The principal's credential is attached by the broker and withheld from the agent even when the remote side echoes it; redirects are reported, not followed; loopback, private and cloud-metadata addresses are refused on every resolved answer unless the principal allows them by name. A call sent without a complete answer is unknown, never failed: its intent stays reserved and its idempotency key unresolved (darm-monitor E31). The claim `governed-get` states the limits: the response is the broker's attestation, the remote state is not attested, and URL normal form is tested, not proved. The effect-surface audit now sees network calls; it found one that had gone unseen (the kernel download, now classified), and two network attacks on it are rejected. `darm-guard demo` gains five network steps against a local API, and the Docker deployment a stand-in API the confined agent reaches only through the broker. Also: `EVALUATING.md`; a broker refusing to start says why in a plain message; CI checks that every workflow file is valid.

## 0.24.0

`darm-guard demo`: one command, after installing, runs the broker against an agent in a temporary directory and shows each step: an admitted write and read; refusals for a write without an intent, a path outside the policy even with an intent for it, a traversal, and a proposal that labels itself; an auditor verifying the evidence with the public key alone; an edit outside the broker detected; the audit log's chain intact. It exits non-zero if any step does not behave as described, and runs on every push. No change to the broker or the kernel.

## 0.23.0

Licensed under Apache-2.0; 0.22.0 and earlier remain MIT. The README is rewritten for evaluators: what DARM Guard is and is not, the broker first, how a request is decided, and each claim with its current evidence and bridge, with figures generated from the repository and checked by CI, and a quick start that CI runs exactly as written. The release history moves to this file; the broker's full design and the earlier APIs move to docs/. SECURITY.md, CITATION.cff and CONTRIBUTING.md (contributions under the DCO) are added, and darm-broker --help describes the current broker and intents. No change to the broker's behaviour or the kernel.

## 0.22.0

the broker uses kernel-v0.4.0: every kernel request carries a fresh nonce, and a reply not carrying it is refused and the kernel restarted, so a stale or foreign admission can never be read as the answer (darm-monitor K7). The broker's whole effect surface is audited and gated: all 37 effect sites are classified as executing the kernel's invocation for their request, continuing an admitted transition, or outside the workspace, none open, and the build fails on any new, changed or unclassified site. Recovery rolls a rename forward only on a signed attestation for that request; a forged log record is rolled back. A flaky evidence test now waits for the event instead of a fixed delay. Seventeen mutations, all caught.

## 0.21.0

the broker uses kernel-v0.3.0: it sends the raw proposal, the kernel computes well-formedness, canonicalization and the decision (darm-monitor K6), and the broker executes the invocation the kernel returns, refusing if its own canonicalization disagrees. Normal form is K6's normalPath: paths POSIX keeps, such as '//workspace/x', are now refused, as is a rename destination containing '..', before any decision. A SIGTERM shortly after start-up no longer kills the broker without a stop record. The broker reads kernel replies exactly as K5 proves (a reply that is not an object is a rejection). Every claim now states its bridge to the code: construction, proved, tested or assumed. Fifteen mutations, all caught.

## 0.20.0

every read carries an attribution verdict: attributed only if the attestation, read from the same open file as the content, verifies, names this path, matches the bytes read, and is the path's latest logged write. A file restored with its genuine attestation after the broker replaced or deleted it is refused, because only the log binds freshness. read_requires_attestation refuses unattributed reads (opt-in); a principal-held manifest outside the workspace can vouch for external inputs. verify_world and the verdict share one reading of the log. Also: E30's lineage tested at runtime, and twelve mutations, all caught.

## 0.19.0

a rename now requires the source to carry a valid attestation for its own path and current content, and refuses otherwise (the refusal is recorded). Before this, a file created outside the broker and renamed through it came out attested, with verification clean: foreign content laundered into a state that looked authorized. Found from the model (darm-monitor E29). Files placed outside the broker can no longer be renamed through it; write them through it instead. Also: E28's request link checked at runtime, and eleven mutations, all caught.

## 0.18.0

every threat-model guarantee is backed by an assurance-graph claim and every claim is stated in the threat model, both enforced by check_assurance (which also reports the plan's metrics and writes a machine-readable manifest). Execution identity (darm-monitor E27, E27b): a consistently attested file was put there by the broker operation under its request; its runtime evidence isolates the attestation's signed-path check, which had been tested only by a stale file. Mutation gate at eight checks, all caught.

## 0.17.0

darm-coverage: a coverage map for any gate, showing which dimensions it checks and which rest on DARM Guard alone. Every load-bearing check shown guarded by breaking it (scripts/mutation_gate.py), which found three checks no test asserted; each now tested for its exact failure class. darm-verify gains paired payload scenarios, its default set pinned by hash. Assurance graph: provenance independence and composition, with a README section on composing DARM Guard with other defenses.

## 0.16.0

premise-bound intents (E24d Part 3): an intent may carry premises the broker observes in the world (if_present, if_absent, if_digest), never read from the proposal; while one is false, no one redeems the intent (P15a, closed). With a premise true and content unpinned, the first matching proposal still wins, as E24d proves; pin the content to close that.

## 0.15.0

three-state intent consumption (E24d Part 4): an intent is reserved at admission and settled by B5's verdict once the outcome is durable, so a failed effect no longer spends it (P16, closed). Intents can pin content by digest (content_sha256=), so pinned intents work for real text. A refused path is described by its actual cause. Listen backlog 64 -> 1024 (P10 lost clients under a 100-client burst). Formal side: E24d in darm-monitor, including that deny-by-default is necessary for completeness.

## 0.14.0

in-flight revocation (E24c): the principal revokes through an append-only --revocations file, in force for every decision after it is written; an action already under way completes. Fixes a flaw in every earlier release with intents: editing the intents file while the broker ran was ignored, and the broker's next write could restore an intent the principal had deleted. An outside edit now stops intent-gated actions instead.

## 0.13.0

per-resource intents: an intent names a tool and, optionally, the exact arguments it authorizes (write_file path=/workspace/reports/a.md; a rename's source and destination). Proven in Lean (E24b), including that no intent can widen the policy. Existing tool-only intents files work unchanged.

## 0.12.1

the broker fails closed without its private signing key instead of writing unattested files, and a rename whose signing fails is rolled back. Found by the 0.12.0 release check.

## 0.12.0

external audit checkpoints: the broker signs its log's chain head every N records and at startup and shutdown, and publishes it to a sink outside its own control; anyone with the public keys can detect truncation or rewriting below a published head. New options --checkpoint-sink and --checkpoint-every.

## 0.11.0

attestations are Ed25519 signatures verified against a public key ring, so verifying evidence no longer requires the power to forge it; legacy HMAC attestations are read, re-attested without laundering, then retired; key rotation. First declared dependency: cryptography.

## 0.10.2

a rename onto itself is refused: it lies outside B9's model, and after a crash recovery could not tell it from an interrupted roll-back. Rename recovery is tested through its own crash window (B9: recovery_crash_window_harmless).

## 0.10.1

rename recovery made all or nothing, as B9 proves: a blocked roll-back changes nothing, and recovery never alters foreign content.

## 0.10.0

rename_file: the claim, inspect, re-attest, place protocol (B9), with startup recovery at every phase; a rename is a source delete and a destination write in the typed log (B8 Part 2).

## 0.9.0

delete_file, the first new tool since the hardening: compare-and-delete, a typed audit log so legitimate deletions verify clean (B8), and deletion covered by the compare-and-swap model (B6 Part 1b).

## 0.8.2

fixes 'already applied' being reported after a failed or unresolved keyed attempt (probes P11, P12); proved sound in B7b.

## 0.8.1

corrects an overclaim: retry non-repetition was attributed to B6's final-state theorem; it holds for keyed requests and is now proved in B7.

## 0.8

adversarial hardening: race-free paths, compare-and-swap writes, single-owner locks, a clock witness, kernel-verified callers, startup reconciliation, idempotency keys, file attestation with verify_world, and an evidence basis in every response; B4, B5 and B6 proved; eleven adversarial probes gate every push.

## 0.7.1

evidence before effect: fail-closed prepared records, explicit effect states, startup chain verification, atomic writes. Fixes a 0.7.0 gap in which an effect could occur with no record and the client was told it was rejected.

## 0.7

intents: E24 epistemic premise transfer and the single-use intent gate, certified against the broker; darm-verify adapters for AgentLock and Agent-Airlock.

## 0.6

writes: registry patterns (B2a); role-aware kernel K4, where payload cannot buy authority; write_file; the complete broker model B3 with 2,000 certified facts; kernel-v0.2.0.

## 0.5

DARM Broker for the filesystem domain (read-only): B1 model and certificates, credential lifetime, CI mediation tests.

## 0.4

DARM Verify; proved kernel correspondence to E17, E18, and R22 (K3); kernel-checked certification of the shipped binary.

## 0.3

KernelGuard: invocation-level, provenance-aware, decisions computed by the Lean kernel.
