# What DARM Guard does not establish

Every claim DARM Guard makes is scoped: to the boundary it mediates, the assumptions it states, and the kind of
evidence behind it. This page gathers those limits in one place. The first section lists what every claim rests
on. The second lists each claim in [`assurance/claims.json`](assurance/claims.json) with its own limitation,
generated from that file by `scripts/limitations.py`, so the two cannot disagree: CI fails if this page falls out
of date, or if any claim states no limitation.

## Assumed throughout

- **Complete mediation.** The agent reaches governed files only through the broker. A deployment has to provide
  this, for example with a container or kernel-level enforcement; it is tested only in the reference deployment.
- **The Python broker is tested against the model, not proved.** The decision path is the model compiled, with
  theorems about the server's replies; the broker's execution, logging and attestation are tested. Its effect
  surface is audited and gated, which rests on correct review at each acceptance, on static analysis of the
  package, on collision-resistant fingerprints, and on equal code behaving equally in the same environment.
- **The trusted base.** The Lean compiler and runtime, the kernel's JSON parser and I/O loop, the operating
  system, the C library and Python, the signing key's secrecy, and fresh nonces.
- **What is out of scope.** The truth, harm or sensitivity of content; information flow; physical effects; and
  anything outside the governed workspace.
- **The principal's files.** The config, registry, intents and revocations must be where the agent cannot
  write; file permissions are the deployer's responsibility.

## Claim by claim

Bridges: **construction** means the code is the model compiled; **proved** means a theorem covers the code;
**tested** means tests check the code against the model; **assumed** means nothing does.

### `kernel-admission`

No governed effect without kernel admission: the kernel admits exactly what the certified decision procedure admits, with no false admits.

- **Bridge:** construction
- **Limitation:** The binary's correspondence to the model is by certification on sampled answers, not a refinement proof.
- **Trusted:** the Lean compiler and runtime; Lean's Json.parse and the derived FromJson instances; the kernel server's I/O loop; the broker executes the invocation it decodes from the reply (checked by hash, not proved)

### `kernel-wire-contract`

The broker reads a kernel admission only when the proved kernel admitted the request the kernel parsed; an error or malformed reply never reads as an admission.

- **Bridge:** proved
- **Limitation:** The encoding side (that the request the broker sends is the invocation it means) is tested, not proved.
- **Trusted:** the Lean compiler and runtime; Lean's Json.parse and the derived FromJson instances; the kernel server's I/O loop; Python's json.loads; the broker's decoder matching pyAdmits (checked exhaustively, not proved); the broker never reuses a nonce (a fresh random one per request)

### `authorized-effect-chain`

An authorized write, followed from the proposal to the attested state of the world, holds exactly the authorized content, placed by a write in the history that corresponds to the authorized invocation.

- **Bridge:** tested
- **Limitation:** Pinned writes only (deletes and renames are not authorized effects in E26's correspondence); the implementation's correspondence to the models is tested, not proved; the physical disk is B8's model plus E2's transfer assumption.

### `burst-availability`

Under a burst larger than the listen backlog, excess clients are refused at connect, before sending anything.

- **Bridge:** tested
- **Limitation:** Availability, not safety; the backlog is capped by the kernel's somaxconn.

### `cas-writes`

A write or delete takes effect only if the target is in the state recorded at admission; otherwise nothing changes.

- **Bridge:** tested
- **Limitation:** A foreign writer between observation and replace is detected as a conflict, not prevented; a file with more than one name (a hard link) is refused for reads and writes, checked when it is opened; a link made after that check is outside the model.

### `causal-coverage`

The broker's evidence covers the world's changes exactly when A1 and A2 hold.

- **Bridge:** tested
- **Limitation:** A1 and A2 are deployment assumptions, not guarantees.

### `checkpoints`

Truncating or rewriting the audit log below a published checkpoint is detected, even with the chain recomputed.

- **Bridge:** tested
- **Limitation:** A8: the sink must be outside the broker host's control; records after the last checkpoint are unprotected.

### `completeness`

A mediated mechanism whose intents are all complete executes only acceptable proposals, whoever proposed them; pinned intents are complete, jointly with deny-by-default.

- **Bridge:** tested
- **Limitation:** Digest pinning rests on SHA-256's collision resistance.

### `composition`

A defense layered with DARM Guard backs it up only in a dimension it also checks, from an independent input: a fault in a dimension the other layer does not check, or in an input both share, passes the composition.

- **Bridge:** tested
- **Limitation:** The theorems model layers as independent dimension checks; a real upstream defense's coverage is measured by darm-coverage, not assumed. The results against a specific third-party defense stay private until its disclosure is made.

### `effect-surface`

No governed effect happens without a K6 admission for its request: every effect site in the broker is classified as closed (it executes the kernel's invocation for this request), a continuation of an admitted transition, or outside the governed workspace, and the build fails on any site that is new, changed or unclassified.

- **Bridge:** tested
- **Limitation:** An audit kept true by a gate, not a proof. By darm-monitor E34 the claim holds for every version the build accepts, provided: each --accept follows a correct review; the inventory sees every dependency that static analysis of the package can see (not monkeypatching from outside the package, nor behavior below Python); equal fingerprints mean equal code; and equal code behaves equally in the same environment. That the cones are local is shown by design, by the manifest pinning the analysis's own output, and by attack, not proved. It also rests on the signing key's secrecy, on only the broker writing the log's unprotected tail, and on fresh nonces (K7).

### `evidence-before-effect`

A durable record precedes every effect, whatever faults occur, and no effect is reported as none.

- **Bridge:** tested
- **Limitation:** An outcome that cannot be recorded is reported as evidence unavailable, and the effect's status is then settled by reconciliation.

### `execution-identity`

A file consistently attested (rid, d) was put at its path by a broker operation under rid, in the world's actual history, whatever foreign actions were interleaved; for a write, that operation corresponds to the authorized invocation.

- **Bridge:** tested
- **Limitation:** A rename carries identity under the rename's request, not the original write's; cryptographic unforgeability is assumed (the model's analogue: foreign actions never write the log).

### `governed-get`

An http_get reaches the network only for a URL the kernel admits, in URL normal form, at an address the principal allows; the agent never receives the principal's credential; and every call is recorded before it is sent, with what came back.

- **Bridge:** tested
- **Limitation:** The response is the broker's attestation: TLS does not make it provable to a third party, and the remote system's state is not attested. Data the agent places in an allowed URL reaches that host. URL normal form is checked by the broker before the decision: tested, not proved, since the kernel checks normal form for paths only. GET only, with no headers or body from the agent.
- **Trusted:** the TLS library's certificate verification; the system resolver; the secrecy of the principal's credential files

### `input-coverage-limit`

Authorization completeness constrains what an action produces, not what it drew on; when the boundary does not observe an agent's inputs, no intent can enforce coverage of them.

- **Bridge:** tested
- **Limitation:** Inputs could be governed by mediating reads, which would enlarge what the boundary observes; DARM Guard does not do this today.

### `intent-required`

Execution requires a principal-held intent and B3's full admission; the agent's stated reason cannot move the decision.

- **Bridge:** tested
- **Limitation:** A tool-only intent does not fix which resource or content (see resource-intents and completeness).

### `invocation-correspondence`

The authorized payload survives canonicalization and reaches the executed invocation, and the mediated domain excludes external creation: every mediated transition is logged.

- **Bridge:** tested
- **Limitation:** Proved for the pinned write case; the corresponding operation exists by construction.

### `lineage-limit`

Completeness is possible exactly when acceptance is determined by what the boundary observes; when it depends on an unobserved process, no intent is complete.

- **Bridge:** tested
- **Limitation:** Making a hidden process observable requires a trusted component whose correctness is an assumption.

### `path-race-free`

A path cannot be redirected between check and use: resolution is race-free and refuses symlinks.

- **Bridge:** tested
- **Limitation:** Hard links are outside the model; the resolution is Linux-specific (openat with O_NOFOLLOW).

### `premises`

While every fitting intent has a false premise, nothing executes and nothing is spent; premises never widen the policy.

- **Bridge:** tested
- **Limitation:** A premise holds at the decision, not throughout the effect; digest premises are modeled only as presence.

### `provenance-independent`

Provenance is assigned by the broker from the principal's registry, never read from the proposal or from an upstream layer; what executes is the broker's canonical reading of the proposal.

- **Bridge:** tested
- **Limitation:** Independence holds only if the deployment never populates the principal's registry from an upstream layer's labels; that is a deployment obligation, stated in the README.

### `read-attribution`

Every read through the broker carries a verdict on whether its content is attributed, and to whom: to a broker write (the attestation verifies, names the path read, and its digest equals the digest of the exact content returned) or to the principal (a principal-held manifest names the path and that digest). With read_requires_attestation, an unattributed read is refused and nothing is delivered.

- **Bridge:** tested
- **Limitation:** The verdict is advisory unless read_requires_attestation is set or the consumer gates on it; content from outside the broker is attributed only if the principal vouches for its exact digest; vouching attributes provenance, not truth or safety; the manifest's location is checked against the workspace, but other ways the agent could reach it (shared mounts, a writable parent) are the deployment's to exclude; Freshness is the log's: a read whose content and attestation were restored after the broker replaced or deleted them is refused, because the path's latest log entry is not its write (B8p replay_accepted_by_attestation_caught_by_log); a reader without the log cannot check freshness.

### `reconciliation`

Reconciliation reports state correspondence, never causation: success only when the observed state is the intended one.

- **Bridge:** tested
- **Limitation:** ABA: an outside writer restoring the exact previous state is indistinguishable from no effect.

### `rename-atomic`

A rename, including its crash recovery, ends where one atomic move would, or where it started; never in between, never lost or duplicated.

- **Bridge:** tested
- **Limitation:** Requires renameat2; the private slot is outside casMove (B9 proves it empty at the end).

### `rename-attribution`

A file placed by a rename is attributed through two requests: the rename that moved it, from its path to its destination, and the write that authorized its content, linked by the attestation the rename moved.

- **Bridge:** tested
- **Limitation:** The capstone assumes the content was written once, under the authorized request; deletes are not attributed (an absence carries no attestation).

### `rename-no-laundering`

A rename never attests content the broker did not write: it moves only a source carrying a valid attestation for its own path and current content, and in such histories every attested content was produced by a write.

- **Bridge:** tested
- **Limitation:** Files placed outside the broker cannot be renamed through it; they must be written through it, under an authorized request. Rests on the secrecy of the signing key.

### `resource-intents`

An intent authorizes only proposals whose named arguments all match, and never admits what the policy rejects.

- **Bridge:** tested
- **Limitation:** Intents bind names, not files; values cannot contain whitespace (use content_sha256).

### `retry-once`

A keyed retry never applies an effect twice, and 'already applied' is reported only when the effect happened.

- **Bridge:** tested
- **Limitation:** Keys are scoped to one audit log.

### `revocation`

A revocation is in force for every decision after it is on disk, never grants, and revoking a tool blocks every proposal for it.

- **Bridge:** tested
- **Limitation:** An action already committed completes; its effect is not recalled.

### `signatures`

Evidence can be verified with public keys only, and forged by no one without the private key.

- **Bridge:** tested
- **Limitation:** Rests on Ed25519 and the secrecy of the private key; rotated keys are deleted, not securely erased.

### `three-state`

An intent is spent only by a confirmed effect: a proven non-effect returns it, an unknown outcome keeps it reserved.

- **Bridge:** tested
- **Limitation:** ABA: an outside writer restoring the exact previous content after a failed-but-applied effect returns the intent.

### `world-matches-log`

Legitimate operations never flag, and a governed file tampered with or deleted outside the broker is detected.

- **Bridge:** tested
- **Limitation:** Files created outside the broker are not detected (foreign_creation_undetected).
