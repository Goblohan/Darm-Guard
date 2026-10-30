# Native multi-agent provenance candidate

Status: candidate implementation and evidence summary. This is not a production
release and does not claim universal multi-agent security.

Base repository commit: `b4165ba`

## Scope

This candidate adds provenance-aware gateway and bridge wrappers, plus an
independent persistent-state observer. It validates delegation acceptance,
scope enforcement, signature rejection, replay rejection, and reconciliation
between gateway audit records, the witness ledger, and observed filesystem
state.

Runtime scope: `integrated-userspace`

Kernel-floor lifecycle: `NOT_QUALIFIED`

Native model calls: `0`

## Candidate result

The preserved assessment reports:

`PASS_CANDIDATE_NATIVE_INTEGRATION_STATE_OBSERVED`

The tested candidate path demonstrated:

- Valid signed provenance accepted.
- Missing provenance rejected.
- Forged signatures rejected.
- Replayed invocation nonces rejected.
- In-scope write and delete effects accepted.
- Out-of-scope write rejected.
- Independent polling observed `ABSENT -> PRESENT -> ABSENT`.
- Unauthorized targets remained absent from filesystem and witness state.
- Gateway audit records carried provenance fields.

The separate single-agent model campaign tested prompt-injection resistance.
This native provenance campaign intentionally made no model calls so that
provenance enforcement could be attributed to the gateway and bridge layer.

## Limitations

- The candidate gateway was manually launched and was not service-managed.
- The native Codex configuration still points to the original bridge.
- The provenance bridge wrapper was tested as a candidate adapter, not installed
  as the production Codex configuration.
- The polling observer passed. The inotify observer was inconclusive because it
  received no filesystem events.
- The native peer identity remains the shared `darm-agent` UID. Logical
  delegation fields provide the tested provenance distinction.
- The audit and observer components are candidate test infrastructure, not an
  independent production attestation service.
- No kernel-floor qualification or universal multi-agent security claim is
  made.

## Evidence preservation

Raw logs, transcripts, signed envelopes, keys, runtime configuration, and
process artifacts remain outside Git.

Evidence capsule:

`darm-native-provenance-v01-evidence-capsule.tar.gz`

SHA-256:

`b6b52c1d54902ebd12bbbb2b872bed9b4855b92668e37fb7cbb82354729a024f`

Assessment SHA-256:

`781c55fb1e507c39251062200c20361b2db97ac00c1f2e7649fe7f5f2eaf1be7`

## Next qualification gate

Before production or release claims, the candidate requires service-managed
gateway integration, native Codex configuration integration, a separate
model-path campaign, and a hardened independent observation service.
