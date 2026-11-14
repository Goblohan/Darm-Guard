# DARM SDK-A1 Security Contract

Status: PROPOSED, NOT IMPLEMENTED
Baseline: b4165ba4a27551c1117e574db23694339883d897
Formal source pin: caebc7c
Scope: Python SDK client only

## Invariants

I01. No direct governed effect from SDK code.
I02. No agent-assigned trusted provenance.
I03. Malformed responses never become confirmed success.
I04. Possible post-submission effects remain UNKNOWN on transport failure.
I05. Request and response bytes and processing duration must be bounded.
I06. Authorization, effect, evidence and assurance remain distinct.
I07. No implicit retry of potentially executed requests.
I08. Connectivity does not prove complete mediation.
I09. already_applied is not a newly executed effect.
I10. Assurance claims retain their assumptions.
I11. Valid JSON does not establish broker identity.
I12. Missing evidence never defaults to recorded.

## Implementation constraints

- Preserve the existing broker request protocol.
- Do not change the Lean kernel or authorization logic.
- Do not interpret local transport failure as kernel rejection.
- Do not equate reconciliation with independent causal evidence.
- Preserve request correlation and idempotency semantics.
- Reject or quarantine unrecognized response structures.
- No automatic promotion of deployment assurance status.

## Required negative tests

N01. JSON null, list, string and incomplete dictionaries.
N02. Invalid decision and effect combinations.
N03. Truncated and oversized responses remain uncertain.
N04. Slow fragmented responses beyond the overall deadline.
N05. Connection loss before, during and after submission.
N06. Missing evidence and missing assurance basis.
N07. Unresolved idempotency-key request.
N08. already_applied without a new effect.
N09. Unexpected broker error with unknown effect.
N10. Untrusted or substituted socket peer.
N11. Oversized outbound requests are rejected before connecting.
N12. Request encoding is covered by the transaction deadline.
N13. Exact request byte boundary includes LF; one byte over is rejected.
N14. Bounded encoding preserves the existing broker wire representation.

## Track B obligations

Complete mediation, OS isolation, broker identity,
source-to-runtime correspondence, independent event witnessing
and external evidence custody remain separately qualified.

## Release rule

Static contract completion is not runtime qualification.
SDK-A1 release requires negative tests and reviewed source changes.
