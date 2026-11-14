# DARM SDK A2: Bounded Transport Contract

Status: proposed Track A implementation contract.
Not a claim of production compatibility or independent assurance.

## Pinned baseline

Guard commit: b4165ba4a27551c1117e574db23694339883d897
Broker: darm_guard/broker.py
BrokerClient: lines 1876-1905
Server framing: lines 1550-1577

## Transport invariants

T01. Use AF_UNIX stream transport with newline-delimited JSON.

T02. Require exactly one complete response frame terminated by LF.
Wait for EOF to rule out delayed trailing data. EOF before LF
is not a complete response.

T03. Bound cumulative response bytes, including the delimiter.
Provisional default: 4 MiB, configurable and subject to
real-broker compatibility testing.

T04. Enforce one monotonic transaction deadline covering
connect, request transmission, and response reception.
Individual socket timeouts must respect remaining time.

T05. A definite pre-transmission connection failure may
produce decision=reject, effect=none.

T06. Once transmission is attempted, any transmission
failure, timeout, oversized response, missing delimiter,
or invalid response must preserve an uncertain outcome.
Never infer that the effect did not occur.

T07. No automatic retry after transmission is attempted.

T08. A complete transport frame is not proof of execution.
Pass decoded responses through the SDK response validator.

T09. After the first LF, accept only trailing whitespace
through EOF. Reject non-whitespace trailing bytes even when
they arrive in a later read.

T10. Reject invalid or ambiguous JSON, including duplicate
object keys and non-standard NaN/Infinity constants, as well
as non-object and schema-invalid replies. Treat them as
untrusted without converting the possibly submitted operation
into reject/none.

T11. Preserve broker-declared evidence status and effect
uncertainty. No promotion from unknown to succeeded.

T12. Test using isolated mock AF_UNIX servers and disposable
resources. Do not run consequential broker tools.

## Required adversarial tests

A01. Connection refused before transmission.
A02. Failure during request transmission.
A03. Complete valid response.
A04. Partial response followed by EOF.
A05. Response exceeding byte ceiling.
A06. Slow-drip response exceeding total deadline.
A07. Invalid JSON after transmission.
A08. Valid JSON but invalid response schema.
A09. Trailing bytes after a complete frame.
A10. Boundary-size complete response.
A11. Unknown effect retained without retry.
A12. Repeated requests use independent transactions.

## Evidence boundaries

This contract concerns SDK protocol integrity and bounded
resource use. It does not establish complete mediation,
broker authenticity, independent event observation,
external custody, or causal assurance.

The proposed size ceiling requires compatibility tests
against representative real broker responses.
