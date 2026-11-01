# DARM Q4.3 and Q4.4 runtime assurance evidence

This directory preserves experimental auditor and mutation-suite
source code, verified research records, and references to frozen
evidence archives.

## Q4.4 P2 results

Two real broker sessions were examined, including an explicit
writable-FD canary positive control.

The corrected event auditor passed 36 case-specific checks
and 12 global integrity checks.

All 20 specified adversarial trace mutations were rejected
by the expected checks.

The tested broker-to-decision-kernel executable boundary
was corroborated within the recorded sessions.

## Negative results preserved

The original P2 auditor was NOT_QUALIFIED because of
trace parsing errors. A corrected version subsequently passed.

The first mutation suite rejected 19 of 20 intended mutations.
One mutation was invalid due to an ambiguous syscall target.
The corrected suite rejected all 20.

Both historical versions are retained.

## Q4.4 P3

P3 is preregistered with seven independent-witness gates.

The existing WSL2 environment did not qualify as the
intended native Linux observation host.

No independent kernel witness has been established.

## Scope limitations

This research does not establish universal FD containment,
complete event-history observation, or end-to-end correctness
of the Python broker.

The original evidence archives remain outside this repository.
Their SHA-256 identifiers are recorded in manifest.json.

Scripts may require the original evidence archives and
experimental environment. They are research artifacts,
not production runtime components.

## Verification

Check published_file_sha256 in manifest.json against the
nine files in scripts/ and records/.

The four frozen external archives require separate
SHA-256 verification before reproducing the evaluations.
