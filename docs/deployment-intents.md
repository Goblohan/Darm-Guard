# Intent-gated reference deployment

The Compose broker starts with --intents /data/intents.txt. The fixture is
copied into the broker image and is not mounted into the agent. Its four
single-use entries authorize an exact write path and content digest, one
read-back, one deliberately unregistered read, and one exact HTTP URL.
The unregistered read must still fail the kernel's provenance check: an
intent cannot widen the registry or policy.

The agent checks missing intent, wrong path, wrong content before consumption,
successful consumption, and repeated write/HTTP rejection. Successful replies
must report the expected consumed intent. The existing socket mount and bypass
checks remain. Together these are 14 checks in the Compose deployment job.
Numbers 1 through 9 retain their earlier meanings; checks 10 through 14 run
where their preconditions hold, so output is not numerically ordered.

The same CI job also runs tests/deployment_intents.py against the real pinned
kernel. Its three tests establish that the missing/wrong-intent proposals are
admitted by a decision-only control without intent gating, then refused with
gating enabled. They check unchanged files and authority on refusal, exact
content and persisted consumption on success, replay rejection, and the
inability of a matching intent to override a provenance refusal.

Run the Mediation workflow manually on the relevant branch, or locally:

```sh
docker compose -f deploy/compose.yaml up --build --force-recreate --abort-on-container-exit --exit-code-from agent
```

This is a disposable demonstration. Intent consumption, audit records, and
workspace files live in the broker container's writable layer. Restarting that
same container retains it, but recreating it resets the fixture, including the
intents. Recreating a production service must not reissue spent authority.
A production deployment needs a persistent authority/ledger lifecycle and
separate management of principal configuration and broker-mutated state.

The fixture entries are publicly known test authorizations, not secrets or a
production issuance service. The separate host-broker bypass job is unchanged
and does not establish this intent-gated configuration.

No new Lean theorem or Python refinement proof is claimed. The Python broker,
kernel binary/runtime, OS, container runtime, and storage assumptions remain in
the trusted computing base described in THREAT_MODEL.md. These tests do not
prove isolation against every bypass or exactly-once remote effects.
