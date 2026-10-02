#!/usr/bin/env python3
"""Every claim states its bridge from model to implementation, and the gate
counts them, so the empirical part of the system stays explicit."""
import json, sys
BRIDGES = {"construction": "the code is the model, compiled",
           "proved": "a theorem about the code itself",
           "tested": "runtime tests against the model, not proved",
           "assumed": "stated, not checked"}
doc = json.load(open("assurance/claims.json"))
bad, tally = [], {}
for c in doc["claims"]:
    b = c.get("bridge")
    if b not in BRIDGES:
        bad.append(f"{c['id']}: bridge {b!r} is not one of {sorted(BRIDGES)}")
    elif b in ("construction", "proved") and not c.get("trusted_base"):
        bad.append(f"{c['id']}: a {b} bridge must name its trusted base")
    else:
        tally[b] = tally.get(b, 0) + 1
for x in bad:
    print("BRIDGE", x)
print("bridges:", ", ".join(f"{tally.get(k, 0)} {k}" for k in BRIDGES))
print("trusted base named:", "; ".join(sorted({t for c in doc["claims"] for t in c.get("trusted_base", [])})))
sys.exit(1 if bad else 0)
