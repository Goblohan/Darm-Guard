#!/usr/bin/env python3
"""LIMITATIONS.md, generated from the assurance graph: what DARM Guard assumes
throughout, then every claim with its bridge to the code, its stated limitation
and, where the claim names one, its trusted base. --write writes the file;
--check fails if the file is out of date, or if any claim states no limitation.
Usage: scripts/limitations.py --write | --check"""
import json, sys

INTRO = """# What DARM Guard does not establish

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
"""

ORDER = {"construction": 0, "proved": 1, "tested": 2, "assumed": 3}

def render(claims):
    out = [INTRO]
    for c in sorted(claims, key=lambda c: (ORDER.get(c.get("bridge"), 9), c["id"])):
        out.append(f"### `{c['id']}`\n")
        out.append(c.get("claim", "").strip() + "\n")
        out.append(f"- **Bridge:** {c.get('bridge', 'not stated')}")
        out.append(f"- **Limitation:** {c.get('limitation', '').strip() or 'not stated'}")
        tb = c.get("trusted_base")
        if tb:
            out.append("- **Trusted:** " + "; ".join(tb))
        out.append("")
    return "\n".join(out).rstrip() + "\n"

claims = json.load(open("assurance/claims.json"))["claims"]
missing = [c["id"] for c in claims if not c.get("limitation", "").strip()]
text = render(claims)
if "--write" in sys.argv:
    open("LIMITATIONS.md", "w").write(text)
    print(f"LIMITATIONS.md: {len(claims)} claims; {len(missing)} without a stated limitation")
    for m in missing:
        print("   no limitation:", m)
else:
    ok = True
    if missing:
        print("claims with no stated limitation: " + ", ".join(missing)); ok = False
    try:
        current = open("LIMITATIONS.md").read()
    except FileNotFoundError:
        current = ""
    if current != text:
        print("LIMITATIONS.md is out of date; run scripts/limitations.py --write"); ok = False
    if ok:
        print(f"LIMITATIONS.md matches the assurance graph ({len(claims)} claims, each with its limitation)")
    sys.exit(0 if ok else 1)
