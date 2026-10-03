#!/usr/bin/env python3
"""Every effect site in darm_guard is classified: the inventory found now must
equal the manifest, every verdict is CLOSED, CONTINUATION or EXCEPTION (OPEN
fails), and every CLOSED or CONTINUATION entry cites tests that exist."""
import collections, json, os, subprocess, sys
rows = json.loads(subprocess.run([sys.executable, "scripts/effect_inventory.py", "darm_guard", "--json"],
                                 capture_output=True, text=True, check=True).stdout)
found = collections.Counter((r["module"] + ":" + r["function"], r["effect"]) for r in rows)
man = json.load(open("assurance/effect_sites.json"))
expected, bad, tally = collections.Counter(), [], collections.Counter()
for fn, e in man["functions"].items():
    for eff, n in e["effects"].items():
        expected[(fn, eff)] += n
    v = e.get("verdict")
    tally[v] += sum(e["effects"].values())
    if v not in ("CLOSED", "CONTINUATION", "EXCEPTION", "OPEN"):
        bad.append(f"{fn}: verdict {v!r} is not a verdict")
    if v == "OPEN":
        bad.append(f"{fn}: OPEN, a governed effect with no authority behind it")
    if not e.get("authority"):
        bad.append(f"{fn}: no authority stated")
    if v in ("CLOSED", "CONTINUATION") and not e.get("tests"):
        bad.append(f"{fn}: {v} cites no test")
    for t in e.get("tests", []):
        if not os.path.exists(t):
            bad.append(f"{fn}: cited test {t} does not exist")
for k in sorted(set(found) | set(expected)):
    if found[k] != expected[k]:
        bad.append(f"{k[0]} {k[1]}: found {found[k]}, manifest says {expected[k]}")
for b in bad:
    print("EFFECT", b)
print(f"effect sites: {sum(found.values())} found, {sum(expected.values())} classified "
      f"({tally['CLOSED']} closed, {tally['CONTINUATION']} continuation, {tally['EXCEPTION']} exception, "
      f"{tally['OPEN']} open)")
sys.exit(1 if bad else 0)
