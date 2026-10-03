#!/usr/bin/env python3
"""The effect-surface gate (v3). Fails unless: the effect sites found now equal
the manifest's; every verdict is CLOSED, CONTINUATION or EXCEPTION (OPEN
fails); every CLOSED or CONTINUATION entry cites tests that exist; every effect
function still has the fingerprint it was reviewed with; and every closed or
continuation verdict's cone (routes into it, everything called along them, and
the module code involved) holds exactly the reviewed functions, each unchanged. After reviewing a change, --accept records the new fingerprints and
routes; it refuses while any site is new or unclassified or any verdict is
invalid, which must be written into the manifest by hand."""
import collections, json, os, subprocess, sys
ACCEPT = "--accept" in sys.argv
inv = json.loads(subprocess.run([sys.executable, "scripts/effect_inventory.py", "darm_guard", "--json"],
                                capture_output=True, text=True, check=True).stdout)
found = collections.Counter((s["module"] + ":" + s["function"], s["effect"]) for s in inv["sites"])
MP = "assurance/effect_sites.json"
man = json.load(open(MP))
expected, bad, review, tally = collections.Counter(), [], [], collections.Counter()
GUARDED = ("CLOSED", "CONTINUATION")
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
    if v in GUARDED and not e.get("tests"):
        bad.append(f"{fn}: {v} cites no test")
    for t in e.get("tests", []):
        if not os.path.exists(t):
            bad.append(f"{fn}: cited test {t} does not exist")
    cur = inv["functions"].get(fn)
    if cur is None:
        continue
    if e.get("fingerprint") != cur["fingerprint"]:
        review.append(f"{fn}: its code changed since its verdict was reviewed")
    if v in GUARDED:
        mr, cr = e.get("cone", {}), cur["cone"]
        for a in sorted(set(mr) | set(cr)):
            if a not in mr:
                review.append(f"{fn}: {a} is new in its cone")
            elif a not in cr:
                review.append(f"{fn}: {a} has left its cone")
            elif mr[a] != cr[a]:
                review.append(f"{fn}: {a}, in its cone, changed")
for k in sorted(set(found) | set(expected)):
    if found[k] != expected[k]:
        bad.append(f"{k[0]} {k[1]}: found {found[k]}, manifest says {expected[k]}")
if ACCEPT:
    if bad:
        for b in bad:
            print("EFFECT", b)
        sys.exit("refused: classify every site by hand in the manifest first; --accept records review, "
                 "it never classifies")
    for fn, e in man["functions"].items():
        cur = inv["functions"][fn]
        e["fingerprint"] = cur["fingerprint"]
        e.pop("reach", None)
        if e.get("verdict") in GUARDED:
            e["cone"] = cur["cone"]
        else:
            e.pop("cone", None)
    json.dump(man, open(MP, "w"), indent=1)
    print(f"accepted: {len(man['functions'])} functions, {len(review)} reviewed changes recorded")
    sys.exit(0)
for b in bad:
    print("EFFECT", b)
for r in review:
    print("REVIEW", r)
print(f"effect sites: {sum(found.values())} found, {sum(expected.values())} classified "
      f"({tally['CLOSED']} closed, {tally['CONTINUATION']} continuation, {tally['EXCEPTION']} exception, "
      f"{tally['OPEN']} open); {len(review)} changes awaiting review")
sys.exit(1 if bad or review else 0)
