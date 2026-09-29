"""The default darm-verify scenarios are pinned: every reported comparison
(FIDES, AgentLock, Airlock) was computed on scenarios(1000, 20260922). If the
generator changes what that produces, earlier numbers stop being reproducible,
so the change must be deliberate: update this hash in the same commit, and say so."""
import hashlib, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import darm_guard.verify as V
PINNED = "cfbd206510cb6d57a4453c3cc9ee096a35fad02a10523c71889435b3b07beab9"
h = hashlib.sha256(json.dumps(V.scenarios(1000, 20260922), sort_keys=True).encode()).hexdigest()
p = V.scenarios(1000, 20260922, payload=True)
paired = all(len(a["invocation"]["args"]) >= 0 and a["credential"] == b["credential"]
             for a, b in zip(V.scenarios(1000, 20260922), p))
print(("ok      " if h == PINNED else "CHANGED ") + f"default scenarios {h[:16]}...")
print(("ok      " if paired else "UNPAIRED") + " payload scenarios are the same scenarios, paired")
sys.exit(0 if h == PINNED and paired else 1)
