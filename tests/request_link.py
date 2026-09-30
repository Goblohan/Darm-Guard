"""E28's request link at runtime: each request identifier is minted for one
invocation, and an attested file leads back, through its identifier, to the
invocation that intended exactly its content (darm-monitor E28:
ExecutedUnder, authorized_effect_to_attested_state). Predictions first."""
import collections, hashlib, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
AUDIT = f"{D}/reqlink.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".lock"):
    if os.path.exists(f): os.remove(f)
keys = B.Keys.generate()
b = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, keys)
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

sent = []                                   # (path, content, request_id)
for rnd in (1, 2):
    for i in range(10):
        path, content = f"/workspace/reports/rl{i}.md", f"round {rnd}, file {i}"
        r = b.handle({"tool": "write_file", "args": [["path", path], ["content", content]]})
        sent.append((path, content, r.get("request_id")))
records = [json.loads(l) for l in open(AUDIT) if l.strip()]

rids = [s[2] for s in sent]
check("1. every request has its own identifier", (len(rids), len(set(rids)), None in rids), (20, 20, False))

hashes = collections.defaultdict(set)
for e in records:
    if e.get("request_id") and e.get("invocation_hash"):
        hashes[e["request_id"]].add(e["invocation_hash"])
check("2. each identifier belongs to one invocation", all(len(v) == 1 for v in hashes.values()) and len(hashes) == 20, True)

prepared = {e["request_id"]: e for e in records if e.get("event") == "prepared"}
same_path = [(prepared[a[2]]["invocation_hash"], prepared[b_[2]]["invocation_hash"])
             for a, b_ in zip(sent[:10], sent[10:])]
check("3. same path, different content: different invocations", all(x != y for x, y in same_path), True)

linked = 0
for path, content, rid in sent[10:]:
    real = R + "/" + path.rsplit("/", 1)[1]
    att = B._check_attestation(keys, os.getxattr(real, B.XATTR))
    digest = hashlib.sha256(open(real, "rb").read()).hexdigest()
    p = prepared.get(att["rid"], {})
    if (att["rid"] == rid and p.get("target") == path and p.get("intended_state") == ["present", digest]
            and digest == hashlib.sha256(content.encode()).hexdigest()):
        linked += 1
check("4. each attested file leads back to the invocation that intended exactly its content", linked, 10)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
