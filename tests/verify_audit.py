import hashlib, json, sys
path = sys.argv[1] if len(sys.argv) > 1 else "darm-broker-audit.jsonl"
prev, n = "0" * 64, 0
for line in open(path):
    e = json.loads(line)
    h = e.pop("entry_hash")
    if e["prev_hash"] != prev:
        sys.exit(f"chain broken at entry {n}")
    if hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
        sys.exit(f"entry {n} was altered")
    prev, n = h, n + 1
print(f"audit chain intact: {n} entries")
