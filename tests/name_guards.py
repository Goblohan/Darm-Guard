"""Two guards from asking where the kernel reads a name and the file system acts on what it resolves
to. A file with more than one name (a hard link) is refused for reads and writes, since the policy
covers one name and the file is reachable by others. And a registry line may name a tool
('read_file /workspace/notes.txt'), vouching for the value for that tool only, so registering a
file for reading no longer vouches for writing it; untagged lines vouch for every tool, as before.
Predictions first."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

def setup(registry, write_prefix="/workspace/"):
    d = tempfile.mkdtemp(prefix="names-"); ws = os.path.join(d, "workspace")
    for sub in ("reports", "secrets"):
        os.makedirs(os.path.join(ws, sub))
    open(os.path.join(ws, "secrets", "key.txt"), "w").write("TOP SECRET")
    open(os.path.join(ws, "notes.txt"), "w").write("notes")
    open(os.path.join(ws, "shared.txt"), "w").write("shared")
    json.dump({"policy": {"tools": [
        {"tool": "read_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/"]}]},
        {"tool": "write_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": [write_prefix]},
                                         {"key": "content", "allowedValues": [], "allowedPrefixes": [""], "payload": True}]}]},
        "credential_tools": ["read_file", "write_file"], "workspace": ws}, open(os.path.join(d, "c.json"), "w"))
    open(os.path.join(d, "r.txt"), "w").write(registry)
    cfg = B.BrokerConfig.load(os.path.join(d, "c.json"), os.path.join(d, "r.txt"))
    return B.Broker(cfg, KernelClient(), B.AuditLog(os.path.join(d, "audit.jsonl"))), ws, d

read = lambda b, p: b.handle({"tool": "read_file", "args": [["path", p]]})
write = lambda b, p, c: b.handle({"tool": "write_file", "args": [["path", p], ["content", c]]})

print("files with more than one name")
b, ws, _ = setup("/workspace/reports/*\n")
os.link(os.path.join(ws, "secrets", "key.txt"), os.path.join(ws, "reports", "link.md"))
open(os.path.join(ws, "reports", "plain.md"), "w").write("plain")
r = read(b, "/workspace/reports/link.md")
check("reading a hard-linked file: refused, and nothing read", (r.get("effect"), "more than one name" in (r.get("error") or ""), "TOP SECRET" in json.dumps(r)), ("failed", True, False))
check("reading an ordinary file: unaffected", read(b, "/workspace/reports/plain.md").get("content"), "plain")
r = write(b, "/workspace/reports/link.md", "replaced")
check("writing a hard-linked file's name: refused", "more than one name" in (r.get("error") or ""), True)
check("and the other name's contents are untouched", open(os.path.join(ws, "secrets", "key.txt")).read(), "TOP SECRET")
check("writing an ordinary file: unaffected", write(b, "/workspace/reports/new.md", "x").get("effect"), "succeeded")

print("\nregistry lines naming a tool")
b, ws, _ = setup("read_file /workspace/notes.txt\nwrite_file /workspace/reports/*\n/workspace/shared.txt\n")
check("notes.txt, registered for read_file: readable", read(b, "/workspace/notes.txt").get("content"), "notes")
r = write(b, "/workspace/notes.txt", "overwritten")
check("notes.txt, registered for read_file: not writable", (r.get("decision"), open(os.path.join(ws, "notes.txt")).read()), ("reject", "notes"))
check("reports/*, registered for write_file: writable", write(b, "/workspace/reports/q3.md", "q3").get("effect"), "succeeded")
check("reports/*, registered for write_file: not readable", read(b, "/workspace/reports/q3.md").get("decision"), "reject")
check("an untagged line vouches for every tool, as before",
      (read(b, "/workspace/shared.txt").get("content"), write(b, "/workspace/shared.txt", "s2").get("effect")), ("shared", "succeeded"))
for bad, why in (("remove_file /workspace/x\n", "the tool 'remove_file', which the policy does not have"),
                 ("write_file /workspace/reports*\n", "does not end at a component boundary")):
    try:
        setup(bad); got = "loaded"
    except ValueError as e:
        got = why in str(e)
    check(f"{bad.strip()!r}: refused at load", got, True)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
