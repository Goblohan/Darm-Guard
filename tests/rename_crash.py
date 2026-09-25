"""rename_file, step 4b: a crash after each B9 phase, then a restart.
Predictions from B9's recover: after the claim, roll back; after the
re-attestation, roll forward; after the place, nothing to move."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; R = f"{WS}/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
class Crash(BaseException):
    pass

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

def case(label, hook_name, crash_on_call, verdict, where):
    audit = f"{D}/crash_{hook_name}_{crash_on_call}.jsonl"
    for f in (audit, audit + ".key", audit + ".lock"):
        if os.path.exists(f):
            os.remove(f)
    key = os.urandom(32)
    b = B.Broker(cfg, KernelClient(), B.AuditLog(audit), None, None, key)
    src, dst = f"c{crash_on_call}{hook_name[1]}src.md", f"c{crash_on_call}{hook_name[1]}dst.md"
    assert b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + src],
                                                    ["content", "survives"]]})["effect"] == "succeeded"
    orig, calls = getattr(B, hook_name), [0]
    def hooked(*a, **kw):
        out = orig(*a, **kw)
        calls[0] += 1
        if calls[0] == crash_on_call:
            raise Crash()
        return out
    setattr(B, hook_name, hooked)
    try:
        b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/" + src],
                                                  ["destination", "/workspace/reports/" + dst]]})
        crashed = False
    except Crash:
        crashed = True
    finally:
        setattr(B, hook_name, orig)
    kfd = os.open(audit + ".key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(kfd, key); os.close(kfd)
    srv = B.serve(cfg, f"/tmp/darm-{hook_name}{crash_on_call}.sock", audit)
    srv.server_close()
    verdicts = [e.get("reconciliation") for e in map(json.loads, open(audit)) if e.get("event") == "reconciled"]
    here = [n for n in (src, dst) if os.path.exists(f"{R}/{n}")]
    print(label)
    check("crashed before the outcome", crashed, True)
    check("verdict", verdicts, [verdict])
    check("the file is at", here, [src if where == "src" else dst])
    check("content intact", open(f"{R}/{here[0]}").read() if here else None, "survives")
    check("no private file left", [n for n in os.listdir(R) if ".darm-tmp-" in n], [])
    fs = [x["finding"] for x in B.verify_world(cfg, audit, key)["findings"]
          if x["target"] in ("/workspace/reports/" + src, "/workspace/reports/" + dst)]
    check("both paths verify clean", fs, [])

case("1. crash after the claim",        "_renameat2", 1, "confirmedFailure", "src")
case("2. crash after the re-attestation", "_set_att",  1, "confirmedSuccess", "dst")
case("3. crash after the place",        "_renameat2", 2, "confirmedSuccess", "dst")

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
