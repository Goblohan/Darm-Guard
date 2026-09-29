"""Coverage map: which dimensions a gate checks.

Start from one request every check passes, change it in exactly one dimension
at a time (so only that dimension can refuse it), and run each case through the
gate under test. The kernel self-checks every case first: each must be refused
in exactly its own dimension (the payload case admitted), or the map says so
rather than report a misleading coverage.

For an adopter this answers the practical question from the composition
experiment: whatever an existing defense does not check, DARM must carry alone.
Usage: darm-coverage ADAPTER   (a built-in adapter name, 'kernel', or module:function)"""
import copy, dataclasses, importlib, sys
from typing import Callable, List, Tuple

from .kernel import KernelClient
from .verify import Verdict


def _base() -> dict:
    return {"policy": {"tools": [{"tool": "send", "rules": [
                {"key": "to", "allowedValues": ["alice"], "allowedPrefixes": []},
                {"key": "body", "allowedValues": [], "allowedPrefixes": [""], "payload": True}]}]},
            "credential": {"tools": ["send"], "expired": False},
            "invocation": {"tool": "send", "args": [
                {"key": "to", "value": "alice", "prov": "authoritative"},
                {"key": "body", "value": "hi", "prov": "authoritative"}]}}


def _edit(f) -> dict:
    r = _base()
    f(r)
    return r


def _arg(r, k):
    return next(a for a in r["invocation"]["args"] if a["key"] == k)


def _unknown_tool(r):
    r["invocation"]["tool"] = "exfiltrate"
    r["credential"]["tools"].append("exfiltrate")    # credentialed, so only observation can refuse


def cases() -> List[Tuple[str, dict, str]]:
    """(name, request, expected kernel outcome): a failure class, or 'admit'."""
    return [
        ("control (every check passes)", _base(), "admit"),
        ("authority", _edit(lambda r: r["credential"].update(tools=[])), "authority"),
        ("temporal", _edit(lambda r: r["credential"].update(expired=True)), "temporal"),
        ("observation", _edit(_unknown_tool), "observation"),
        ("semantic: unruled argument", _edit(lambda r: r["invocation"]["args"].append(
            {"key": "cc", "value": "alice", "prov": "authoritative"})), "semantic"),
        ("semantic: value outside its rule", _edit(lambda r: _arg(r, "to").update(value="mallory")), "semantic"),
        ("provenance", _edit(lambda r: _arg(r, "to").update(prov="untrusted")), "provenance"),
        ("payload role (untrusted payload)", _edit(lambda r: _arg(r, "body").update(prov="untrusted")), "admit"),
    ]


def _admitted(v) -> bool:
    return bool(getattr(v, dataclasses.fields(v)[0].name))


def coverage(adapter: Callable[[dict], Verdict], kernel=None) -> List[dict]:
    kernel = kernel or KernelClient()
    rows = []
    for name, req, expected in cases():
        kd = kernel.decide(copy.deepcopy(req))
        kernel_ok = kd.admitted if expected == "admit" else (not kd.admitted and kd.failure == expected)
        v = adapter(copy.deepcopy(req))
        if getattr(v, "supported", True) is False:
            verdict = "not expressible"
        elif name.startswith("control"):
            verdict = "admits" if _admitted(v) else "REFUSES (coverage inconclusive)"
        elif name.startswith("payload"):
            verdict = "argument-aware (admits)" if _admitted(v) else "per-call (refuses)"
        else:
            verdict = "covers" if not _admitted(v) else "MISSES"
        rows.append({"case": name, "expected": expected,
                     "kernel": "ok" if kernel_ok else f"SELF-CHECK FAILED ({kd.admitted}, {kd.failure})",
                     "gate": verdict})
    return rows


def kernel_adapter(req: dict) -> Verdict:
    d = KernelClient().decide(req)
    return Verdict(d.admitted, None if d.admitted else f"kernel: {d.failure}")


def resolve(name: str):
    if name == "kernel":
        return kernel_adapter
    if ":" in name:
        mod, fn = name.split(":", 1)
        return getattr(importlib.import_module(mod), fn)
    from . import verify
    return getattr(verify, name)


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1]); sys.exit(2)
    rows = coverage(resolve(sys.argv[1]))
    print(f"{'case':36s} {'kernel':8s} gate")
    for r in rows:
        print(f"{r['case']:36s} {r['kernel'][:8]:8s} {r['gate']}")
    covered = [r["case"] for r in rows if r["gate"] == "covers"]
    missed = [r["case"] for r in rows if r["gate"] == "MISSES"]
    print(f"\ncovers: {', '.join(covered) or 'nothing'}")
    print(f"misses: {', '.join(missed) or 'nothing'}  (these rest on DARM alone)")
    sys.exit(1 if any(r["kernel"] != "ok" for r in rows) else 0)


if __name__ == "__main__":
    main()
