"""DARM Verify adapter for Agent-Airlock (sattyamjjain/agent-airlock), probed against 0.10.7.

Probe-confirmed mapping only. Authority goes through a PolicyResolver fed
by the caller identity in the first argument, because on the decorator
path SecurityPolicy.allowed_roles is not applied (see the private finding).
Exact values map to Literal types, path prefixes to FilesystemPolicy roots,
keys without a rule to unknown_args=BLOCK. Expiry and provenance have no
Airlock counterpart and are declined. Airlock checks resolved paths, so it
blocks traversal that the kernel's string-prefix rule alone would pass.
"""
import inspect
import os
from pathlib import Path
from typing import Any, Literal, Optional

from ..verify import Verdict

ROOT = "/tmp/darmv"
WS, PUB = ROOT + "/ws/", ROOT + "/pub/"
PATHS = [ROOT + "/ws/a.txt", ROOT + "/pub/b.txt", ROOT + "/etc/p.txt", ROOT + "/ws/../etc/p.txt"]
EMAILS = ["alice@corp.example", "bob@corp.example", "mallory@evil.example"]


def _ensure_files():
    for d in ("ws", "pub", "etc"):
        os.makedirs(f"{ROOT}/{d}", exist_ok=True)
    for p in (ROOT + "/ws/a.txt", ROOT + "/pub/b.txt", ROOT + "/etc/p.txt"):
        if not os.path.exists(p):
            open(p, "w").write("x")


def scenario(rng) -> dict:
    tools = []
    if rng.random() < 0.85:
        tools.append({"tool": "read_doc", "rules": [{"key": "path", "allowedValues": [],
                      "allowedPrefixes": rng.sample([WS, PUB], rng.randint(1, 2))}]})
    if rng.random() < 0.85:
        tools.append({"tool": "send_note", "rules": [{"key": "to",
                      "allowedValues": rng.sample(EMAILS, rng.randint(1, 2)), "allowedPrefixes": []}]})
    cred = {"tools": rng.sample(["read_doc", "send_note"], rng.randint(1, 2)), "expired": False}
    tool = rng.choice(["read_doc", "send_note"]) if rng.random() < 0.9 else "wipe"
    key, pool = ("path", PATHS) if tool == "read_doc" else ("to", EMAILS)
    args = [] if rng.random() < 0.1 else [
        {"key": key, "value": rng.choice(pool),
         "prov": "untrusted" if rng.random() < 0.1 else "authoritative"}]
    if rng.random() < 0.1:
        args.append({"key": "mode", "value": "force", "prov": "authoritative"})
    return {"policy": {"tools": tools}, "credential": cred,
            "invocation": {"tool": tool, "args": args}}


def _decline(reason):
    return Verdict(False, reason, supported=False)


class _Inner:
    def __init__(self, roles):
        self.agent_id, self.roles = "darm-verify", roles


class _Ctx:
    def __init__(self, roles):
        self.context = _Inner(roles)


def _make_tool(name, params):
    def f(*a, **kw):
        return "ran"
    f.__name__ = f.__qualname__ = name
    sig = [inspect.Parameter("ctx", inspect.Parameter.POSITIONAL_ONLY, annotation=Any)]
    sig += [inspect.Parameter(k, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=t)
            for k, t in params.items()]
    f.__signature__ = inspect.Signature(sig)
    f.__annotations__ = {"ctx": Any, **params, "return": str}
    return f


def airlock_adapter(req: dict) -> Verdict:
    try:
        import agent_airlock as aa
    except ImportError:
        return _decline("agent-airlock not installed")
    if req["credential"]["expired"]:
        return _decline("credential expiry (no Airlock counterpart)")
    inv = req["invocation"]
    if any(a["prov"] != "authoritative" for a in inv["args"]):
        return _decline("argument provenance (Airlock has no provenance mechanism)")
    _ensure_files()
    tp = next((t for t in req["policy"]["tools"] if t["tool"] == inv["tool"]), None)
    params, roots = {}, []
    for r in (tp["rules"] if tp else []):
        if r["allowedValues"] and r["allowedPrefixes"]:
            return _decline("rule mixing exact values and prefixes")
        if r["allowedValues"]:
            params[r["key"]] = Optional[Literal[tuple(r["allowedValues"])]]
        elif r["allowedPrefixes"]:
            params[r["key"]] = Optional[str]
            roots += [Path(p) for p in r["allowedPrefixes"]]
        else:
            return _decline("rule allowing no values")
    granted = [t["tool"] for t in req["policy"]["tools"] if t["tool"] in req["credential"]["tools"]]

    def resolver(ctx):
        allowed = granted if "agent" in (ctx.roles or []) else []
        return aa.SecurityPolicy(allowed_tools=allowed, default_deny=True)

    cfg = aa.AirlockConfig(unknown_args=aa.UnknownArgsMode.BLOCK, enable_audit_log=False,
                           filesystem_policy=aa.FilesystemPolicy(allowed_roots=roots) if roots else None)
    fn = aa.Airlock(config=cfg, policy=resolver, return_dict=True)(_make_tool(inv["tool"], params))
    r = fn(_Ctx(["agent"]), **{a["key"]: a["value"] for a in inv["args"]})
    if isinstance(r, dict) and r.get("success"):
        return Verdict(True)
    reason = r.get("block_reason") if isinstance(r, dict) else None
    return Verdict(False, str(reason or "blocked"))
