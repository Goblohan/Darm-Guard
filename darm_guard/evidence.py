"""darm-guard audit and darm-guard report: the broker's evidence, read back.

audit  checks a broker's evidence the way an outside auditor would: the audit log's hash
       chain, then, given the principal's config and registry, every governed file against
       the log, using only the public key. It changes nothing, and exits non-zero on any finding.
report says what the agent tried and what happened, request by request, from the log alone:
       each request's tool, its path or URL, the decision, the effect and the reason.
"""
import collections, hashlib, json, os, sys

from . import broker as B


def _entries(audit_path):
    with open(audit_path) as f:
        return [json.loads(l) for l in f if l.strip()]


def chain_problems(audit_path) -> list:
    """Every place the hash chain does not hold, by entry number; [] if it is intact."""
    problems, prev = [], "0" * 64
    for n, e in enumerate(_entries(audit_path), 1):
        h = e.pop("entry_hash", None)
        if e.get("prev_hash") != prev:
            problems.append(f"entry {n}: does not follow the entry before it")
        if hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
            problems.append(f"entry {n}: its contents do not match its hash")
        prev = h
    return problems


def audit(audit_path, config=None, registry=None, pub=None) -> int:
    print(f"Auditing {audit_path}")
    problems = chain_problems(audit_path)
    n = len(_entries(audit_path))
    if problems:
        print(f"  hash chain: BROKEN ({len(problems)} problem{'s' if len(problems) != 1 else ''} in {n} entries)")
        for p in problems[:20]:
            print("    " + p)
    else:
        print(f"  hash chain: intact, {n} entries")
    findings = []
    if config and registry:
        pub = pub or audit_path + ".pub.json"
        if not os.path.exists(pub):
            print(f"  workspace: not checked: no public key at {pub}")
            return 1
        cfg = B.BrokerConfig.load(config, registry)
        keys = B.Keys(B.KeyRing.load(None, pub))           # the public key only: nothing here can sign
        v = B.verify_world(cfg, audit_path, keys)
        findings = v["findings"]
        if v["ok"]:
            print(f"  workspace: every governed file matches the log ({cfg.workspace}), checked with the public key alone")
        else:
            print(f"  workspace: {len(findings)} findings")
            for f in findings[:50]:
                print(f"    {f['target']}: {f['finding']}")
    else:
        print("  workspace: not checked (give --config and --registry to check every governed file)")
    ok = not problems and not findings
    print("RESULT: the evidence holds" if ok else "RESULT: the evidence does not hold; see above")
    return 0 if ok else 1


def _what(p: dict, rec: dict) -> str:
    """The path or URL a request named, from its proposal summary, else from its record."""
    for k, v in (p or {}).get("args", []):
        if k in ("path", "url") and isinstance(v, str):
            dest = [d for kk, d in p["args"] if kk == "destination" and isinstance(d, str)]
            return v + (f" -> {dest[0]}" if dest else "")
    return rec.get("url") or rec.get("target") or ""


def report(audit_path, as_json=False) -> int:
    reqs = collections.OrderedDict()
    for e in _entries(audit_path):
        rid = e.get("request_id")
        if not rid:
            continue
        r = reqs.setdefault(rid, {"ts": e.get("ts"), "tool": None, "what": "", "decision": None,
                                  "effect": None, "reason": None, "extra_fields": None})
        p = e.get("proposal")
        if p:
            r["tool"] = r["tool"] or p.get("tool")
            r["what"] = r["what"] or _what(p, e)
            r["extra_fields"] = r["extra_fields"] or p.get("extra_fields")
        r["tool"] = r["tool"] or e.get("tool")
        r["what"] = r["what"] or e.get("url") or e.get("target") or ""
        if e.get("event") in ("decision", "duplicate", "prepared", "outcome", "reconciled"):
            r["decision"] = e.get("decision") or r["decision"]
            r["effect"] = e.get("effect") or e.get("verdict") or r["effect"]
            r["reason"] = e.get("failure") or e.get("error") or r["reason"]
    rows = list(reqs.values())
    if as_json:
        print(json.dumps(rows, indent=1))
        return 0
    print(f"What the agent tried, from {audit_path}: {len(rows)} requests\n")
    for r in rows:
        mark = "admitted" if r["decision"] == "admit" else "REFUSED " if r["decision"] == "reject" else (r["decision"] or "?")
        what = r["what"] or "(no path or URL)"
        extra = f"  [sent extra fields: {', '.join(r['extra_fields'])}]" if r["extra_fields"] else ""
        reason = f"  ({r['reason']})" if r["reason"] else ""
        print(f"  {(r['ts'] or '')[:19]}  {mark}  {r['tool'] or '?':12} {what}  -> {r['effect'] or '?'}{reason}{extra}")
    refused = [r for r in rows if r["decision"] == "reject"]
    print(f"\n{len(rows) - len(refused)} admitted, {len(refused)} refused")
    for reason, k in collections.Counter(r["reason"] or "?" for r in refused).most_common():
        print(f"  refused for {reason}: {k}")
    return 0
