"""DARM Verify: check an authorization gate against the DARM kernel.

A gate under test is wrapped in an adapter: a function that takes a DARM
request (policy, credential, invocation as plain dicts) and returns a
Verdict. Verify generates seeded scenarios, asks both the gate and the
kernel, and reports every disagreement as a reproducible counterexample.

Scope: disagreements are relative to the DARM kernel's semantics AND to
the adapter's translation of each scenario into the gate's own terms. A
divergence can mean a gap in the gate or a limit of the translation;
each is reported with its full scenario so a human can tell which.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Callable, List, Optional

from .kernel import KernelClient


@dataclass(frozen=True)
class Verdict:
    admitted: bool
    reason: Optional[str] = None
    supported: bool = True   # False: the gate cannot express this scenario


Adapter = Callable[[dict], Verdict]

TOOLS = ["read", "send", "exec"]
KEYS = ["k1", "k2"]
VALUES = ["/w/a", "/w/b", "/t/x", "/etc/p", "v1", "v2"]
PREFIXES = ["/w/", "/t/"]
EXACT = ["v1", "v2"]
PROVS = ["authoritative", "derived", "untrusted"]


def _sample(rng, xs, lo, hi):
    return rng.sample(xs, rng.randint(lo, min(hi, len(xs))))


def _gen(rng) -> dict:
    tools = []
    for t in TOOLS:
        if rng.random() < 0.8:
            rules = [{"key": k, "allowedValues": _sample(rng, EXACT, 0, 2),
                      "allowedPrefixes": _sample(rng, PREFIXES, 0, 2)}
                     for k in _sample(rng, KEYS, 0, 2)]
            tools.append({"tool": t, "rules": rules})
    cred = {"tools": _sample(rng, TOOLS, 1, 3), "expired": rng.random() < 0.15}
    tool = rng.choice(TOOLS) if rng.random() < 0.85 else "unknown"
    rules = {r["key"]: r for tp in tools if tp["tool"] == tool for r in tp["rules"]}
    args = []
    for k in _sample(rng, KEYS, 0, 2):
        r = rules.get(k)
        choices = (r["allowedValues"] + [x + "f" for x in r["allowedPrefixes"]]) if r else []
        v = rng.choice(choices) if choices and rng.random() < 0.7 else rng.choice(VALUES)
        args.append({"key": k, "value": v, "prov": rng.choice(PROVS)})
    return {"policy": {"tools": tools}, "credential": cred,
            "invocation": {"tool": tool, "args": args}}


def scenarios(n: int, seed: int) -> List[dict]:
    rng = random.Random(seed)
    return [_gen(rng) for _ in range(n)]


# ---- Built-in adapters -------------------------------------------------

def allow_all(req: dict) -> Verdict:
    """Baseline: admits everything. Every kernel rejection is a false admit."""
    return Verdict(True)


def darmguard_v01(req: dict) -> Verdict:
    """DARM Guard v0.1 (tool-name only), in GOVERN mode.
    Translation: policy tools -> authorized_tools; expiry emulated via TTL."""
    from .guard import DARMGuard, Mode
    from .types import Credential, Policy
    cred = req["credential"]
    g = DARMGuard(
        policy=Policy(authorized_tools=frozenset(t["tool"] for t in req["policy"]["tools"])),
        credential=Credential(
            tools=frozenset(cred["tools"]),
            issued_at=datetime(2000, 1, 1) if cred["expired"] else None,
            ttl=timedelta(seconds=1) if cred["expired"] else None),
        mode=Mode.GOVERN)
    g._stderr_alerts = False
    r = g.check({req["invocation"]["tool"]})
    return Verdict(r.admitted, r.failures[0].kind.name.lower() if r.failures else None)


def _agentlock(req: dict) -> Verdict:
    from .adapters.agentlock_adapter import agentlock_adapter
    return agentlock_adapter(req)


def _agentlock_scenario(rng) -> dict:
    from .adapters.agentlock_adapter import scenario
    return scenario(rng)


def _airlock(req: dict) -> Verdict:
    from .adapters.airlock_adapter import airlock_adapter
    return airlock_adapter(req)


def _airlock_scenario(rng) -> dict:
    from .adapters.airlock_adapter import scenario
    return scenario(rng)


ADAPTERS = {"allow-all": allow_all, "darmguard-v0.1": darmguard_v01,
            "agentlock": _agentlock, "agent-airlock": _airlock}
GENERATORS = {"agentlock": _agentlock_scenario, "agent-airlock": _airlock_scenario}   # gate-specific scenario sets


# ---- Report ------------------------------------------------------------

@dataclass
class Divergence:
    index: int
    kind: str      # "false_admit" (gate admits, kernel rejects) or "false_reject"
    kernel: str    # "admit" or the kernel's failure kind
    gate: str      # "admit" or the gate's stated reason
    request: dict


@dataclass
class Report:
    adapter: str
    n: int
    seed: int
    agree: int = 0
    unsupported: Counter = field(default_factory=Counter)
    divergences: List[Divergence] = field(default_factory=list)

    def summary(self) -> str:
        fa = Counter(d.kernel for d in self.divergences if d.kind == "false_admit")
        fr = Counter(d.gate for d in self.divergences if d.kind == "false_reject")
        out = [f"DARM Verify: {self.adapter} vs DARM kernel "
               f"({self.n} scenarios, seed {self.seed})",
               f"  agree           {self.agree}",
               f"  not expressible {sum(self.unsupported.values())}   (excluded from comparison)"]
        out += [f"      reason: {k}  {v}" for k, v in sorted(self.unsupported.items())]
        out += [
               f"  false admits    {sum(fa.values())}   (gate admits, kernel rejects)"]
        out += [f"      kernel: {k:12s} {v}" for k, v in sorted(fa.items())]
        out.append(f"  false rejects   {sum(fr.values())}   (gate rejects, kernel admits)")
        out += [f"      gate:   {k:12s} {v}" for k, v in sorted(fr.items())]
        return "\n".join(out)

    def to_json(self) -> str:
        return json.dumps({"adapter": self.adapter, "n": self.n, "seed": self.seed,
                           "agree": self.agree,
                           "not_expressible": dict(self.unsupported),
                           "divergences": [asdict(d) for d in self.divergences]}, indent=2)


# ---- Comparison --------------------------------------------------------

def verify(name: str, adapter: Adapter, n: int = 1000, seed: int = 20260922,
           kernel: Optional[KernelClient] = None, generator=None) -> Report:
    """Run n seeded scenarios through the gate and the kernel; record disagreements.
    Stops if the kernel itself errors: with no referee, no verdict is reported."""
    kernel = kernel or KernelClient()
    rep = Report(name, n, seed)
    gen_fn, rng = generator or _gen, random.Random(seed)
    for i in range(n):
        req = gen_fn(rng)
        g = adapter(req)
        if not g.supported:
            rep.unsupported[g.reason or "unspecified"] += 1
            continue
        k = kernel.decide(req)
        if k.error:
            raise RuntimeError(f"kernel error on scenario {i}: {k.error}")
        if g.admitted == k.admitted:
            rep.agree += 1
            continue
        rep.divergences.append(Divergence(
            index=i,
            kind="false_admit" if g.admitted else "false_reject",
            kernel="admit" if k.admitted else (k.failure or "reject"),
            gate="admit" if g.admitted else (g.reason or "reject"),
            request=req))
    return rep


def main() -> None:
    ap = argparse.ArgumentParser(prog="darm-verify",
        description="Check an authorization gate against the DARM kernel.")
    ap.add_argument("--adapter", default="darmguard-v0.1", choices=sorted(ADAPTERS))
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=20260922)
    ap.add_argument("--json", help="write the full report, with every scenario, to this file")
    ap.add_argument("--fail-on-false-admit", action="store_true",
                    help="exit 1 if the gate admits anything the kernel rejects")
    a = ap.parse_args()
    try:
        rep = verify(a.adapter, ADAPTERS[a.adapter], a.n, a.seed,
                     generator=GENERATORS.get(a.adapter))
    except RuntimeError as e:
        print(f"darm-verify: {e}", file=sys.stderr)
        sys.exit(2)
    print(rep.summary())
    if a.json:
        open(a.json, "w").write(rep.to_json())
        print(f"full report: {a.json}")
    if a.fail_on_false_admit and any(d.kind == "false_admit" for d in rep.divergences):
        sys.exit(1)


if __name__ == "__main__":
    main()
