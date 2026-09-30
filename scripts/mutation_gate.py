#!/usr/bin/env python3
"""Mutation gate: disable one broker check at a time and require the full gate
to FAIL. A mutation the gate survives is a check whose removal no test notices.

Each mutation is applied in a throwaway clone and committed there only; the
clone's scripts/ci_local.py then runs the gate on that mutated tree, in its own
private environment. The working repository is never modified.
Slow (one full gate run per mutation): run by hand, not on every push.
Usage: scripts/mutation_gate.py [name ...]   (default: all mutations)"""
import os, shutil, subprocess, sys, tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BROKER = "darm_guard/broker.py"

LIFT = '''

def _mut_lift(policy, inv):
    """MUTATION: deny-by-default lifted: rule every argument key."""
    import copy
    policy = copy.deepcopy(policy)
    for t in policy["tools"]:
        if t["tool"] == inv["tool"]:
            ruled = {r["key"] for r in t["rules"]}
            for a in inv["args"]:
                if a["key"] not in ruled:
                    t["rules"].append({"key": a["key"], "allowedValues": [], "allowedPrefixes": [""],
                                       "payload": False})
                    ruled.add(a["key"])
    return policy
'''
OPEN = '''

def _mut_open(policy):
    """MUTATION: value rules off: every rule allows any value."""
    import copy
    policy = copy.deepcopy(policy)
    for t in policy["tools"]:
        for r in t["rules"]:
            r["allowedPrefixes"] = [""]
    return policy
'''

MUTATIONS = {
    "expiry ignored": [('"expired": self.cfg.expired(now)},', '"expired": False},')],
    "credential check off": [('"credential": {"tools": list(self.cfg.credential_tools),',
                              '"credential": {"tools": list(self.cfg.credential_tools) + [tool],')],
    "deny-by-default lifted": [('request = {"policy": self.cfg.policy,',
                                'request = {"policy": _mut_lift(self.cfg.policy, inv),'), ("<append>", LIFT)],
    "value rules off": [('request = {"policy": self.cfg.policy,',
                         'request = {"policy": _mut_open(self.cfg.policy),'), ("<append>", OPEN)],
    "provenance always trusted": [('    if value in registry:\n        return "authoritative"',
                                   '    return "authoritative"\n    if value in registry:\n        return "authoritative"')],
    "intents ignored": [('fitting = [i for i in self.intents if _intent_fits(i, tool, args)]',
                         'fitting = list(self.intents)')],
    "path check off": [('if a is None or a.get("target") != logical:', 'if a is None:')],
    "log freshness off": [('elif logical in latest and latest[logical][1] == "delete":', 'elif False:'),
                          ('elif logical in latest and latest[logical][0] != a["rid"]:', 'elif False:')],
    "request identifier from the path": [('rid = uuid.uuid4().hex',
        'rid = hashlib.sha256(repr([a for a in obj.get("args", []) if isinstance(a, list) and a[:1] == ["path"]]).encode()).hexdigest()[:32] if isinstance(obj, dict) else uuid.uuid4().hex')],
    "premises ignored": [('next((i for i in fitting if _premise_problem(self.cfg, i) is None), None)',
                          'next((i for i in fitting), None)')],
}


def mutate(src, edits):
    for old, new in edits:
        if old == "<append>":
            src += new
            continue
        if src.count(old) != 1:
            raise SystemExit(f"anchor not found exactly once: {old[:60]!r}")
        src = src.replace(old, new, 1)
    return src


names = sys.argv[1:] or list(MUTATIONS)
survived = []
for name in names:
    work = tempfile.mkdtemp(prefix="darm-mut-")
    clone = os.path.join(work, "repo")
    subprocess.run(["git", "clone", "-q", REPO, clone], check=True)
    path = os.path.join(clone, BROKER)
    mutated = mutate(open(path).read(), MUTATIONS[name])   # read BEFORE opening for write:
    open(path, "w").write(mutated)                        # "w" truncates the file immediately
    subprocess.run(["git", "-C", clone, "-c", "user.name=mutation", "-c", "user.email=m@local",
                    "commit", "-qam", f"MUTATION: {name}"], check=True)
    r = subprocess.run([sys.executable, os.path.join(clone, "scripts", "ci_local.py")],
                       capture_output=True, text=True)
    out = r.stdout.splitlines()
    first_fail = next((l.replace("FAILED", "").strip() for l in out if l.startswith("FAILED")), None)
    if r.returncode != 0 and first_fail:
        print(f"CAUGHT    {name:28s} first failing step: {first_fail}")
    elif r.returncode != 0:
        print(f"ERROR     {name:28s} the run failed without a failing step:\n{(r.stdout + r.stderr)[-800:]}")
        survived.append(name)
    else:
        print(f"SURVIVED  {name:28s} the whole gate passed with this check disabled")
        survived.append(name)
    shutil.rmtree(work, ignore_errors=True)

print(f"\n{len(names) - len(survived)}/{len(names)} mutations caught")
sys.exit(1 if survived else 0)
