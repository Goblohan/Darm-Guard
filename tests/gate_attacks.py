"""The effect-surface gate rejects unreviewed changes to the effect surface,
not only new primitives: fourteen attacks on a copy of the repository must each
fail the gate, and three controls (no change; a comment; indentation width) must
pass it, so the gate is neither blind nor indiscriminate. Predictions first."""
import ast, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

def gate(edit=None):
    d = tempfile.mkdtemp(prefix="gate-attack-")
    w = os.path.join(d, "repo")
    shutil.copytree(ROOT, w, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".venv*", "venv", "build", "dist"))
    if edit:
        p = os.path.join(w, "darm_guard", "broker.py")
        t = open(p).read()
        t2 = edit(t)
        assert t2 != t, "the edit changed nothing"
        ast.parse(t2)  # a syntax error is not evidence of semantic change detection
        open(p, "w").write(t2)
    r = subprocess.run([sys.executable, "scripts/check_effect_sites.py"], cwd=w, capture_output=True, text=True)
    shutil.rmtree(d, ignore_errors=True)
    return r.returncode == 0

def once(old, new):
    def f(t):
        assert t.count(old) == 1, f"anchor found {t.count(old)} times: {old[:50]!r}"
        return t.replace(old, new, 1)
    return f

def authorization_witness():
    """Real inventory/checker, synthetic effect, and an observed temporary canary.

    Only indentation changes between the authorized and unconditional versions.
    No broker, kernel, or external service is needed for this regression.
    """
    original = "import os\ndef effect(allowed, path):\n    if allowed:\n        pass\n        os.unlink(path)\n"
    changed = original.replace("        os.unlink(path)", "    os.unlink(path)")
    benign = original.replace("        ", "            ")
    with tempfile.TemporaryDirectory(prefix="gate-structure-") as d:
        root = Path(d)
        for name in ("scripts", "darm_guard", "assurance"):
            (root / name).mkdir()
        for name in ("effect_inventory.py", "check_effect_sites.py"):
            shutil.copyfile(Path(ROOT) / "scripts" / name, root / "scripts" / name)
        source = root / "darm_guard" / "witness.py"
        source.write_text(original)
        inventory = json.loads(subprocess.check_output(
            [sys.executable, "scripts/effect_inventory.py", "darm_guard", "--json"], cwd=root))
        entry = dict(inventory["functions"]["witness.py:effect"],
                     effects={"os.unlink": 1}, verdict="CLOSED",
                     authority="synthetic allowed condition", tests=["darm_guard/witness.py"])
        (root / "assurance" / "effect_sites.json").write_text(
            json.dumps({"functions": {"witness.py:effect": entry}}))
        def accepted():
            return subprocess.run([sys.executable, "scripts/check_effect_sites.py"], cwd=root,
                                  capture_output=True, text=True).returncode == 0
        baseline = accepted()
        canary = root / "canary"
        canary.write_text("temporary witness")
        ns = {}
        exec(compile(original, "<authorized witness>", "exec"), ns)
        ns["effect"](False, str(canary))
        refused = canary.exists()
        source.write_text(benign)
        harmless = accepted()
        source.write_text(changed)
        rejected = not accepted()
        exec(compile(changed, "<unconditional witness>", "exec"), ns)
        ns["effect"](False, str(canary))
        return baseline, harmless, refused and not canary.exists(), rejected

EXEC_ARGS = '    args = {a["key"]: a["value"] for a in inv["args"]}\n    if inv["tool"] == "http_get":\n        return _execute_http(cfg, args)'
attacks = [
 ("indentation moves fsync after its file context has closed",
  once('                os.fsync(f.fileno())\n            conflict = _cas_replace',
       '            os.fsync(f.fileno())\n            conflict = _cas_replace')),
 ("a new route into _execute", lambda t: t + "\n\ndef _sneak(cfg, inv):\n    return _execute(cfg, inv)\n"),
 ("_execute's arguments no longer from inv", once(EXEC_ARGS, EXEC_ARGS.replace('inv["args"]', 'inv.get("raw_args", inv["args"])'))),
 ("an aliased import", lambda t: t + "\n\ndef _wipe(path):\n    import os as _o\n    _o.unlink(path)\n"),
 ("a direct import", lambda t: t + "\n\ndef _wipe2(path):\n    from os import unlink as _u\n    _u(path)\n"),
 ("an effect function bound to a name", lambda t: t + "\n\ndef _wipe3(path):\n    f = os.unlink\n    f(path)\n"),
 ("dynamic access to os", lambda t: t + "\n\ndef _wipe4(path):\n    getattr(os, 'unl' + 'ink')(path)\n"),
 ("_handle no longer refuses before executing", once('            if resp["decision"] != "admit":', '            if False:')),
 ("a helper below the decision changes (normal form accepts anything)",
  once("def path_in_normal_form(value: str) -> bool:\n", "def path_in_normal_form(value: str) -> bool:\n    return True\n")),
 ("a constant a verdict relies on changes (PATH_KEYS loses destination)",
  once('PATH_KEYS = ("path", "destination")', 'PATH_KEYS = ("path",)')),
 ("a route through a thread target", lambda t: t + "\n\ndef _sneak2(cfg, inv):\n    import threading\n    threading.Thread(target=_execute, args=(cfg, inv)).start()\n"),
 ("dynamic evaluation", lambda t: t + "\n\ndef _ev(s):\n    eval(s)\n"),
 ("a network call from a new helper (urllib)",
  lambda t: t + "\n\ndef _phone_home(url):\n    import urllib.request\n    urllib.request.urlopen(url)\n"),
 ("a raw connection from a new helper (socket, aliased)",
  lambda t: t + "\n\ndef _phone_home2(host):\n    import socket as _s\n    _s.create_connection((host, 443))\n"),
]
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
check("authorization witness: baseline and width-only edit pass; behavior differs; dedent rejected",
      authorization_witness(), (True, True, True, True))
check("control: the unmodified code passes the gate", gate(), True)
check("control: a comment inside _execute passes the gate",
      gate(once(EXEC_ARGS, "    # a comment changes no token\n" + EXEC_ARGS)), True)
check("control: indentation width changes without changing the suite pass the gate",
      gate(once(EXEC_ARGS, EXEC_ARGS.replace('        return _execute_http', '            return _execute_http'))), True)
for i, (label, edit) in enumerate(attacks, 1):
    check(f"attack {i}: {label}: rejected", not gate(edit), True)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
