"""The effect-surface gate rejects unreviewed changes to the effect surface,
not only new primitives: seven attacks on a copy of the repository must each
fail the gate, and two controls (no change; a comment inside _execute) must
pass it, so the gate is neither blind nor indiscriminate. Predictions first."""
import os, shutil, subprocess, sys, tempfile
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
        open(p, "w").write(t2)
    r = subprocess.run([sys.executable, "scripts/check_effect_sites.py"], cwd=w, capture_output=True, text=True)
    shutil.rmtree(d, ignore_errors=True)
    return r.returncode == 0

def once(old, new):
    def f(t):
        assert t.count(old) == 1, f"anchor found {t.count(old)} times: {old[:50]!r}"
        return t.replace(old, new, 1)
    return f

EXEC_ARGS = '    args = {a["key"]: a["value"] for a in inv["args"]}\n    opened = _open_parent(cfg, args.get("path", ""))'
attacks = [
 ("a new route into _execute", lambda t: t + "\n\ndef _sneak(cfg, inv):\n    return _execute(cfg, inv)\n"),
 ("_execute's arguments no longer from inv", once(EXEC_ARGS, EXEC_ARGS.replace('inv["args"]', 'inv.get("raw_args", inv["args"])'))),
 ("an aliased import", lambda t: t + "\n\nimport os as _o\ndef _wipe(path):\n    _o.unlink(path)\n"),
 ("a direct import", lambda t: t + "\n\nfrom os import unlink as _u\ndef _wipe2(path):\n    _u(path)\n"),
 ("an effect function bound to a name", lambda t: t + "\n\ndef _wipe3(path):\n    f = os.unlink\n    f(path)\n"),
 ("dynamic access to os", lambda t: t + "\n\ndef _wipe4(path):\n    getattr(os, 'unl' + 'ink')(path)\n"),
 ("_handle no longer refuses before executing", once('            if resp["decision"] != "admit":', '            if False:')),
]
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
check("control: the unmodified code passes the gate", gate(), True)
check("control: a comment inside _execute passes the gate",
      gate(once(EXEC_ARGS, "    # a comment changes no token\n" + EXEC_ARGS)), True)
for i, (label, edit) in enumerate(attacks, 1):
    check(f"attack {i}: {label}: rejected", not gate(edit), True)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
