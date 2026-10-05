"""Prefixes must end at a component boundary. The kernel matches a prefix as a string, while the
file system and the HTTP client read paths and URLs by components, so a prefix ending inside a
component admits siblings: '/workspace/reports' also matches '/workspace/reports-private/', and
'https://127.0.0.1' also matches 'https://127.0.0.10/'. The broker refuses such a configuration
when it loads, and says what the prefix would also admit. Predictions first."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import darm_guard.broker as B

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

d = tempfile.mkdtemp(); ws = os.path.join(d, "workspace"); os.makedirs(ws)
def load(path_prefixes, url_prefixes, registry):
    cfg = {"policy": {"tools": [
        {"tool": "write_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": path_prefixes},
                                         {"key": "content", "allowedValues": [], "allowedPrefixes": ["", "x"], "payload": True}]},
        {"tool": "http_get", "rules": [{"key": "url", "allowedValues": [], "allowedPrefixes": url_prefixes}]}]},
        "credential_tools": ["write_file", "http_get"], "workspace": ws}
    json.dump(cfg, open(os.path.join(d, "c.json"), "w")); open(os.path.join(d, "r.txt"), "w").write(registry)
    try:
        B.BrokerConfig.load(os.path.join(d, "c.json"), os.path.join(d, "r.txt")); return "loaded"
    except ValueError as e:
        return str(e)

ok = load(["/workspace/reports/", ""], ["https://api.example.com/v1/", ""], "/workspace/reports/*\nhttps://api.example.com/v1/*\n/workspace/notes.txt\n")
check("prefixes ending at a separator, empty prefixes and exact values: loaded", ok, "loaded")
r = load(["/workspace/reports"], ["https://api.example.com/v1/"], "/workspace/reports/*\n")
check("path prefix '/workspace/reports': refused, naming a sibling it would admit",
      ("refused" in r, "'/workspace/reports'" in r, "reports-other" in r), (True, True, True))
r = load(["/workspace/reports/"], ["https://127.0.0.1"], "")
check("URL prefix 'https://127.0.0.1': refused", ("refused" in r, "'https://127.0.0.1'" in r), (True, True))
r = load(["/workspace/reports/"], ["https://api.example.com/v1"], "")
check("URL prefix ending inside a path component: refused", "refused" in r, True)
r = load(["/workspace/reports/"], ["https://API.example.com/"], "")
check("URL prefix not in normal form: refused", "refused" in r, True)
r = load(["/workspace/reports/"], ["https://api.example.com/v1/"], "/workspace/reports*\nhttps://127.0.0.1*\n")
check("registry patterns ending inside a component: both refused, both named",
      ("'/workspace/reports*'" in r, "'https://127.0.0.1*'" in r), (True, True))
r = load(["/workspace/a", "/workspace/b/"], ["https://x.example.com"], "/workspace/c*\n")
check("every problem reported at once, not only the first", r.count("does not end at a component boundary"), 3)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
