"""Every theorem the broker cites in a response basis must exist in darm-monitor."""
import glob, os, re, sys
here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, "..", "darm_guard", "broker.py")).read()
cited = sorted(set(re.findall(r'"(DARM\.[A-Za-z0-9_.]+)"', src)))
mon = os.path.expanduser(os.environ.get("DARM_MONITOR", "~/darm-monitor"))
lean = "\n".join(open(f).read() for f in glob.glob(os.path.join(mon, "GRBS", "*.lean")))
missing = [n for n in cited if not re.search(rf"\btheorem\s+{re.escape(n.split('.')[-1])}\b", lean)]
for n in cited:
    print(("MISSING " if n in missing else "found   ") + n)
print(f"\n{len(cited) - len(missing)}/{len(cited)} cited theorems exist in darm-monitor")
sys.exit(1 if missing else 0)
