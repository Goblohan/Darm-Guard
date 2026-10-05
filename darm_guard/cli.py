"""darm-guard: the command-line entry point. `darm-guard demo` runs the demonstration."""
import argparse, sys


def main() -> None:
    ap = argparse.ArgumentParser(prog="darm-guard",
                                 description="DARM Guard: runtime authorization for AI agents.")
    sub = ap.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run the broker against an agent, step by step, in a temporary directory")
    demo.add_argument("--keep", action="store_true", help="keep the temporary directory for inspection")
    au = sub.add_parser("audit", help="check a broker's evidence as an outside auditor would, with the public key alone")
    au.add_argument("--audit", required=True, help="the broker's audit log")
    au.add_argument("--config", help="the principal's config, to check every governed file against the log")
    au.add_argument("--registry", help="the principal's registry, with --config")
    au.add_argument("--pub", help="the public key file (default: the audit log's .pub.json)")
    rp = sub.add_parser("report", help="what the agent tried and what happened, request by request, from the log")
    rp.add_argument("--audit", required=True, help="the broker's audit log")
    rp.add_argument("--json", action="store_true", help="one JSON object per request instead of text")
    a = ap.parse_args()
    if a.command == "demo":
        from .demo import run
        sys.exit(run(keep=a.keep))
    if a.command == "audit":
        from .evidence import audit
        sys.exit(audit(a.audit, a.config, a.registry, a.pub))
    if a.command == "report":
        from .evidence import report
        sys.exit(report(a.audit, a.json))


if __name__ == "__main__":
    main()
