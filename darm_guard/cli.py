"""darm-guard: the command-line entry point. `darm-guard demo` runs the demonstration."""
import argparse, sys


def main() -> None:
    ap = argparse.ArgumentParser(prog="darm-guard",
                                 description="DARM Guard: runtime authorization for AI agents.")
    sub = ap.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run the broker against an agent, step by step, in a temporary directory")
    demo.add_argument("--keep", action="store_true", help="keep the temporary directory for inspection")
    a = ap.parse_args()
    if a.command == "demo":
        from .demo import run
        sys.exit(run(keep=a.keep))


if __name__ == "__main__":
    main()
