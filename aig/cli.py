"""Command line entry points.

    aig proxy  --policy P --agent ID --principal WHO [--log FILE] -- <upstream mcp command...>
    aig check  --policy P --agent ID --principal WHO TOOL [--args JSON] [--labels a,b]
    aig verify-log FILE
"""
from __future__ import annotations

import argparse
import json
import sys

from .engine import Engine, Session
from .gateway import Gateway, run_stdio
from .ledger import Ledger, verify
from .policy import PolicyError, load_policy


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aig", description="Agent Intent Gateway")
    sub = p.add_subparsers(dest="cmd", required=True)

    def ident(sp):
        sp.add_argument("--policy", required=True)
        sp.add_argument("--agent", required=True)
        sp.add_argument("--principal", required=True)

    px = sub.add_parser("proxy", help="run as an MCP stdio proxy in front of an upstream server")
    ident(px)
    px.add_argument("--log", default="aig-decisions.jsonl")
    px.add_argument("--show-all-tools", action="store_true", help="don't hide out-of-scope tools from tools/list")
    px.add_argument("upstream", nargs=argparse.REMAINDER)

    ck = sub.add_parser("check", help="evaluate a single call (dry run)")
    ident(ck)
    ck.add_argument("tool")
    ck.add_argument("--args", default="{}")
    ck.add_argument("--labels", default="", help="comma-separated labels the session already holds")

    vf = sub.add_parser("verify-log", help="verify a decision log's hash chain")
    vf.add_argument("file")

    a = p.parse_args(argv)

    if a.cmd == "verify-log":
        ok, _, msg = verify(a.file)
        print(("OK: " if ok else "TAMPERED: ") + msg)
        return 0 if ok else 1

    try:
        policy = load_policy(a.policy)
    except (OSError, PolicyError) as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2
    engine = Engine(policy)
    session = Session(agent_id=a.agent, principal=a.principal)

    if a.cmd == "check":
        for label in filter(None, a.labels.split(",")):
            session.labels.add(label)
            session.provenance[label] = "--labels"
        d = engine.evaluate(session, a.tool, json.loads(a.args))
        print(json.dumps({"action": d.action, "sink": d.sink, "reasons": d.reasons, "rules": d.rules}, indent=2))
        return 0 if d.allowed else 1

    upstream = a.upstream[1:] if a.upstream[:1] == ["--"] else a.upstream
    if not upstream:
        print("proxy needs an upstream command after --", file=sys.stderr)
        return 2
    gw = Gateway(engine, session, Ledger(a.log), hide_out_of_scope=not a.show_all_tools)
    return run_stdio(gw, upstream)


if __name__ == "__main__":
    sys.exit(main())
