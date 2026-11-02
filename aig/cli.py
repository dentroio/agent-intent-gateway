"""Command line entry points.

    aig proxy  --policy P --agent ID --principal WHO [--log FILE] -- <upstream mcp command...>
    aig serve  --policy P --key PUB.pem --audience AUD [--upstream sim|URL] [--port N]
    aig token  keygen --out NAME | issue --key PRIV.pem --agent ... --principal ... --class ...
    aig check  --policy P --agent ID --principal WHO TOOL [--args JSON] [--labels a,b]
    aig redteam --policy P [--scenarios DIR] [--md FILE] [--json FILE]
    aig verify-log FILE
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import Engine, Session
from .gateway import Gateway, run_stdio
from .labels import LabelStore
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
    px.add_argument("--label-store", default="aig-labels.json",
                    help="file shared by all gateway processes so labels follow data across agents")
    px.add_argument("upstream", nargs=argparse.REMAINDER)

    sv = sub.add_parser("serve", help="run as an MCP Streamable HTTP gateway; identity from per-stream tokens")
    sv.add_argument("--policy", required=True)
    sv.add_argument("--key", required=True, help="Ed25519 public key (PEM) that verifies stream tokens")
    sv.add_argument("--audience", required=True, help="this gateway's audience, e.g. aegis-gateway-01")
    sv.add_argument("--upstream", default="sim", help="'sim' for the simulated enterprise, or an MCP HTTP URL")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8443)
    sv.add_argument("--log", default="aig-decisions.jsonl")
    sv.add_argument("--label-store", default="aig-labels.json")
    sv.add_argument("--revoked", help="file with one revoked token id, instance id or device id per line")
    sv.add_argument("--allow-origin", action="append", default=[], help="browser Origin to accept (repeatable)")

    tk = sub.add_parser("token", help="lab token tools (mock AegisFlux issuer)")
    tsub = tk.add_subparsers(dest="tcmd", required=True)
    kg = tsub.add_parser("keygen", help="write NAME.key (private) and NAME.pub")
    kg.add_argument("--out", default="issuer")
    ti = tsub.add_parser("issue", help="mint a per-stream token")
    ti.add_argument("--key", required=True, help="Ed25519 private key (PEM)")
    ti.add_argument("--agent", required=True)
    ti.add_argument("--principal", required=True)
    ti.add_argument("--class", dest="klass", required=True)
    ti.add_argument("--instance", required=True, help="agent_instance_id")
    ti.add_argument("--device", required=True)
    ti.add_argument("--audience", required=True)
    ti.add_argument("--policy-version")
    ti.add_argument("--ttl", type=int, default=300)

    ck = sub.add_parser("check", help="evaluate a single call (dry run)")
    ident(ck)
    ck.add_argument("tool")
    ck.add_argument("--args", default="{}")
    ck.add_argument("--labels", default="", help="comma-separated labels the session already holds")

    vf = sub.add_parser("verify-log", help="verify a decision log's hash chain")
    vf.add_argument("file")

    rt = sub.add_parser("redteam", help="run attack scenarios and workloads, print a scoreboard")
    rt.add_argument("--policy", required=True)
    rt.add_argument("--scenarios", default="scenarios")
    rt.add_argument("--json", help="write full results as JSON")
    rt.add_argument("--md", help="write the scoreboard as Markdown")

    a = p.parse_args(argv)

    if a.cmd == "verify-log":
        ok, _, msg = verify(a.file)
        print(("OK: " if ok else "TAMPERED: ") + msg)
        return 0 if ok else 1

    if a.cmd == "token":
        from . import token as tok

        if a.tcmd == "keygen":
            tok.keygen(f"{a.out}.key", f"{a.out}.pub")
            print(f"wrote {a.out}.key (keep private) and {a.out}.pub (give to gateways)")
            return 0
        print(tok.issue(tok.load_private(a.key), device=a.device, instance=a.instance, klass=a.klass,
                        agent=a.agent, principal=a.principal, audience=a.audience, ttl=a.ttl,
                        policy_version=a.policy_version))
        return 0

    try:
        policy = load_policy(a.policy)
    except (OSError, PolicyError) as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2

    if a.cmd == "redteam":
        from .redteam import load_scenarios, run_all, scoreboard, to_json, to_markdown

        results = run_all(policy, load_scenarios(a.scenarios))
        md = to_markdown(results)
        if a.json:
            Path(a.json).write_text(to_json(results), encoding="utf-8")
        if a.md:
            Path(a.md).write_text(md, encoding="utf-8")
        print(md)
        return 1 if scoreboard(results)["unexpected"] else 0

    if a.cmd == "serve":
        from .http_server import GatewayServer, HttpUpstream, SimUpstream
        from .token import load_public

        revoked = set()
        if a.revoked:
            revoked = {l.strip() for l in Path(a.revoked).read_text().splitlines() if l.strip()}
        upstream = SimUpstream() if a.upstream == "sim" else HttpUpstream(a.upstream)
        srv = GatewayServer(Engine(policy, LabelStore(a.label_store)), load_public(a.key), a.audience, upstream,
                            ledger=Ledger(a.log), revoked=revoked, allowed_origins=set(a.allow_origin),
                            host=a.host, port=a.port)
        print(f"agent-intent-gateway listening on {srv.url} (audience {a.audience}, "
              f"policy {policy.policy_version or 'unversioned'})", file=sys.stderr)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    engine = Engine(policy, LabelStore(a.label_store) if a.cmd == "proxy" else None)
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
