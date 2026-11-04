"""Command line entry points.

    aig proxy  --policy P --agent ID --principal WHO [--log FILE] -- <upstream mcp command...>
    aig serve  --policy P --key PUB.pem --audience AUD [--upstream sim|URL] [--port N]
    aig token  keygen --out NAME | issue --key PRIV.pem --agent ... --principal ... --class ...
    aig check  --policy P --agent ID --principal WHO TOOL [--args JSON] [--labels a,b]
    aig redteam --policy P [--scenarios DIR] [--md FILE] [--json FILE]
    aig compile --intent INTENT.json --policy P --key COMPILER.key --key-id ID [--out BUNDLE.json]
    aig verify-log FILE

proxy, serve, check and redteam accept --overlay BUNDLE.json (repeatable) with
--overlay-key COMPILER.pub; proxy and serve accept --emit-events FILE / --emit-url URL.
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

    def overlays(sp):
        sp.add_argument("--overlay", action="append", default=[], help="signed bundle from aig compile (repeatable)")
        sp.add_argument("--overlay-key", help="Ed25519 public key (PEM) that signed the overlays")

    def emit(sp):
        sp.add_argument("--emit-events", help="append AegisFlux segmentation_outcome_event.v1 records to this file")
        sp.add_argument("--emit-url", help="POST outcome events to this collector URL (best-effort)")

    px = sub.add_parser("proxy", help="run as an MCP stdio proxy in front of one upstream server, or all of an "
                                      "agent's servers with --config")
    px.add_argument("--config", help="aig_agent_config.v1 file: one gateway in front of all of an agent's MCP servers")
    px.add_argument("--policy")
    px.add_argument("--agent")
    px.add_argument("--principal")
    px.add_argument("--log", default="aig-decisions.jsonl")
    px.add_argument("--show-all-tools", action="store_true", help="don't hide out-of-scope tools from tools/list")
    px.add_argument("--label-store", default="aig-labels.json",
                    help="file shared by all gateway processes so labels follow data across agents")
    overlays(px)
    emit(px)
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
    overlays(sv)
    emit(sv)

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
    overlays(ck)

    vf = sub.add_parser("verify-log", help="verify a decision log's hash chain")
    vf.add_argument("file")

    rt = sub.add_parser("redteam", help="run attack scenarios and workloads, print a scoreboard")
    rt.add_argument("--policy", required=True)
    rt.add_argument("--scenarios", default="scenarios")
    rt.add_argument("--json", help="write full results as JSON")
    rt.add_argument("--md", help="write the scoreboard as Markdown")
    overlays(rt)

    cn = sub.add_parser("console", help="serve the AIG console for a gateway's policy, log and evidence")
    cn.add_argument("--policy", required=True)
    cn.add_argument("--log", default="aig-decisions.jsonl", help="the gateway's decision log")
    cn.add_argument("--events", help="AegisFlux outcome events file written by --emit-events")
    cn.add_argument("--redteam", help="red-team results JSON from aig redteam --json")
    cn.add_argument("--host", default="127.0.0.1")
    cn.add_argument("--port", type=int, default=3040)
    overlays(cn)

    cp = sub.add_parser("compile", help="compile a Clarion intent into a signed gateway overlay")
    cp.add_argument("--intent", required=True, help="segmentation_policy_intent.v1 JSON")
    cp.add_argument("--policy", required=True, help="the gateway policy the overlay will apply to")
    cp.add_argument("--key", required=True, help="Ed25519 private key (PEM) that signs the artifact")
    cp.add_argument("--key-id", required=True)
    cp.add_argument("--previous-artifact-id", default="")
    cp.add_argument("--out", help="write the signed bundle here")

    a = p.parse_args(argv)

    agent_cfg = None
    if a.cmd == "proxy":
        if a.config:
            from .aggregate import load_agent_config

            try:
                agent_cfg = load_agent_config(a.config)
            except (OSError, ValueError) as e:
                print(f"config error: {e}", file=sys.stderr)
                return 2
            explicit = set(argv if argv is not None else sys.argv[1:])
            a.policy = a.policy or agent_cfg.get("policy")
            a.agent = a.agent or agent_cfg.get("agent")
            a.principal = a.principal or agent_cfg.get("principal")
            if "--log" not in explicit and agent_cfg.get("log"):
                a.log = agent_cfg["log"]
            if "--label-store" not in explicit and agent_cfg.get("label_store"):
                a.label_store = agent_cfg["label_store"]
            if not a.overlay:
                a.overlay, a.overlay_key = agent_cfg.get("overlays", []), a.overlay_key or agent_cfg.get("overlay_key")
            a.emit_events = a.emit_events or agent_cfg.get("emit_events")
        missing = [f for f in ("policy", "agent", "principal") if not getattr(a, f)]
        if missing:
            print(f"proxy needs --{', --'.join(missing)} (or a --config that sets them)", file=sys.stderr)
            return 2
        Path(a.log).expanduser().parent.mkdir(parents=True, exist_ok=True)

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
        if getattr(a, "overlay", None):
            from .clarion import apply_overlays
            from .token import load_public

            if not a.overlay_key:
                raise PolicyError("--overlay needs --overlay-key to verify the signature")
            bundles = [json.loads(Path(f).read_text()) for f in a.overlay]
            policy = apply_overlays(policy, bundles, load_public(a.overlay_key))
            print(f"loaded {len(bundles)} overlay(s); {len(policy.flows)} flow rules in force", file=sys.stderr)
    except (OSError, ValueError, PolicyError) as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2

    if a.cmd == "console":
        from .console import build_snapshot, serve

        bundles = [json.loads(Path(f).read_text()) for f in a.overlay]
        redteam = None
        if a.redteam:
            rt = json.loads(Path(a.redteam).read_text())
            redteam = {"configs": [{"key": "current", "name": "Current policy", "description": a.policy,
                                    "scoreboard": rt["scoreboard"], "results": rt["results"]}]}
        snap = lambda: build_snapshot(policy, decisions_path=a.log, events_path=a.events, redteam=redteam,
                                      bundles=bundles, gateway={"transport": "live", "policy_file": a.policy})
        srv = serve(snap, a.host, a.port)
        print(f"AIG console on http://{a.host}:{srv.server_address[1]}/", file=sys.stderr)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    if a.cmd == "compile":
        from .clarion import CompileError, compile_intent
        from .token import load_private

        try:
            res = compile_intent(json.loads(Path(a.intent).read_text()), policy, key=load_private(a.key),
                                 key_id=a.key_id, previous_artifact_id=a.previous_artifact_id)
        except (CompileError, ValueError) as e:
            print(f"refused: {e}", file=sys.stderr)
            return 2
        for line in res.report:
            print(f"  {line}")
        if not res.placed:
            return 3
        art = res.bundle["artifact"]
        print(f"compiled {art['artifact_id']} ({art['action_mode']}, {len(res.bundle['payload']['flows'])} rule(s))")
        if a.out:
            Path(a.out).write_text(json.dumps(res.bundle, indent=2) + "\n", encoding="utf-8")
            print(f"wrote {a.out}")
        return 0

    emitter = None
    if getattr(a, "emit_events", None) or getattr(a, "emit_url", None):
        from .aegis import OutcomeEmitter

        emitter = OutcomeEmitter(a.emit_events, a.emit_url,
                                 actor_id=f"aig:{getattr(a, 'audience', None) or 'stdio'}")

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
                            host=a.host, port=a.port, on_decision=emitter)
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
        out = {"action": d.action, "sink": d.sink, "reasons": d.reasons, "rules": d.rules}
        if d.observed:
            out["observed"] = [{"rule": m.rule_id, "would": m.action, "reason": m.reason} for m in d.observed]
        print(json.dumps(out, indent=2))
        return 0 if d.allowed else 1

    if agent_cfg is not None:
        from .aggregate import Aggregator

        gw = Gateway(engine, session, Ledger(a.log), hide_out_of_scope=not a.show_all_tools, on_decision=emitter)
        Aggregator(gw, agent_cfg["servers"]).run()
        return 0

    upstream = a.upstream[1:] if a.upstream[:1] == ["--"] else a.upstream
    if not upstream:
        print("proxy needs an upstream command after --", file=sys.stderr)
        return 2
    gw = Gateway(engine, session, Ledger(a.log), hide_out_of_scope=not a.show_all_tools, on_decision=emitter)
    return run_stdio(gw, upstream)


if __name__ == "__main__":
    sys.exit(main())
