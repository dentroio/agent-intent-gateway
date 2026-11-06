"""Aggregator: one gateway session across all of an agent's MCP servers."""
import io
import json
import sys
import threading
import time
from pathlib import Path

import pytest

from aig import Engine, Session, parse_policy
from aig.aggregate import Aggregator, exposed_name, load_agent_config
from aig.gateway import Gateway
from aig.ledger import Ledger

FAKE = str(Path(__file__).parent / "fixtures" / "fake_mcp.py")
POLICY = parse_policy({
    "version": 1, "default": "deny",
    "tools": {
        "files.read_file": {"reads": ["finance"], "args": ["path", "slow"]},
        "files.list_dir": {"args": ["path"]},
        "chat.post_message": {"sink": "external", "args": ["channel", "text"]},
    },
    "agents": [{"id": "assistant", "purpose": "Help with finance files", "on_behalf_of": ["user:*@corp.example"],
                "allow": ["files.*", "chat.post_message"]}],
    "flows": [{"id": "no-finance-out", "from": "finance", "to": "external", "action": "deny",
               "precision": "value", "residual": "allow"}],
})


class Agent:
    """Drives an Aggregator the way an MCP client would."""

    def __init__(self, tmp, monkeypatch, policy=POLICY):
        monkeypatch.setenv("AIG_CHAT_LOG", str(tmp / "chat.jsonl"))
        self.chat_log = tmp / "chat.jsonl"
        self.out = io.StringIO()
        gw = Gateway(Engine(policy), Session("assistant", "user:dana@corp.example"), ledger=Ledger(tmp / "d.jsonl"))
        self.agg = Aggregator(gw, {"files": {"command": sys.executable, "args": [FAKE, "files"]},
                                   "chat": {"command": sys.executable, "args": [FAKE, "chat"]}}, out=self.out)
        self.agg.start()
        self.n = 0

    def send(self, method, params=None, wait=True):
        self.n += 1
        rid = self.n
        self.agg.handle({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        return self.response(rid) if wait else rid

    def response(self, rid, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            for line in self.out.getvalue().splitlines():
                m = json.loads(line)
                if m.get("id") == rid:
                    return m
            time.sleep(0.01)
        raise AssertionError(f"no response for {rid}")

    def call(self, tool, args=None, wait=True):
        return self.send("tools/call", {"name": tool, "arguments": args or {}}, wait)

    def close(self):
        self.agg.stop()


@pytest.fixture
def agent(tmp_path, monkeypatch):
    a = Agent(tmp_path, monkeypatch)
    yield a
    a.close()


def text(resp):
    return resp["result"]["content"][0]["text"]


def test_initialize_and_merged_namespaced_tool_list(agent):
    init = agent.send("initialize", {"protocolVersion": "2025-06-18"})
    assert init["result"]["serverInfo"]["name"] == "agent-intent-gateway"
    tools = {t["name"]: t for t in agent.send("tools/list")["result"]["tools"]}
    assert set(tools) == {"files__read_file", "files__list_dir", "chat__post_message"}
    assert tools["chat__post_message"]["description"].startswith("[chat] ")


def test_calls_route_to_the_right_server(agent):
    assert "Contoso" in text(agent.call("files__read_file", {"path": "ledger.json"}))
    assert text(agent.call("chat__post_message", {"channel": "#general", "text": "hello"})) == "posted"


def test_cross_server_leak_caught_in_one_session(agent):
    """Read through one server, send through another: the case separate proxies miss."""
    agent.call("files__read_file", {"path": "ledger.json"})
    resp = agent.call("chat__post_message", {"channel": "#public", "text": "Contoso is owed 72,300 on TX-1042"})
    assert resp["result"]["isError"] and "finance" in text(resp) and "files.read_file" in text(resp)
    assert not agent.chat_log.exists()                      # the message never reached the chat server


def test_unrelated_message_after_read_still_allowed(agent):
    agent.call("files__read_file", {"path": "ledger.json"})
    assert text(agent.call("chat__post_message", {"channel": "#general", "text": "lunch at noon?"})) == "posted"


def test_undeclared_and_unknown_tools_refused(agent):
    assert agent.call("files__delete_everything")["result"]["isError"]
    assert agent.call("files__read_file", {"path": "x", "exfil_to": "y"})["result"]["isError"]


def test_out_of_order_responses_keep_their_ids(agent):
    slow = agent.call("files__read_file", {"path": "a", "slow": True}, wait=False)
    fast = agent.call("files__list_dir", {"path": "/"}, wait=False)
    assert "ledger.json" in text(agent.response(fast)) and "Contoso" in text(agent.response(slow))


def test_dead_server_reported_not_hung(tmp_path, monkeypatch):
    out = io.StringIO()
    gw = Gateway(Engine(POLICY), Session("assistant", "user:dana@corp.example"))
    agg = Aggregator(gw, {"files": {"command": "/nonexistent/binary"}}, out=out)
    agg.start()
    assert agg.upstreams["files"].error and agg.catalogue() == {}
    agg.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "files__read_file", "arguments": {}}})
    resp = json.loads(out.getvalue().splitlines()[-1])
    assert resp["id"] == 1 and ("error" in resp or resp["result"]["isError"])


def test_long_names_stay_valid_and_unique():
    a, b = exposed_name("server", "x" * 80), exposed_name("server", "x" * 79 + "y")
    assert len(a) <= 64 and len(b) <= 64 and a != b
    assert exposed_name("my.server", "do/it") == "my_server__do_it"


def test_agent_config_validation(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"agent": "a", "servers": {"x": {"args": []}}}))
    with pytest.raises(ValueError, match="needs a command"):
        load_agent_config(p)
    p.write_text(json.dumps({"agent": "a", "log": "~/x.jsonl", "servers": {"x": {"command": "y"}}}))
    assert not load_agent_config(p)["log"].startswith("~")


def test_cli_end_to_end(tmp_path, monkeypatch):
    """aig proxy --config, driven over real stdio like an MCP client."""
    import subprocess
    import yaml
    monkeypatch.setenv("AIG_CHAT_LOG", str(tmp_path / "chat.jsonl"))
    pol = tmp_path / "policy.yaml"
    pol.write_text(yaml.safe_dump({"version": 1, "tools": {"files.read_file": {"reads": ["finance"]},
        "chat.post_message": {"sink": "external"}}, "agents": [{"id": "assistant", "purpose": "p",
        "on_behalf_of": "user:*@corp.example", "allow": ["files.*", "chat.*"]}],
        "flows": [{"from": "finance", "to": "external", "action": "deny"}]}))
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"schema": "aig_agent_config.v1", "agent": "assistant", "principal": "user:dana@corp.example",
        "policy": str(pol), "log": str(tmp_path / "logs" / "d.jsonl"),
        "servers": {"files": {"command": sys.executable, "args": [FAKE, "files"]},
                    "chat": {"command": sys.executable, "args": [FAKE, "chat"]}}}))
    proc = subprocess.Popen([sys.executable, "-m", "aig.cli", "proxy", "--config", str(cfg)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, cwd=Path(__file__).parent.parent)
    def rpc(i, method, params=None):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())
    try:
        assert rpc(1, "initialize")["result"]["serverInfo"]["name"] == "agent-intent-gateway"
        names = {t["name"] for t in rpc(2, "tools/list")["result"]["tools"]}
        assert names == {"files__read_file", "chat__post_message"}   # list_dir isn't in this policy, so it's hidden
        rpc(3, "tools/call", {"name": "files__read_file", "arguments": {}})
        assert rpc(4, "tools/call", {"name": "chat__post_message", "arguments": {"text": "hi"}})["result"]["isError"]
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)
    assert len((tmp_path / "logs" / "d.jsonl").read_text().splitlines()) == 2


# ---- servers that use Content-Length framing (seen in the field) ---------------------------
FRAMED = str(Path(__file__).parent / "fixtures" / "framed_mcp.py")
LAB_POLICY = parse_policy({"version": 1, "tools": {"lab.lab_health": {}, "lab.lab_memory_search": {"args": ["q"]}},
                           "agents": [{"id": "assistant", "purpose": "p", "on_behalf_of": "user:*@*",
                                       "allow": ["lab.*"]}]})


def _framed_agg(spec_extra=None, on_detected=None):
    out = io.StringIO()
    gw = Gateway(Engine(LAB_POLICY), Session("assistant", "user:dana@corp.example"))
    agg = Aggregator(gw, {"lab": {"command": sys.executable, "args": [FRAMED], **(spec_extra or {})}}, out=out,
                     on_detected=on_detected)
    return agg, out


def test_content_length_server_detected_and_usable(monkeypatch):
    from aig.aggregate import Upstream
    monkeypatch.setattr(Upstream, "PROBE", 1.0)
    found = []
    agg, out = _framed_agg(on_detected=found.append)
    started = time.time()
    agg.start()
    try:
        up = agg.upstreams["lab"]
        assert up.error is None and up.framing == "content-length"
        assert set(agg.catalogue()) == {"lab__lab_health", "lab__lab_memory_search"}
        assert found == [{"lab": "content-length"}]           # remembered for next time
        assert time.time() - started < 5
        agg.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": {"name": "lab__lab_memory_search", "arguments": {"q": "roadmap"}}})
        end = time.time() + 5
        while time.time() < end and '"id": 9' not in out.getvalue():
            time.sleep(0.01)
        resp = [json.loads(l) for l in out.getvalue().splitlines() if json.loads(l).get("id") == 9][0]
        assert '"q": "roadmap"' in resp["result"]["content"][0]["text"]
    finally:
        agg.stop()


def test_explicit_framing_skips_the_probe():
    found = []
    agg, _ = _framed_agg({"framing": "content-length"}, on_detected=found.append)
    started = time.time()
    agg.start()
    try:
        assert agg.upstreams["lab"].framing == "content-length" and time.time() - started < 3
        assert found == []                                    # already known, nothing to record
    finally:
        agg.stop()


def test_standard_server_is_not_reported():
    found = []
    gw = Gateway(Engine(POLICY), Session("assistant", "user:dana@corp.example"))
    agg = Aggregator(gw, {"files": {"command": sys.executable, "args": [FAKE, "files"]}}, out=io.StringIO(),
                     on_detected=found.append)
    agg.start()
    try:
        assert agg.upstreams["files"].framing == "newline" and found == []
    finally:
        agg.stop()


def test_cli_records_detected_framing_in_the_agent_config(tmp_path, monkeypatch):
    import subprocess
    import yaml
    pol = tmp_path / "policy.yaml"
    pol.write_text(yaml.safe_dump({"version": 1, "tools": {"lab.lab_health": {}},
                                   "agents": [{"id": "assistant", "purpose": "p", "on_behalf_of": "user:*@*", "allow": ["lab.*"]}]}))
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"agent": "assistant", "principal": "user:dana@corp.example", "policy": str(pol),
                               "log": str(tmp_path / "d.jsonl"), "servers": {"lab": {"command": sys.executable, "args": [FRAMED]}}}))
    proc = subprocess.Popen([sys.executable, "-m", "aig.cli", "proxy", "--config", str(cfg)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, cwd=Path(__file__).parent.parent)
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
        proc.stdin.flush()
        assert {t["name"] for t in json.loads(proc.stdout.readline())["result"]["tools"]} == {"lab__lab_health"}
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    assert json.loads(cfg.read_text())["servers"]["lab"]["framing"] == "content-length"
