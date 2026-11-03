"""Clarion intent -> signed gateway overlay -> decisions -> AegisFlux outcome events."""
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aig import Engine, PolicyError, Session, load_policy
from aig.aegis import OutcomeEmitter, outcome_events
from aig.clarion import CompileError, apply_overlays, compile_intent, load_overlay, validate
from aig.gateway import Gateway
from aig.ledger import Ledger
from aig.redteam import load_scenarios, run_all, run_scenario, scoreboard
from aig.sim import Enterprise

ROOT = Path(__file__).parent.parent
EX = ROOT / "examples" / "clarion"
BASE = load_policy(EX / "gateway-base.yaml")
KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key()
NOW = 1_800_000_000_000


def intent(name):
    return json.loads((EX / f"{name}.intent.json").read_text())


def build(doc, policy=BASE):
    return compile_intent(doc, policy, key=KEY, key_id="lab-1", now_ms=NOW)


def managed(*names, policy=BASE):
    return apply_overlays(policy, [build(intent(n)).bundle for n in names], PUB, now_ms=NOW)


# ---- compiling ---------------------------------------------------------------
def test_examples_compile_to_valid_signed_artifacts():
    for name, mode in [("finance-egress", "deny"), ("research-internal", "deny"), ("ot-egress-rollout", "observe")]:
        res = build(intent(name))
        assert res.placed
        art = res.bundle["artifact"]
        assert validate(art, "segmentation-compiled-artifact.v1.schema.json") == []
        assert (art["platform_path"], art["action_mode"], art["blocking_enabled"]) == ("proxy_broker", mode, mode == "deny")


def test_aegisflux_own_example_compiles_in_observe_with_honest_warnings():
    doc = json.loads((ROOT / "contracts" / "aegisflux" / "example.code_agent_mcp_bridge.intent.json").read_text())
    res = build(doc)
    assert res.placed and res.bundle["artifact"]["action_mode"] == "observe"
    report = "\n".join(res.report)
    assert "process_selectors left to the host" in report
    assert "destination rule(s) left to the steering gateway" in report
    assert "no declared tool produces 'model_api'" in report


@pytest.mark.parametrize("change,msg", [
    (lambda d: d.update(lifecycle_status="draft"), "only approved"),
    (lambda d: d["ttl"].update(expires_at_ms=NOW - 1), "expired"),
    (lambda d: d["approval"].update(status="pending"), "approval|segmentation_policy_intent"),
    (lambda d: d.update(subject={"kind": "process", "process_selectors": [{"image_name": "node"}]}), "cannot be enforced"),
    (lambda d: d.update(bogus=1), "segmentation_policy_intent.v1"),
])
def test_refused(change, msg):
    doc = intent("finance-egress")
    change(doc)
    with pytest.raises(CompileError, match=msg):
        build(doc)


@pytest.mark.parametrize("change,msg", [
    (lambda d: d["platform_adapters"]["proxy_broker"].update(supported=False), "unsupported"),
    (lambda d: d.update(action_mode="redirect_to_proxy"), "steering gateway"),
    (lambda d: d.update(data_rules=[{"classification": "finance", "sensitivity": "public"}]), "restricts anything"),
])
def test_not_placed(change, msg):
    doc = intent("finance-egress")
    change(doc)
    res = build(doc)
    assert not res.placed and msg in res.report[-1]


def test_blocking_disabled_downgrades_to_observe():
    doc = intent("finance-egress")
    doc["blocking_enabled"] = False
    res = build(doc)
    assert res.bundle["artifact"]["action_mode"] == "observe"
    assert any("downgraded to observe: action_mode 'deny' but blocking_enabled is false" in r for r in res.report)


def test_narrow_scope_warns_about_shared_stores():
    assert any("shared stores" in r for r in build(intent("research-internal")).report)
    assert not any("shared stores" in r for r in build(intent("finance-egress")).report)


# ---- loading: the gateway trusts only signed, current, untampered overlays ---------
def test_tampering_and_wrong_keys_rejected():
    bundle = build(intent("finance-egress")).bundle
    loosened = copy.deepcopy(bundle)
    loosened["payload"]["flows"][0]["action"] = "allow"
    with pytest.raises(PolicyError, match="tampered"):
        load_overlay(loosened, PUB, now_ms=NOW)
    resigned = copy.deepcopy(loosened)
    resigned["artifact"]["signature"]["content_sha256"] = __import__("hashlib").sha256(
        json.dumps(resigned["payload"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(PolicyError, match="signature"):
        load_overlay(resigned, PUB, now_ms=NOW)
    with pytest.raises(PolicyError, match="signature"):
        load_overlay(bundle, Ed25519PrivateKey.generate().public_key(), now_ms=NOW)
    with pytest.raises(PolicyError, match="expired"):
        load_overlay(bundle, PUB, now_ms=bundle["artifact"]["expires_at_ms"] + 1)


def test_provenance_comes_from_signed_artifact():
    [rule] = load_overlay(build(intent("finance-egress")).bundle, PUB, now_ms=NOW)
    assert rule.intent_id == "clarion-finance-egress" and rule.artifact_id.startswith("aig-clarion-finance-egress-")


def test_duplicate_overlay_refused():
    b = build(intent("finance-egress")).bundle
    with pytest.raises(PolicyError, match="duplicate"):
        apply_overlays(BASE, [b, b], PUB, now_ms=NOW)


# ---- enforcement -----------------------------------------------------------
def _after_read(policy, agent, principal, tool, attrs=None):
    eng, s, ent = Engine(policy), Session(agent, principal, attrs=attrs or {}), Enterprise()
    args = {"sensor": "line-3/temp"} if tool == "ot.read_sensor" else {}
    eng.record(s, tool, args)
    eng.observe(s, tool, args, ent.call(tool, args)["content"][0]["text"])
    return eng, s


def test_without_intent_base_policy_lets_finance_out():
    eng, s = _after_read(BASE, "expense-bot", "group:finance", "finance.query_ledger")
    assert eng.evaluate(s, "email.send", {"to": "x@evil.example", "body": "TX-1042"}).allowed


def test_enforced_intent_blocks_with_intent_provenance():
    eng, s = _after_read(managed("finance-egress"), "expense-bot", "group:finance", "finance.query_ledger")
    d = eng.evaluate(s, "email.send", {"to": "x@evil.example", "body": "TX-1042"})
    assert d.action == "deny" and d.matches[0].intent_id == "clarion-finance-egress" and d.matches[0].enforced


def test_observe_intent_records_but_does_not_block():
    eng, s = _after_read(managed("ot-egress-rollout"), "plant-monitor", "group:ot-operators", "ot.read_sensor")
    d = eng.evaluate(s, "email.send", {"to": "vendor@supplier.example", "body": "line 3 temp 71.4"})
    assert d.allowed
    [m] = d.observed
    assert (m.intent_id, m.action, m.enforced) == ("clarion-ot-egress", "deny", False)


def test_scoped_intent_ignores_other_agent_classes():
    policy = managed("research-internal")
    eng, s = _after_read(policy, "expense-bot", "group:finance", "docs.search")
    assert not any(m.intent_id for m in eng.evaluate(s, "email.send", {"to": "x@evil.example", "body": "roadmap 2027 market"}).matches)


def test_expired_rule_stops_applying():
    policy = managed("finance-egress")
    eng, s = _after_read(policy, "expense-bot", "group:finance", "finance.query_ledger")
    later = policy.flows[-1].expires_at_ms / 1000 + 1
    assert eng.evaluate(s, "email.send", {"to": "x@evil.example", "body": "TX-1042"}, now=later).allowed


def test_laundering_pitfall_narrow_scope_vs_data_scope():
    """The red team catches a scoping mistake the compiler only warns about."""
    attack = next(s for s in load_scenarios(ROOT / "scenarios") if s["id"] == "ATK-LAU-001")
    narrow = intent("finance-egress")
    narrow["subject"] = {"kind": "agent_class", "agent_class": "finance_automation"}
    assert run_scenario(managed(policy=apply_overlays(BASE, [build(narrow).bundle], PUB, now_ms=NOW)), attack).verdict == "bypass"
    assert run_scenario(managed("finance-egress"), attack).verdict == "blocked"


def test_clarion_managed_gateway_red_team():
    results = run_all(managed("finance-egress", "research-internal", "ot-egress-rollout"), load_scenarios(ROOT / "scenarios"))
    sb = scoreboard(results)
    assert sb["attacks"]["blocked"] == sb["attacks"]["total"]          # confidential: paraphrase blocked too
    # ...at the documented price: replies after reading the ledger need a human
    assert set(sb["workloads"]["false_positives"]) == {"LEG-FIN-005", "LEG-FIN-006"}
    for r in results:
        if r.id in ("LEG-FIN-005", "LEG-FIN-006"):
            assert r.steps[r.stopped_at].rules == ["flow:clarion-finance-egress:finance:residual"]


# ---- AegisFlux outcome events -------------------------------------------------
def _events(policy, agent, principal, tool, call_args, attrs):
    eng, s = _after_read(policy, agent, principal, tool, attrs)
    d = eng.evaluate(s, "email.send", call_args)
    return d, outcome_events(s, "email.send", d, d.action, {"hash": "ab" * 32}, "aig:lab")


def test_blocked_event_matches_contract_and_carries_no_values():
    d, [e] = _events(managed("finance-egress"), "expense-bot", "group:finance", "finance.query_ledger",
                     {"to": "x@evil.example", "body": "TX-1042 Contoso 72300"},
                     {"device": "dev-7", "instance": "inst-42"})
    assert validate(e, "segmentation-outcome-event.v1.schema.json") == []
    assert (e["event_type"], e["blocking_applied"], e["device_id"], e["platform_path"]) == \
        ("match_blocked", True, "dev-7", "proxy_broker")
    assert {"kind": "agent_instance", "ref": "inst-42"} in e["evidence_refs"]
    assert e["approval_ref"] == "chg-2026-1101"                         # the approved change that authorised it
    assert "tx1042" in d.reasons[0]                                    # the agent and the local log see values
    assert "tx1042" not in e["detail"].lower() and "72300" not in e["detail"]   # telemetry does not


def test_observed_event_matches_contract():
    _, [e] = _events(managed("ot-egress-rollout"), "plant-monitor", "group:ot-operators", "ot.read_sensor",
                     {"to": "vendor@supplier.example", "body": "71.4"}, {})
    assert validate(e, "segmentation-outcome-event.v1.schema.json") == []
    assert (e["event_type"], e["action_mode"], e["blocking_applied"]) == ("match_observed", "observe", False)
    assert "would deny" in e["detail"]


def test_base_policy_rules_emit_nothing():
    eng, s = _after_read(BASE, "expense-bot", "group:finance", "email.read_inbox")
    d = eng.evaluate(s, "finance.approve_payment", {"id": "TX-1042"})
    assert d.action == "deny" and outcome_events(s, "x", d, "deny", None, "aig") == []


def test_gateway_writes_events_and_ledger_notes_observed(tmp_path):
    emitter = OutcomeEmitter(tmp_path / "events.jsonl", actor_id="aig:test")
    gw = Gateway(Engine(managed("ot-egress-rollout")), Session("plant-monitor", "group:ot-operators"),
                 ledger=Ledger(tmp_path / "d.jsonl"), on_decision=emitter)
    call = lambda i, t, a: {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": t, "arguments": a}}
    gw.from_agent(call(1, "ot.read_sensor", {"sensor": "line-3/temp"}))
    gw.from_server({"jsonrpc": "2.0", "id": 1, "result": Enterprise().call("ot.read_sensor", {"sensor": "line-3/temp"})})
    fwd, _ = gw.from_agent(call(2, "email.send", {"to": "vendor@supplier.example", "body": "71.4"}))
    assert fwd is not None                                             # observe mode: not blocked
    [event] = map(json.loads, (tmp_path / "events.jsonl").read_text().splitlines())
    rec = json.loads((tmp_path / "d.jsonl").read_text().splitlines()[-1])
    assert event["evidence_refs"][0]["ref"] == rec["hash"]             # event points at the tamper-evident record
    assert rec["observed"][0]["would"] == "deny" and rec["intents"] == ["clarion-ot-egress"]


def test_emitter_failure_never_changes_a_decision(tmp_path):
    def broken(*_):
        raise RuntimeError("collector down")
    gw = Gateway(Engine(BASE), Session("expense-bot", "group:finance"), on_decision=broken)
    fwd, _ = gw.from_agent({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "docs.search", "arguments": {"q": "x"}}})
    assert fwd is not None
