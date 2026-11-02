import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aig.token import TokenError, issue, verify

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key()
NOW = 1_800_000_000
BASE = dict(device="dev-7", instance="inst-42", klass="development", agent="expense-bot",
            principal="group:finance", audience="aegis-gateway-01", policy_version="2026.11.1")


def tok(**over):
    key, now = over.pop("key", KEY), over.pop("now", NOW)
    return issue(key, **{**BASE, **over}, now=now)


def check(t, **kw):
    return verify(t, PUB, audience=kw.pop("audience", "aegis-gateway-01"), now=kw.pop("now", NOW + 10), **kw)


def test_round_trip():
    ident = check(tok(), policy_version="2026.11.1")
    assert (ident.instance, ident.klass, ident.agent, ident.principal) == ("inst-42", "development", "expense-bot", "group:finance")


def _tamper(t, **claims):
    h, b, s = t.split(".")
    body = json.loads(base64.urlsafe_b64decode(b + "=="))
    body.update(claims)
    nb = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    return f"{h}.{nb}.{s}"


@pytest.mark.parametrize("make,kw,msg", [
    (lambda: tok(key=Ed25519PrivateKey.generate()), {}, "bad signature"),
    (lambda: _tamper(tok(), cls="privileged"), {}, "bad signature"),      # self-promotion
    (lambda: tok(), {"audience": "other-gw"}, "wrong audience"),
    (lambda: tok(), {"now": NOW + 3600}, "expired"),
    (lambda: tok(ttl=86400), {}, "too long"),
    (lambda: tok(now=NOW + 600), {}, "future"),
    (lambda: tok(policy_version="2026.10.9"), {"policy_version": "2026.11.1"}, "policy version"),
    (lambda: tok(), {"revoked": {"inst-42"}}, "revoked"),
    (lambda: "not.a.token", {}, "malformed"),
])
def test_rejected(make, kw, msg):
    with pytest.raises(TokenError, match=msg):
        check(make(), **kw)


def test_alg_none_rejected():
    h = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    _, b, _ = tok().split(".")
    with pytest.raises(TokenError, match="algorithm"):
        check(f"{h}.{b}.")
