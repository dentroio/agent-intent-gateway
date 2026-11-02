"""Per-stream identity tokens (AegisFlux ADR-GW-002 shape).

Compact JWS, EdDSA (Ed25519). Claims:

    ADR-GW-002 (binding)        dev   device credential id
                                aiid  agent_instance_id (WO-SEG-010)
                                cls   backend-assigned policy class
                                pv    policy version
                                aud   gateway audience
                                exp   expiry (short: minutes)
                                jti   nonce
    Proposed extensions         agt   policy agent id (which intent applies)
                                prn   principal the instance acts for

Identity always comes from here, never from the agent: a class or agent
claim sent any other way is ignored.

`aig token issue` is a mock issuer for the lab until the AegisFlux backend
mints these (WO-SEG-006).
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REQUIRED = ("dev", "aiid", "cls", "aud", "exp", "jti", "agt", "prn")
MAX_TTL = 15 * 60       # tokens are meant to live minutes; refuse anything longer
SKEW = 30


class TokenError(ValueError):
    """Why a token was refused. Safe to show the caller."""


@dataclass(frozen=True)
class Identity:
    device: str
    instance: str
    klass: str
    policy_version: str | None
    agent: str
    principal: str
    jti: str
    exp: int

    def binding(self) -> tuple[str, str, str, str]:
        """What must stay constant for the life of an MCP session."""
        return (self.device, self.instance, self.agent, self.principal)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def keygen(private_path: str | Path, public_path: str | Path) -> None:
    key = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    Path(private_path).chmod(0o600)
    Path(public_path).write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TokenError("signing key must be Ed25519")
    return key


def load_public(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TokenError("verification key must be Ed25519")
    return key


def issue(key: Ed25519PrivateKey, *, device: str, instance: str, klass: str, agent: str,
          principal: str, audience: str, ttl: int = 300, policy_version: str | None = None,
          now: float | None = None) -> str:
    now = int(now if now is not None else time.time())
    claims = {"dev": device, "aiid": instance, "cls": klass, "agt": agent, "prn": principal,
              "aud": audience, "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex}
    if policy_version is not None:
        claims["pv"] = policy_version
    header = _b64(json.dumps({"alg": "EdDSA", "typ": "aegis-stream+jwt"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = key.sign(f"{header}.{body}".encode())
    return f"{header}.{body}.{_b64(sig)}"


def verify(token: str, key: Ed25519PublicKey, *, audience: str, policy_version: str | None = None,
           revoked: set[str] | frozenset[str] = frozenset(), now: float | None = None) -> Identity:
    now = now if now is not None else time.time()
    try:
        h, b, s = token.split(".")
        header = json.loads(_unb64(h))
        claims = json.loads(_unb64(b))
        sig = _unb64(s)
    except (ValueError, json.JSONDecodeError) as e:
        raise TokenError("malformed token") from e
    if header.get("alg") != "EdDSA":          # never let the token pick its own algorithm
        raise TokenError("unsupported algorithm")
    try:
        key.verify(sig, f"{h}.{b}".encode())
    except InvalidSignature as e:
        raise TokenError("bad signature") from e

    if not isinstance(claims, dict) or (missing := [c for c in REQUIRED if c not in claims]):
        raise TokenError(f"missing claims: {', '.join(missing) if isinstance(claims, dict) else 'all'}")
    if claims["aud"] != audience:
        raise TokenError("wrong audience")
    exp, iat = claims["exp"], claims.get("iat", claims["exp"] - MAX_TTL)
    if not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
        raise TokenError("bad timestamps")
    if exp <= now - SKEW:
        raise TokenError("token expired")
    if iat > now + SKEW:
        raise TokenError("token issued in the future")
    if exp - iat > MAX_TTL:
        raise TokenError("token lifetime too long")
    if policy_version is not None and claims.get("pv") not in (None, policy_version):
        raise TokenError(f"token policy version {claims.get('pv')} != gateway policy {policy_version}")
    if claims["jti"] in revoked or claims["aiid"] in revoked or claims["dev"] in revoked:
        raise TokenError("revoked")

    return Identity(device=str(claims["dev"]), instance=str(claims["aiid"]), klass=str(claims["cls"]),
                    policy_version=claims.get("pv"), agent=str(claims["agt"]),
                    principal=str(claims["prn"]), jti=str(claims["jti"]), exp=int(exp))
