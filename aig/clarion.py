"""Compile Clarion intent (AegisFlux `segmentation_policy_intent.v1`) into gateway policy.

    Clarion intent ──► aig compile ──► signed segmentation_compiled_artifact.v1
                                        (platform_path: proxy_broker)
                                        + aig_policy_overlay.v1 payload
                   ──► aig serve/proxy --overlay  (verifies signature, applies rules)

What each intent field means at the tool layer:

| Intent field | Compiled to |
|---|---|
| `data_rules[].classification` | data label (`finance`, `pii`, ...) |
| `data_rules[].sensitivity` | flow rule to `external` (table `SENSITIVITY`) |
| `subject.agent_class` / `device_ids` | rule scope (agent class in gateway policy, device in token) |
| `action_mode` + `blocking_enabled` + `proxy_broker.max_action_mode` | `enforce` or `observe` |
| `lifecycle_status`, `approval`, `ttl` | refused unless approved and live; rule expiry |
| `destination_rules` | not compiled here: destinations belong to the steering gateway and host |
| `subject.process_selectors` | not compiled here: processes are identified on the host by AegisFlux |

Intent never loosens the gateway: compiled rules are added to the base policy,
and flow rules can only tighten decisions.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import time
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import __version__
from .policy import Policy, PolicyError, parse_flow

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts" / "aegisflux"
COMPILER_VERSION = "aig-intent-compiler-v1"
OVERLAY_SCHEMA = "aig_policy_overlay.v1"

# sensitivity -> how data of that classification may leave
SENSITIVITY: dict[str, dict[str, str] | None] = {
    "restricted":   {"action": "deny", "precision": "session"},            # seen it? nothing leaves
    "confidential": {"action": "deny", "precision": "value", "residual": "require_approval"},
    "internal":     {"action": "require_approval", "precision": "value", "residual": "allow"},
    "public":       None,                                                 # no restriction
}
BLOCKING_MODES = {"deny", "quarantine"}
NOT_TOOL_LAYER = {"redirect_to_proxy", "assign_tunnel", "rollback"}


class CompileError(ValueError):
    """The intent was refused. The message says why."""


@dataclass
class CompileResult:
    placed: bool
    report: list[str] = field(default_factory=list)
    bundle: dict[str, Any] | None = None    # {"artifact": ..., "payload": ...}


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _validator(name: str):
    try:
        import jsonschema
    except ImportError:          # validation is a safety net, not a runtime dependency
        return None
    schema = json.loads((CONTRACTS / name).read_text())
    return jsonschema.Draft202012Validator(schema)


def validate(doc: dict, schema_file: str) -> list[str]:
    v = _validator(schema_file)
    if v is None:
        return []
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in v.iter_errors(doc)]


def compile_intent(intent: dict[str, Any], policy: Policy, *, key: Ed25519PrivateKey, key_id: str,
                   previous_artifact_id: str = "", now_ms: int | None = None) -> CompileResult:
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    errors = validate(intent, "segmentation-policy-intent.v1.schema.json")
    if errors:
        raise CompileError("intent does not match segmentation_policy_intent.v1: " + "; ".join(errors[:5]))

    iid = intent["intent_id"]
    report: list[str] = []

    # --- governance gates --------------------------------------------------------
    if intent["lifecycle_status"] not in ("approved", "compiled"):
        raise CompileError(f"lifecycle_status is {intent['lifecycle_status']!r}; only approved intents compile")
    approval = intent["approval"]
    if approval["required"] and approval.get("status") != "approved":
        raise CompileError(f"approval required but status is {approval.get('status', 'missing')!r}")
    expires = intent["ttl"]["expires_at_ms"]
    if expires <= now_ms:
        raise CompileError("intent has expired (ttl.expires_at_ms is in the past)")

    # --- placement --------------------------------------------------------------
    pb = intent["platform_adapters"].get("proxy_broker")
    if pb is not None and not pb["supported"]:
        return CompileResult(False, [f"not placed: the intent marks proxy_broker unsupported ({pb.get('notes', 'no notes')})"])
    if pb is None and "proxy" not in intent["placement_preferences"]:
        return CompileResult(False, ["not placed: neither a proxy_broker adapter nor a 'proxy' placement preference"])

    mode = intent["action_mode"]
    if mode in NOT_TOOL_LAYER:
        return CompileResult(False, [f"not placed: action_mode {mode!r} is a transport action for the steering "
                                     f"gateway, not a tool-layer decision"])
    if mode == "allow":
        return CompileResult(False, ["not placed: action_mode 'allow' grants access; the gateway only compiles "
                                     "intent that restricts"])

    max_mode = (pb or {}).get("max_action_mode", "observe")
    enforce = mode in BLOCKING_MODES and intent["blocking_enabled"] and max_mode in BLOCKING_MODES
    if mode in BLOCKING_MODES and not enforce:
        why = ("blocking_enabled is false" if not intent["blocking_enabled"]
               else f"proxy_broker max_action_mode is {max_mode!r}")
        report.append(f"downgraded to observe: action_mode {mode!r} but {why}")
    report.append(f"mode: {'enforce' if enforce else 'observe'}")

    # --- scope ------------------------------------------------------------------
    subject = intent["subject"]
    if subject["kind"] not in ("agent_class", "device"):
        raise CompileError(f"subject kind {subject['kind']!r} cannot be enforced at the gateway: it identifies "
                           f"agents by token (agent class, device), not by process, workload or user session")
    agent_classes = (subject["agent_class"],) if subject.get("agent_class") else ()
    device_ids = tuple(subject.get("device_ids", ()))
    if subject["kind"] == "agent_class" and not agent_classes:
        raise CompileError("subject kind agent_class without an agent_class")
    if subject["kind"] == "device" and not device_ids:
        raise CompileError("subject kind device without device_ids")
    if subject.get("process_selectors"):
        report.append("process_selectors left to the host placement (AegisFlux identifies processes)")
    if agent_classes:
        matching = [a.id for a in policy.agents.values()
                    if fnmatchcase(a.agent_class or "", agent_classes[0])]
        report.append(f"scope: agent_class {agent_classes[0]!r} -> {', '.join(matching) or 'NO AGENTS'}")
        if not matching:
            report.append(f"warning: no agent in the gateway policy has agent_class {agent_classes[0]!r}; "
                          f"the rules compile but match nothing")
    if device_ids:
        report.append(f"scope: devices {', '.join(device_ids)}")
    stores = sorted({t.stores for t in policy.tools.values() if t.stores})
    if stores and (device_ids or (agent_classes and agent_classes != ("*",))):
        report.append(f"warning: data can move between agents through shared stores ({', '.join(stores)}); "
                      f"a data rule scoped to this subject does not follow it to other agents. "
                      f"Use agent_class '*' if the rule is about the data rather than the agent")

    if intent.get("destination_rules"):
        report.append(f"{len(intent['destination_rules'])} destination rule(s) left to the steering gateway "
                      f"and host placements")

    # --- data rules -> flow rules ------------------------------------------------
    produced = {label for t in policy.tools.values() for label in t.reads}
    artifact_id = f"aig-{iid}-{hashlib.sha256(_canonical(intent)).hexdigest()[:12]}"[:128]
    flows: list[dict[str, Any]] = []
    for rule in intent.get("data_rules", []):
        label, sensitivity = rule.get("classification"), rule.get("sensitivity")
        if not label or not sensitivity:
            report.append(f"skipped data rule without classification and sensitivity: {rule}")
            continue
        spec = SENSITIVITY[sensitivity]
        if spec is None:
            report.append(f"{label}: public, no restriction")
            continue
        if label not in produced:
            report.append(f"warning: no declared tool produces {label!r} data; the rule is inert until one does")
        flows.append({
            "id": f"{iid}:{label}", "from": label, "to": "external", **spec,
            "mode": "enforce" if enforce else "observe",
            **({"agent_classes": list(agent_classes)} if agent_classes else {}),
            **({"device_ids": list(device_ids)} if device_ids else {}),
            "expires_at_ms": expires, "intent_id": iid, "artifact_id": artifact_id,
        })
        how = f"{spec['action']} ({spec['precision']}" + (f", residual {spec['residual']})" if "residual" in spec else ")")
        report.append(f"{label}: {sensitivity} -> {how} to external")
    if not flows:
        return CompileResult(False, report + ["not placed: no data rule restricts anything at the tool layer"])

    for i, f in enumerate(flows):          # the gateway must be able to load what we emit
        parse_flow(f, f"compiled[{i}]", f["id"])

    refs = approval.get("refs") or []
    approval_ref = (refs[0] if refs else f"intent-approval:{iid}")[:256]
    payload = {"schema": OVERLAY_SCHEMA, "artifact_id": artifact_id, "intent_id": iid,
               "approval_ref": approval_ref, "flows": flows}
    body = _canonical(payload)
    artifact = {
        "schema_version": "segmentation_compiled_artifact.v1",
        "artifact_id": artifact_id,
        "intent_id": iid,
        "platform_path": "proxy_broker",
        "placement_target": "proxy",
        "action_mode": ("quarantine" if mode == "quarantine" else "deny") if enforce else "observe",
        "blocking_enabled": enforce,
        "scope": {
            "selectors": [f"agent_class:{c}" for c in agent_classes] or [f"device:{d}" for d in device_ids],
            **({"device_ids": list(device_ids)} if device_ids else {}),
        },
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "value_b64": base64.b64encode(key.sign(body)).decode(),
            "content_sha256": hashlib.sha256(body).hexdigest(),
        },
        "compatibility": {"min_agent_version": __version__, "supported_os": ["linux", "macos", "windows"],
                          "adapter_version": OVERLAY_SCHEMA},
        "expires_at_ms": expires,
        "rollback": {"plan": f"Remove overlay {artifact_id} from the gateway; the base policy stays in force.",
                     "previous_artifact_id": previous_artifact_id},
        "payload_ref": f"aig-overlay:{artifact_id}",
        "compiled_at_ms": now_ms,
        "compiler_version": COMPILER_VERSION,
    }
    errors = validate(artifact, "segmentation-compiled-artifact.v1.schema.json")
    if errors:   # a bug in this compiler, never the operator's fault
        raise AssertionError("compiled artifact violates the AegisFlux contract: " + "; ".join(errors))
    return CompileResult(True, report, {"artifact": artifact, "payload": payload})


def load_overlay(bundle: dict[str, Any], key: Ed25519PublicKey, *, now_ms: int | None = None) -> list:
    """Verify a compiled bundle and return its flow rules. Raises PolicyError on any problem."""
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    try:
        artifact, payload = bundle["artifact"], bundle["payload"]
        sig = artifact["signature"]
    except (KeyError, TypeError) as e:
        raise PolicyError("overlay bundle needs artifact and payload") from e
    body = _canonical(payload)
    if sig.get("algorithm") != "ed25519":
        raise PolicyError("overlay signature must be ed25519")
    if hashlib.sha256(body).hexdigest() != sig.get("content_sha256"):
        raise PolicyError("overlay payload does not match its content hash (tampered)")
    try:
        key.verify(base64.b64decode(sig["value_b64"]), body)
    except (InvalidSignature, ValueError) as e:
        raise PolicyError("overlay signature is invalid") from e
    if artifact.get("platform_path") != "proxy_broker" or payload.get("schema") != OVERLAY_SCHEMA:
        raise PolicyError("not a proxy_broker overlay")
    if payload.get("artifact_id") != artifact.get("artifact_id"):
        raise PolicyError("payload and artifact disagree on artifact_id")
    if artifact.get("expires_at_ms", 0) <= now_ms:
        raise PolicyError(f"overlay {artifact['artifact_id']} has expired")
    rules = []
    for i, spec in enumerate(payload.get("flows") or []):
        rule = parse_flow(spec, f"{artifact['artifact_id']}.flows[{i}]", f"{artifact['artifact_id']}-{i}")
        # provenance comes from the signed artifact, never from the rule text
        rules.append(dataclasses.replace(rule, intent_id=artifact["intent_id"], artifact_id=artifact["artifact_id"],
                                         approval_ref=payload.get("approval_ref")))
    return rules


def apply_overlays(policy: Policy, bundles: list[dict[str, Any]], key: Ed25519PublicKey,
                   now_ms: int | None = None) -> Policy:
    extra = [r for b in bundles for r in load_overlay(b, key, now_ms=now_ms)]
    ids = [r.id for r in policy.flows + extra]
    if len(ids) != len(set(ids)):
        raise PolicyError("duplicate flow rule ids across base policy and overlays")
    return dataclasses.replace(policy, flows=policy.flows + extra)
