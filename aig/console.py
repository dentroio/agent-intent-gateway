"""The AIG console: a snapshot of gateway state, and a small server for the UI.

    aig console --policy P [--overlay B --overlay-key K] [--log decisions.jsonl]
                [--events events.jsonl] [--redteam reports/scoreboard.json] [--port 3040]

The UI (ui/console, built into aig/console_static/index.html) asks for
/api/snapshot and renders it. The same snapshot shape is embedded into the
published demo build, so the demo and a live gateway show the same screens.
"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .ledger import verify
from .policy import Policy

STATIC = Path(__file__).resolve().parent / "console_static" / "index.html"


def _read_jsonl(path: str | Path | None) -> list[dict[str, Any]]:
    if not path or not Path(path).exists():
        return []
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def outcome_kind(rec: dict[str, Any]) -> str:
    if rec.get("decision") == "require_approval":
        return "approved" if rec.get("outcome") == "allow" else "not_approved"
    return "allowed" if rec.get("outcome") == "allow" else "refused"


def build_snapshot(policy: Policy, *, decisions_path=None, events_path=None, redteam: dict | None = None,
                   bundles: list[dict] | None = None, intent_reports: dict[str, list[str]] | None = None,
                   gateway: dict[str, Any] | None = None, demo: bool = False,
                   commit: str = "unknown") -> dict[str, Any]:
    decisions = _read_jsonl(decisions_path)
    events = _read_jsonl(events_path)
    chain_ok, chain_n, chain_msg = verify(decisions_path) if decisions else (True, 0, "no records yet")

    per_agent: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "calls": 0, "refused": 0, "approvals": 0, "last_ts": None,
        "principals": Counter(), "devices": Counter(), "instances": set()})
    for r in decisions:
        a = per_agent[r["agent"]]
        a["calls"] += 1
        kind = outcome_kind(r)
        a["refused"] += kind in ("refused", "not_approved")
        a["approvals"] += kind in ("approved", "not_approved")
        a["last_ts"] = max(a["last_ts"] or 0, r.get("ts", 0))
        a["principals"][r.get("principal", "?")] += 1
        if r.get("device"):
            a["devices"][r["device"]] += 1
        if r.get("instance"):
            a["instances"].add(r["instance"])

    agents = []
    for ag in policy.agents.values():
        s = per_agent.get(ag.id)
        agents.append({
            "id": ag.id, "agent_class": ag.agent_class, "purpose": ag.purpose,
            "on_behalf_of": list(ag.on_behalf_of), "allow": list(ag.allow),
            "require_approval": list(ag.require_approval), "deny": list(ag.deny),
            "calls": s["calls"] if s else 0, "refused": s["refused"] if s else 0,
            "approvals": s["approvals"] if s else 0, "last_ts": s["last_ts"] if s else None,
            "principals": [p for p, _ in s["principals"].most_common(5)] if s else [],
            "devices": [d for d, _ in s["devices"].most_common(5)] if s else [],
            "instances": len(s["instances"]) if s else 0,
        })

    tools = [{
        "name": t.name, "reads": sorted(t.reads), "writes": sorted(t.writes), "sink": t.sink,
        "egress_rules": [{"args": list(r.args), "pattern": r.pattern, "sink": r.sink, "kind": r.kind}
                         for r in t.egress_rules],
        "risk": t.risk, "args": None if t.args is None else list(t.args),
        "stores": t.stores, "loads": t.loads,
    } for t in policy.tools.values()]

    hits: Counter = Counter()
    observed_hits: Counter = Counter()
    for r in decisions:
        for rule in r.get("rules", []):
            if rule.startswith("flow:"):
                hits[rule.removeprefix("flow:").removesuffix(":residual")] += 1
        for o in r.get("observed", []):
            observed_hits[o["rule"]] += 1
    flows = [{
        "id": f.id, "from": f.from_, "to": f.to, "action": f.action, "precision": f.precision,
        "residual": f.residual if f.precision == "value" else None,
        "mode": "enforce" if f.enforce else "observe",
        "source": "clarion" if f.intent_id else "base",
        "intent_id": f.intent_id, "artifact_id": f.artifact_id, "approval_ref": f.approval_ref,
        "agent_classes": list(f.agent_classes), "device_ids": list(f.device_ids),
        "expires_at_ms": f.expires_at_ms, "hits": hits.get(f.id, 0), "observed": observed_hits.get(f.id, 0),
    } for f in policy.flows]

    intents = []
    for b in bundles or []:
        art, payload = b["artifact"], b["payload"]
        intents.append({
            "intent_id": art["intent_id"], "artifact_id": art["artifact_id"], "action_mode": art["action_mode"],
            "blocking_enabled": art["blocking_enabled"], "scope": art["scope"]["selectors"],
            "key_id": art["signature"]["key_id"], "content_sha256": art["signature"]["content_sha256"],
            "approval_ref": payload.get("approval_ref"), "expires_at_ms": art["expires_at_ms"],
            "compiled_at_ms": art.get("compiled_at_ms"), "compiler_version": art.get("compiler_version"),
            "rules": [f["id"] for f in payload.get("flows", [])],
            "report": (intent_reports or {}).get(art["intent_id"], []),
        })

    return {
        "schema": "aig_console_snapshot.v1",
        "generated_ms": int(time.time() * 1000),
        "version": __version__,
        "commit": commit,
        "demo": demo,
        "gateway": {"policy_version": policy.policy_version, "default": policy.default,
                    "classes": sorted(policy.classes) if policy.classes else [], **(gateway or {})},
        "agents": agents,
        "tools": tools,
        "flows": flows,
        "intents": intents,
        "decisions": decisions,
        "chain": {"ok": chain_ok, "n": chain_n, "message": chain_msg},
        "events": events,
        "redteam": redteam,
    }


def serve(snapshot: Callable[[], dict[str, Any]], host: str = "127.0.0.1", port: int = 3040) -> ThreadingHTTPServer:
    page = STATIC.read_bytes() if STATIC.exists() else b"<p>Console not built: run npm run build in ui/console.</p>"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = self.path.split("?")[0]
            if path == "/api/snapshot":
                return self._send(200, json.dumps(snapshot()).encode(), "application/json")
            if path in ("/", "/index.html"):
                return self._send(200, page, "text/html; charset=utf-8")
            self._send(404, b"not found", "text/plain")

    return ThreadingHTTPServer((host, port), Handler)
