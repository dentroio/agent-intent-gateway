"""Gateway decisions as AegisFlux evidence (`segmentation_outcome_event.v1`).

Every decision in which a Clarion-compiled rule fired becomes one outcome
event, so Clarion's Verify stage and the AegisFlux console see tool-layer
enforcement next to host and steering outcomes:

* `match_blocked`  -- an enforced rule fired and the call was refused
* `match_observed` -- an observe-mode rule fired (would have tightened), or an
                      enforced rule asked for approval and a human granted it

Events carry no data values: the reason is the redacted form ("carries
'finance' values (3 identifiers/amounts, 2 words)"). The full, unredacted
reason stays in the gateway's local tamper-evident log, referenced by hash.

Delivery is best-effort and off the decision path: a slow or dead collector
never delays or changes an enforcement decision.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .engine import Decision, Session


def outcome_events(session: Session, tool: str, decision: Decision, final: str,
                   record: dict[str, Any] | None, actor_id: str, now_ms: int | None = None) -> list[dict[str, Any]]:
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    events = []
    for m in decision.matches:
        if not m.intent_id:
            continue          # base-policy rules have no Clarion intent to report against
        blocked = m.enforced and final != "allow"
        refs = [{"kind": "aig_decision", "ref": (record or {}).get("hash", "aig:unlogged")},
                {"kind": "aig_rule", "ref": m.rule_id[:256]}]
        if session.attrs.get("instance"):
            refs.append({"kind": "agent_instance", "ref": session.attrs["instance"][:256]})
        event = {
            "schema_version": "segmentation_outcome_event.v1",
            "event_id": f"aig-{uuid.uuid4().hex}",
            "event_type": "match_blocked" if blocked else "match_observed",
            "timestamp_ms": now_ms,
            "intent_id": m.intent_id,
            "artifact_id": m.artifact_id or "unknown",
            "outcome": "success",
            "action_mode": "deny" if m.enforced else "observe",
            "blocking_applied": blocked,
            "evidence_refs": refs,
            "actor": {"kind": "system", "id": actor_id[:128]},
            "platform_path": "proxy_broker",
            "detail": (f"{session.agent_id} for {session.principal}: {tool} -> "
                       f"{'refused' if blocked else 'allowed'} ({'would ' if not m.enforced else ''}"
                       f"{m.action.replace('_', ' ')}): {m.reason}")[:1024],
        }
        if session.attrs.get("device"):
            event["device_id"] = session.attrs["device"]
        if m.approval_ref:
            event["approval_ref"] = m.approval_ref
        elif blocked:
            # AegisFlux refuses unattributed blocks; report what happened as observed instead of lying
            event.update(event_type="match_observed", blocking_applied=False,
                         detail=("blocked by a rule with no approval reference: " + event["detail"])[:1024])
        events.append(event)
    return events


class OutcomeEmitter:
    """Writes outcome events to a JSONL file and/or POSTs them to a collector."""

    def __init__(self, path: str | Path | None = None, url: str | None = None,
                 actor_id: str = "agent-intent-gateway", max_queue: int = 10_000):
        self.path = Path(path) if path else None
        self.url = url
        self.actor_id = actor_id
        self.sent = self.dropped = self.failed = 0
        self._file_lock = threading.Lock()
        self._q: queue.Queue[dict] = queue.Queue(maxsize=max_queue)
        if url:
            threading.Thread(target=self._sender, daemon=True).start()

    def __call__(self, session: Session, tool: str, decision: Decision, final: str,
                 record: dict[str, Any] | None) -> list[dict[str, Any]]:
        events = outcome_events(session, tool, decision, final, record, self.actor_id)
        if self.path and events:
            with self._file_lock, open(self.path, "a", encoding="utf-8") as fh:
                for e in events:
                    fh.write(json.dumps(e, sort_keys=True) + "\n")
        if self.url:
            for e in events:
                try:
                    self._q.put_nowait(e)
                except queue.Full:
                    self.dropped += 1
        return events

    def _sender(self) -> None:
        while True:
            event = self._q.get()
            req = urllib.request.Request(self.url, data=json.dumps(event).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5):
                    self.sent += 1
            except Exception:
                self.failed += 1
