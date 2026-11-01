"""MCP gateway: sits between an agent and an upstream MCP server (stdio).

    agent  <--stdio-->  gateway  <--stdio-->  upstream MCP server

The gateway is transport-level: it reads newline-delimited JSON-RPC, decides
every `tools/call`, and passes everything else through untouched. Denied calls
never reach the upstream server; the agent receives a normal MCP tool result
with `isError: true` explaining why, so well-behaved agents can recover.

One gateway process serves one agent session, which is how the gateway knows
*which* agent is calling and *for whom* -- the identity the switch/SGT layer
cannot see when an agent and a human share the same host.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from fnmatch import fnmatchcase
from typing import Any, Callable, IO

from .engine import Decision, Engine, Session
from .ledger import Ledger

Approver = Callable[[Session, str, dict, Decision], bool]


def deny_all(_s: Session, _t: str, _a: dict, _d: Decision) -> bool:
    return False


class Gateway:
    def __init__(
        self,
        engine: Engine,
        session: Session,
        ledger: Ledger | None = None,
        approver: Approver = deny_all,
        hide_out_of_scope: bool = True,
    ):
        self.engine = engine
        self.session = session
        self.ledger = ledger
        self.approver = approver
        self.hide_out_of_scope = hide_out_of_scope
        self._pending_lists: set[Any] = set()
        self._lock = threading.Lock()

    # -- agent -> server ------------------------------------------------------
    def from_agent(self, msg: dict) -> tuple[dict | None, dict | None]:
        """Returns (message to forward upstream, message to send back to the agent)."""
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            with self._lock:
                self._pending_lists.add(msg["id"])
            return msg, None
        if method != "tools/call":
            return msg, None

        params = msg.get("params") or {}
        tool = params.get("name", "")
        args = params.get("arguments") or {}
        with self._lock:
            decision = self.engine.evaluate(self.session, tool, args)
            final = decision.action
            if final == "require_approval":
                final = "allow" if self.approver(self.session, tool, args, decision) else "deny"
            if final == "allow":
                # Conservative: label the session at decision time, before the
                # result exists, so a racing second call can't slip past.
                self.engine.record(self.session, tool, args)
            self._log(tool, args, decision, final)

        if final == "allow":
            return msg, None
        return None, self._refusal(msg.get("id"), tool, decision)

    # -- server -> agent ------------------------------------------------------
    def from_server(self, msg: dict) -> dict:
        with self._lock:
            is_list = msg.get("id") in self._pending_lists
            if is_list:
                self._pending_lists.discard(msg["id"])
        if is_list and self.hide_out_of_scope and isinstance(msg.get("result"), dict):
            tools = msg["result"].get("tools") or []
            msg["result"]["tools"] = [t for t in tools if self._in_scope(t.get("name", ""))]
        return msg

    # -- helpers --------------------------------------------------------------
    def _in_scope(self, tool: str) -> bool:
        agent = self.engine.policy.agents.get(self.session.agent_id)
        if agent is None or self.engine.policy.tool(tool) is None:
            return False
        if any(fnmatchcase(tool, p) for p in agent.deny):
            return False
        return self.engine.policy.default != "deny" or any(
            fnmatchcase(tool, p) for p in (*agent.allow, *agent.require_approval)
        )

    def _refusal(self, req_id: Any, tool: str, d: Decision) -> dict:
        verb = "requires approval that was not granted" if d.action == "require_approval" else "was blocked"
        text = f"[agent-intent-gateway] {tool} {verb}: " + "; ".join(d.reasons)
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}], "isError": True}}

    def _log(self, tool: str, args: dict, d: Decision, final: str) -> None:
        if self.ledger is None:
            return
        self.ledger.append({
            "agent": self.session.agent_id,
            "principal": self.session.principal,
            "tool": tool,
            "args": args,
            "decision": d.action,
            "outcome": final,
            "reasons": list(d.reasons),
            "rules": list(d.rules),
            "sink": d.sink,
            "session_labels": sorted(self.session.labels),
        })


def _pump(src: IO[str], dst: IO[str], handle: Callable[[dict], list[tuple[IO[str], dict]]], raw_dst: IO[str]) -> None:
    for line in src:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            raw_dst.write(line)  # not ours to judge; pass through
            raw_dst.flush()
            continue
        for out, m in handle(msg):
            out.write(json.dumps(m) + "\n")
            out.flush()


def run_stdio(gateway: Gateway, upstream_cmd: list[str], agent_in: IO[str] = sys.stdin, agent_out: IO[str] = sys.stdout) -> int:
    proc = subprocess.Popen(upstream_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    out_lock = threading.Lock()

    class Locked:
        def write(self, s: str) -> None:
            with out_lock:
                agent_out.write(s)

        def flush(self) -> None:
            with out_lock:
                agent_out.flush()

    to_agent = Locked()

    def on_agent(msg: dict):
        fwd, reply = gateway.from_agent(msg)
        return ([(proc.stdin, fwd)] if fwd else []) + ([(to_agent, reply)] if reply else [])

    def on_server(msg: dict):
        return [(to_agent, gateway.from_server(msg))]

    t = threading.Thread(target=_pump, args=(proc.stdout, to_agent, on_server, to_agent), daemon=True)
    t.start()
    try:
        _pump(agent_in, proc.stdin, on_agent, proc.stdin)
    finally:
        proc.stdin.close()
        rc = proc.wait()
        t.join(timeout=2)
    return rc
