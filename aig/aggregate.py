"""Aggregator mode: one gateway per agent, in front of all of that agent's MCP servers.

    agent ──stdio──► aig proxy --config agent.json ──┬──► github MCP server
                         (one session, one policy)   ├──► filesystem MCP server
                                                     └──► slack MCP server

Without this, each wrapped server is a separate gateway process with its own
session, so data the agent reads through one server and sends out through
another is never seen by a single decision. Here every server shares one
session: labels, the value index and outbound history span all of them.

Tools are exposed to the agent as `<server>__<tool>` (MCP clients restrict
tool names to letters, digits, `_` and `-`), and appear in policy as
`<server>.<tool>`, e.g. `github.create_issue`.

Config (aig_agent_config.v1, JSON or YAML):

    agent: code-assistant
    principal: user:dana@corp.example
    policy: /etc/aig/policy.yaml
    log: ~/.aig/decisions.jsonl
    servers:
      github:     { command: npx, args: [-y, "@modelcontextprotocol/server-github"], env: { ... } }
      filesystem: { command: npx, args: [-y, "@modelcontextprotocol/server-filesystem", /home/dana] }

Not aggregated yet: resources, prompts, and requests a server sends to the
client (sampling, roots, elicitation). Upstreams are started without those
client capabilities, so well-behaved servers don't ask.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Callable

from . import __version__
from .gateway import Gateway

PROTOCOL = "2025-06-18"
NAME_OK = re.compile(r"[^A-Za-z0-9_-]")


def exposed_name(server: str, tool: str) -> str:
    name = NAME_OK.sub("_", f"{server}__{tool}")
    if len(name) <= 64:
        return name
    return f"{name[:55]}_{hashlib.sha1(name.encode()).hexdigest()[:8]}"


def server_key(name: str) -> str:
    return NAME_OK.sub("_", name)


@dataclass
class ExposedTool:
    exposed: str        # what the agent sees: github__create_issue
    server: str         # github
    tool: str           # create_issue (the upstream's own name)
    policy: str         # github.create_issue
    definition: dict


class UpstreamError(RuntimeError):
    pass


class Upstream:
    """One MCP server process the gateway speaks to on the agent's behalf."""

    def __init__(self, name: str, spec: dict[str, Any], on_response: Callable[[Upstream, dict], None]):
        self.name = name
        self.spec = spec
        self.on_response = on_response
        self.proc: subprocess.Popen | None = None
        self.tools: list[dict] = []
        self.error: str | None = None
        self._ids = itertools.count(1)
        self._wait: dict[Any, tuple[threading.Event, list]] = {}
        self._lock = threading.Lock()

    def start(self, timeout: float = 60) -> None:
        env = {**os.environ, **{k: str(v) for k, v in (self.spec.get("env") or {}).items()}}
        cmd = [self.spec["command"], *[str(a) for a in self.spec.get("args", [])]]
        try:
            self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
                                         text=True, bufsize=1, env=env, cwd=self.spec.get("cwd"))
        except OSError as e:
            self.error = f"could not start {cmd[0]}: {e}"
            return
        threading.Thread(target=self._read, daemon=True, name=f"aig-upstream-{self.name}").start()
        try:
            self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                        "clientInfo": {"name": "agent-intent-gateway", "version": __version__}}, timeout)
            self.notify("notifications/initialized")
            self.refresh_tools(timeout)
        except UpstreamError as e:
            self.error = str(e)

    def refresh_tools(self, timeout: float = 30) -> None:
        tools, cursor = [], None
        while True:
            res = self.request("tools/list", {"cursor": cursor} if cursor else {}, timeout)
            tools += res.get("tools", [])
            cursor = res.get("nextCursor")
            if not cursor:
                break
        self.tools = tools

    def send(self, msg: dict) -> None:
        if self.proc is None or self.proc.stdin is None or self.proc.poll() is not None:
            raise UpstreamError(f"{self.name} is not running")
        with self._lock:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()

    def notify(self, method: str, params: dict | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def request(self, method: str, params: dict, timeout: float) -> dict:
        rid = f"aig-{next(self._ids)}"
        ev, box = threading.Event(), []
        self._wait[rid] = (ev, box)
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        if not ev.wait(timeout):
            self._wait.pop(rid, None)
            raise UpstreamError(f"{self.name} did not answer {method} within {timeout:.0f}s")
        msg = box[0]
        if "error" in msg:
            raise UpstreamError(f"{self.name} refused {method}: {msg['error'].get('message')}")
        return msg.get("result") or {}

    def call(self, tool: str, arguments: dict, upstream_id: Any) -> None:
        self.send({"jsonrpc": "2.0", "id": upstream_id, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments}})

    def _read(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "method" in msg:
                if "id" in msg:   # a request from the server to the client: not supported through the gateway yet
                    try:
                        self.send({"jsonrpc": "2.0", "id": msg["id"], "error": {
                            "code": -32601, "message": f"{msg['method']} is not available through agent-intent-gateway"}})
                    except UpstreamError:
                        pass
                elif msg["method"] == "notifications/tools/list_changed":
                    threading.Thread(target=self._safe_refresh, daemon=True).start()
                continue
            waiter = self._wait.pop(msg.get("id"), None)
            if waiter:
                waiter[1].append(msg)
                waiter[0].set()
            else:
                self.on_response(self, msg)
        self.error = self.error or f"{self.name} exited"

    def _safe_refresh(self) -> None:
        try:
            self.refresh_tools()
        except UpstreamError:
            pass

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()


class Aggregator:
    def __init__(self, gateway: Gateway, servers: dict[str, dict[str, Any]], out: IO[str] = sys.stdout):
        self.gateway = gateway
        self.out = out
        self._out_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._inflight: dict[str, tuple[Upstream, Any]] = {}   # upstream id -> (upstream, client id)
        self._by_client: dict[str, tuple[Upstream, str]] = {}  # client id -> (upstream, upstream id), for cancels
        self._lock = threading.Lock()
        self.upstreams = {server_key(n): Upstream(server_key(n), s, self._on_upstream_response) for n, s in servers.items()}

    # -- lifecycle ----------------------------------------------------------------
    def start(self) -> None:
        threads = [threading.Thread(target=u.start) for u in self.upstreams.values()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for u in self.upstreams.values():
            if u.error:
                print(f"agent-intent-gateway: {u.error}", file=sys.stderr)

    def stop(self) -> None:
        for u in self.upstreams.values():
            u.stop()

    def run(self, agent_in: IO[str] = sys.stdin) -> None:
        self.start()
        try:
            for line in agent_in:
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    self._write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                    continue
                self.handle(msg)
        finally:
            self.stop()

    # -- tool catalogue -----------------------------------------------------------
    def catalogue(self) -> dict[str, ExposedTool]:
        out: dict[str, ExposedTool] = {}
        for name, u in self.upstreams.items():
            for t in u.tools:
                tool = t.get("name", "")
                e = ExposedTool(exposed_name(name, tool), name, tool, f"{name}.{tool}", t)
                out[e.exposed] = e
        return out

    # -- agent -> gateway -----------------------------------------------------------
    def handle(self, msg: dict) -> None:
        method, rid = msg.get("method"), msg.get("id")
        if method is None:
            return   # a response from the agent to a request we never send
        if rid is None:
            if method == "notifications/cancelled":
                self._cancel(msg.get("params") or {})
            return
        if method == "initialize":
            requested = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL
            return self._reply(rid, {"protocolVersion": requested, "capabilities": {"tools": {"listChanged": False}},
                                     "serverInfo": {"name": "agent-intent-gateway", "version": __version__}})
        if method == "ping":
            return self._reply(rid, {})
        if method == "tools/list":
            tools = []
            for e in self.catalogue().values():
                if self.gateway.hide_out_of_scope and not self.gateway._in_scope(e.policy):
                    continue
                d = dict(e.definition)
                d["name"] = e.exposed
                d["description"] = f"[{e.server}] {d.get('description', '')}".strip()
                tools.append(d)
            return self._reply(rid, {"tools": tools})
        if method in ("resources/list", "resources/templates/list", "prompts/list"):
            key = {"resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}[method]
            return self._reply(rid, {key: []})
        if method == "tools/call":
            return self._call(msg)
        self._write({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method {method} not found"}})

    def _call(self, msg: dict) -> None:
        params = msg.get("params") or {}
        name = params.get("name", "")
        e = self.catalogue().get(name)
        policy_name = e.policy if e else name
        gw_msg = {"jsonrpc": "2.0", "id": msg["id"], "method": "tools/call",
                  "params": {"name": policy_name, "arguments": params.get("arguments") or {}}}
        fwd, reply = self.gateway.from_agent(gw_msg)
        if reply is not None:
            return self._write(reply)
        if e is None:   # allowed by policy but no server offers it (e.g. the server failed to start)
            resp = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32602, "message": f"unknown tool {name}"}}
            return self._write(self.gateway.from_server(resp))
        up = self.upstreams[e.server]
        uid = f"agg-{next(self._ids)}"
        with self._lock:
            self._inflight[uid] = (up, msg["id"])
            self._by_client[json.dumps(msg["id"])] = (up, uid)
        try:
            up.call(e.tool, params.get("arguments") or {}, uid)
        except UpstreamError as err:
            with self._lock:
                self._inflight.pop(uid, None)
                self._by_client.pop(json.dumps(msg["id"]), None)
            resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {
                "content": [{"type": "text", "text": f"[agent-intent-gateway] {err}"}], "isError": True}}
            self._write(self.gateway.from_server(resp))

    def _cancel(self, params: dict) -> None:
        with self._lock:
            hit = self._by_client.get(json.dumps(params.get("requestId")))
        if hit:
            up, uid = hit
            try:
                up.notify("notifications/cancelled", {"requestId": uid, "reason": params.get("reason", "")})
            except UpstreamError:
                pass

    # -- upstream -> agent ----------------------------------------------------------
    def _on_upstream_response(self, up: Upstream, msg: dict) -> None:
        with self._lock:
            hit = self._inflight.pop(msg.get("id"), None)
            if hit:
                self._by_client.pop(json.dumps(hit[1]), None)
        if not hit:
            return
        resp = {"jsonrpc": "2.0", "id": hit[1], **({"result": msg["result"]} if "result" in msg else {"error": msg.get("error")})}
        self._write(self.gateway.from_server(resp))   # the gateway indexes the result's values for this session

    def _reply(self, rid: Any, result: dict) -> None:
        self._write({"jsonrpc": "2.0", "id": rid, "result": result})

    def _write(self, msg: dict) -> None:
        with self._out_lock:
            self.out.write(json.dumps(msg) + "\n")
            self.out.flush()


def load_agent_config(path: str | Path) -> dict[str, Any]:
    text = Path(path).expanduser().read_text(encoding="utf-8")
    if str(path).endswith((".yaml", ".yml")):
        import yaml
        cfg = yaml.safe_load(text)
    else:
        cfg = json.loads(text)
    if not isinstance(cfg, dict) or not isinstance(cfg.get("servers"), dict) or not cfg["servers"]:
        raise ValueError(f"{path}: an agent config needs a servers map")
    for name, spec in cfg["servers"].items():
        if not isinstance(spec, dict) or not spec.get("command"):
            raise ValueError(f"{path}: server {name!r} needs a command")
    for key in ("policy", "log", "label_store", "overlay_key", "emit_events"):
        if isinstance(cfg.get(key), str):
            cfg[key] = str(Path(cfg[key]).expanduser())
    cfg["overlays"] = [str(Path(o).expanduser()) for o in cfg.get("overlays", [])]
    return cfg
