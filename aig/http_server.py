"""MCP Streamable HTTP mode: the gateway as a network service.

    agent ──► (AegisFlux steering gateway) ──► aig serve ──► upstream MCP server(s)

The agent is configured to use the gateway as its MCP server, so nothing is
intercepted and no gateway CA is needed. Every request carries a per-stream
identity token (aig.token); who the agent is, who it acts for and its policy
class come from that token only.

Implements the parts of the MCP Streamable HTTP transport (2025-06-18) a
gateway needs: POST of single JSON-RPC messages, JSON responses,
`Mcp-Session-Id`, 202 for notifications, DELETE to end a session, 405 for the
optional GET stream, and Origin checks against DNS rebinding.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .engine import Engine, Session
from .gateway import Gateway
from .ledger import Ledger
from .token import Identity, TokenError, verify

SESSION_HEADER = "Mcp-Session-Id"
IDLE_TIMEOUT = 3600
MAX_BODY = 1 << 20


class Upstream(Protocol):
    def open(self) -> Any: ...
    def send(self, handle: Any, msg: dict) -> dict | None: ...


class SimUpstream:
    """The simulated enterprise, in process. One shared backend for all sessions."""

    def __init__(self) -> None:
        from .sim import Enterprise

        self.enterprise = Enterprise()
        self._lock = threading.Lock()

    def open(self) -> None:
        return None

    def send(self, handle: Any, msg: dict) -> dict | None:
        with self._lock:
            return self.enterprise.handle(msg)


class HttpUpstream:
    """A real MCP server speaking Streamable HTTP."""

    def __init__(self, url: str, timeout: float = 30):
        self.url, self.timeout = url, timeout

    def open(self) -> dict:
        return {"sid": None}

    def send(self, handle: dict, msg: dict) -> dict | None:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if handle.get("sid"):
            headers[SESSION_HEADER] = handle["sid"]
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            if sid := resp.headers.get(SESSION_HEADER):
                handle["sid"] = sid
            if resp.status == 202 or "id" not in msg:
                return None
            body = resp.read().decode()
            if resp.headers.get_content_type() == "text/event-stream":
                # Return the event that answers this request.
                for chunk in body.split("\n\n"):
                    data = "\n".join(l[5:].lstrip() for l in chunk.splitlines() if l.startswith("data:"))
                    if data:
                        event = json.loads(data)
                        if event.get("id") == msg["id"]:
                            return event
                return None
            return json.loads(body)


@dataclass
class McpSession:
    gateway: Gateway
    binding: tuple[str, str, str, str]
    upstream: Any
    jtis: set[str] = field(default_factory=set)
    last_seen: float = field(default_factory=time.time)


class GatewayServer:
    def __init__(self, engine: Engine, key: Ed25519PublicKey, audience: str, upstream: Upstream,
                 ledger: Ledger | None = None, revoked: set[str] | None = None,
                 allowed_origins: set[str] | None = None, host: str = "127.0.0.1", port: int = 8443):
        self.engine, self.key, self.audience, self.upstream = engine, key, audience, upstream
        self.ledger = ledger
        self.revoked = revoked or set()
        self.allowed_origins = allowed_origins or set()
        self.sessions: dict[str, McpSession] = {}
        self.jti_owner: dict[str, str] = {}
        self.lock = threading.Lock()
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}/mcp"

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        return t

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- request handling (transport-independent, so it can be tested directly) --
    def handle_post(self, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, str], dict | None]:
        try:
            ident = self._authenticate(headers)
        except TokenError as e:
            return 401, {"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{e}"'}, \
                _rpc_error(None, -32001, f"unauthorized: {e}")

        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            return 400, {}, _rpc_error(None, -32700, "parse error")
        if not isinstance(msg, dict):
            return 400, {}, _rpc_error(None, -32600, "send one JSON-RPC message per request (no batching)")

        sid = headers.get(SESSION_HEADER.lower())
        if msg.get("method") == "initialize":
            if sid:
                return 400, {}, _rpc_error(msg.get("id"), -32600, "initialize must not carry a session id")
            sid, sess = self._new_session(ident)
            resp = self.upstream.send(sess.upstream, msg)
            return 200, {SESSION_HEADER: sid}, resp

        if not sid:
            return 400, {}, _rpc_error(msg.get("id"), -32600, f"missing {SESSION_HEADER}")
        with self.lock:
            sess = self.sessions.get(sid)
            if sess is None:
                return 404, {}, _rpc_error(msg.get("id"), -32001, "unknown or expired session")
            if ident.binding() != sess.binding:
                return 403, {}, _rpc_error(msg.get("id"), -32001,
                                           "token identity does not match the identity that opened this session")
            owner = self.jti_owner.setdefault(ident.jti, sid)
            if owner != sid:
                return 401, {}, _rpc_error(msg.get("id"), -32001, "token already bound to another session (replay)")
            sess.jtis.add(ident.jti)
            sess.last_seen = time.time()
            # The newest backend-minted token is authoritative for class: a mid-session
            # move to quarantine takes effect on the very next request.
            sess.gateway.session.klass = ident.klass
            sess.gateway.session.attrs["token"] = ident.jti

        fwd, reply = sess.gateway.from_agent(msg)
        if reply is not None:
            return 200, {}, reply
        resp = self.upstream.send(sess.upstream, fwd)
        if resp is None:
            return 202, {}, None
        return 200, {}, sess.gateway.from_server(resp)

    def handle_delete(self, headers: dict[str, str]) -> int:
        try:
            ident = self._authenticate(headers)
        except TokenError:
            return 401
        sid = headers.get(SESSION_HEADER.lower())
        with self.lock:
            sess = self.sessions.get(sid or "")
            if sess is None:
                return 404
            if ident.binding() != sess.binding:
                return 403
            del self.sessions[sid]
        return 204

    def _authenticate(self, headers: dict[str, str]) -> Identity:
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise TokenError("missing bearer token")
        return verify(auth[7:].strip(), self.key, audience=self.audience,
                      policy_version=self.engine.policy.policy_version, revoked=self.revoked)

    def _new_session(self, ident: Identity) -> tuple[str, McpSession]:
        session = Session(ident.agent, ident.principal, klass=ident.klass,
                          attrs={"instance": ident.instance, "device": ident.device, "token": ident.jti})
        sess = McpSession(Gateway(self.engine, session, self.ledger), ident.binding(), self.upstream.open(),
                          {ident.jti})
        sid = uuid.uuid4().hex
        with self.lock:
            now = time.time()
            for old in [k for k, s in self.sessions.items() if now - s.last_seen > IDLE_TIMEOUT]:
                del self.sessions[old]
            if ident.jti in self.jti_owner:
                raise TokenError("token already bound to another session (replay)")
            self.jti_owner[ident.jti] = sid
            self.sessions[sid] = sess
        return sid, sess

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "agent-intent-gateway"

            def log_message(self, fmt: str, *args: Any) -> None:  # quiet; the ledger is the log
                pass

            def _headers(self) -> dict[str, str]:
                return {k.lower(): v for k, v in self.headers.items()}

            def _origin_ok(self) -> bool:
                origin = self.headers.get("Origin")
                return origin is None or origin in server.allowed_origins

            def _send(self, status: int, headers: dict[str, str], body: dict | None) -> None:
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                if body is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                if self.path.split("?")[0] != "/mcp":
                    return self._send(404, {}, None)
                if not self._origin_ok():
                    return self._send(403, {}, _rpc_error(None, -32001, "origin not allowed"))
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    return self._send(413, {}, _rpc_error(None, -32600, "request too large"))
                try:
                    self._send(*server.handle_post(self._headers(), self.rfile.read(length)))
                except TokenError as e:
                    self._send(401, {}, _rpc_error(None, -32001, f"unauthorized: {e}"))
                except Exception as e:  # upstream failure: tell the agent, keep serving
                    self._send(502, {}, _rpc_error(None, -32603, f"upstream error: {type(e).__name__}"))

            def do_DELETE(self) -> None:
                if not self._origin_ok():
                    return self._send(403, {}, None)
                self._send(server.handle_delete(self._headers()), {}, None)

            def do_GET(self) -> None:
                self._send(405, {"Allow": "POST, DELETE"}, None)

        return Handler


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
