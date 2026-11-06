"""Put AIG in front of the MCP servers that AI clients on this machine use.

    aig wrap              plan only: what would change (default, writes nothing)
    aig wrap --apply      rewrite the client configs, with backups
    aig wrap --check      report drift: unwrapped configs, new servers, tampering (exit 1)
    aig wrap --undo       restore every wrapped config
    add --json for a machine-readable plan (aig_wrap_plan.v1)

For each MCP server map in a client config (Claude Desktop, Claude Code,
Cursor, Windsurf, VS Code), the stdio servers move into one aggregator
config (aig_agent_config.v1, file mode 0600) and the client gets a single
entry that starts `aig proxy --config <that file>`. The agent keeps the same
tools, now behind one gateway session. Remote (URL) servers are left as they
are and reported: they need the central gateway or traffic steering.

Built to be driven by an endpoint agent such as AegisFlux:
- the plan is the default; nothing is written without --apply;
- the JSON plan never contains server arguments or environment values, only
  names, transports and command basenames (as AegisFlux's AI-BOM rules require);
- writes are atomic, keep the file's mode and owner (so a service account can
  write a user's config), and every original is backed up first;
- --check is cheap and side-effect free, for periodic drift detection;
- --undo restores servers from the aggregator configs, keeping anything the
  user added since.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PLAN_SCHEMA = "aig_wrap_plan.v1"
AGENT_SCHEMA = "aig_agent_config.v1"


@dataclass(frozen=True)
class Client:
    id: str
    label: str
    paths: dict[str, list[str]]       # platform -> config paths (~ = home; %APPDATA% expanded on Windows)
    key: str = "mcpServers"           # where the server map lives
    projects: bool = False            # Claude Code: also projects.<dir>.mcpServers
    project_files: tuple[str, ...] = ()   # per-project config file names, relative to a project dir
    stdio_type: bool = False          # VS Code entries carry "type": "stdio"


# Known locations as of November 2026. Clients move these; verify against current client docs.
CLIENTS: list[Client] = [
    Client("claude-desktop", "Claude Desktop", {
        "Darwin": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "Windows": ["%APPDATA%/Claude/claude_desktop_config.json"],
        "Linux": ["~/.config/Claude/claude_desktop_config.json"]}),
    Client("claude-code", "Claude Code", {p: ["~/.claude.json"] for p in ("Darwin", "Windows", "Linux")},
           projects=True, project_files=(".mcp.json",)),
    Client("cursor", "Cursor", {p: ["~/.cursor/mcp.json"] for p in ("Darwin", "Windows", "Linux")},
           project_files=(".cursor/mcp.json",)),
    Client("windsurf", "Windsurf", {p: ["~/.codeium/windsurf/mcp_config.json"] for p in ("Darwin", "Windows", "Linux")}),
    Client("vscode", "VS Code", {
        "Darwin": ["~/Library/Application Support/Code/User/mcp.json"],
        "Windows": ["%APPDATA%/Code/User/mcp.json"],
        "Linux": ["~/.config/Code/User/mcp.json"]}, key="servers", project_files=(".vscode/mcp.json",), stdio_type=True),
]


@dataclass
class Settings:
    home: Path
    state_dir: Path
    policy: str
    principal: str
    aig_command: list[str]
    agent: str | None = None          # default: the client id
    entry_name: str = "aig"
    system: str = field(default_factory=platform.system)


def default_settings(home: Path | None = None, state_dir: Path | None = None) -> Settings:
    home = home or Path.home()
    state = state_dir or home / ".aig"
    aig = shutil.which("aig")
    return Settings(home=home, state_dir=state, policy=str(state / "policy.yaml"),
                    principal=f"user:{getpass.getuser()}@{socket.getfqdn() or 'localhost'}",
                    aig_command=[aig] if aig else [sys.executable, "-m", "aig.cli"])


# ---- reading configs -----------------------------------------------------------------------------
def _expand(p: str, s: Settings) -> Path:
    if "%APPDATA%" in p:
        p = p.replace("%APPDATA%", os.environ.get("APPDATA", str(s.home / "AppData" / "Roaming")))
    return Path(p.replace("~", str(s.home), 1) if p.startswith("~") else p)


def _pointer_get(doc: Any, pointer: tuple[str, ...]) -> Any:
    for k in pointer:
        if not isinstance(doc, dict) or k not in doc:
            return None
        doc = doc[k]
    return doc


def _pointer_set(doc: dict, pointer: tuple[str, ...], value: Any) -> None:
    for k in pointer[:-1]:
        doc = doc.setdefault(k, {})
    doc[pointer[-1]] = value


def server_maps(client: Client, doc: Any) -> list[tuple[str, ...]]:
    """JSON pointers to every MCP server map in a client config."""
    out = []
    if isinstance(_pointer_get(doc, (client.key,)), dict):
        out.append((client.key,))
    if client.projects and isinstance(doc, dict) and isinstance(doc.get("projects"), dict):
        for proj, cfg in doc["projects"].items():
            if isinstance(cfg, dict) and isinstance(cfg.get(client.key), dict) and cfg[client.key]:
                out.append(("projects", proj, client.key))
    return out


def transport(spec: Any) -> str:
    if not isinstance(spec, dict):
        return "invalid"
    if spec.get("url") or spec.get("serverUrl") or spec.get("type") in ("http", "sse", "streamable-http"):
        return "remote"
    return "stdio" if spec.get("command") else "invalid"


def is_aig_entry(spec: Any) -> bool:
    if not isinstance(spec, dict) or not spec.get("command"):
        return False
    argv = [str(spec["command"]), *map(str, spec.get("args", []))]
    return "proxy" in argv and "--config" in argv and any(Path(a).name in ("aig", "aig.exe", "aig.cli") or a == "aig.cli" for a in argv)


def config_files(s: Settings, projects: list[Path] | None = None, only: set[str] | None = None) -> list[tuple[Client, Path]]:
    found = []
    for c in CLIENTS:
        if only and c.id not in only:
            continue
        for p in c.paths.get(s.system, c.paths.get("Linux", [])):
            found.append((c, _expand(p, s)))
        for proj in projects or []:
            for rel in c.project_files:
                found.append((c, proj / rel))
    return found


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ---- state ------------------------------------------------------------------------------------
def _state_file(s: Settings) -> Path:
    return s.state_dir / "wrap-state.json"


def load_state(s: Settings) -> dict[str, Any]:
    try:
        return json.loads(_state_file(s).read_text())
    except (OSError, json.JSONDecodeError):
        return {"entries": {}}


def _save_state(s: Settings, state: dict) -> None:
    _write_private(_state_file(s), json.dumps(state, indent=2, sort_keys=True))


def _key(path: Path, pointer: tuple[str, ...]) -> str:
    return f"{path}#{json.dumps(list(pointer))}"   # pointers are lists: project paths contain "/"


def _agent_cfg_path(s: Settings, client: Client, path: Path, pointer: tuple[str, ...]) -> Path:
    h = hashlib.sha1(_key(path, pointer).encode()).hexdigest()[:8]
    return s.state_dir / "agents" / f"{client.id}-{h}.json"


def _map_hash(m: Any) -> str:
    return hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()


# ---- writing ----------------------------------------------------------------------------------
def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.aig-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _write_like(path: Path, text: str) -> None:
    """Atomic replace that keeps the original file's mode and owner."""
    st = path.stat()
    tmp = path.with_name(f".{path.name}.aig-tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, st.st_mode & 0o7777)
    if hasattr(os, "chown"):
        try:
            os.chown(tmp, st.st_uid, st.st_gid)   # a service account writing a user's file keeps it the user's
        except PermissionError:
            pass
    os.replace(tmp, path)


def _backup(s: Settings, path: Path) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%S")
    dest = s.state_dir / "backups" / f"{str(path).strip('/').replace('/', '_').replace(':', '')}.{stamp}.json"
    _write_private(dest, path.read_text(encoding="utf-8"))
    return dest


# ---- plan / apply ------------------------------------------------------------------------------
def _server_view(name: str, spec: Any, status: str) -> dict[str, Any]:
    """What a plan may say about a server: never its arguments or environment."""
    cmd = spec.get("command") if isinstance(spec, dict) else None
    return {"name": name, "transport": transport(spec), "command": Path(str(cmd)).name if cmd else None, "status": status}


def plan(s: Settings, projects: list[Path] | None = None, only: set[str] | None = None) -> dict[str, Any]:
    actions = []
    for client, path in config_files(s, projects, only):
        if not path.exists():
            continue
        try:
            doc = _read_json(path)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            actions.append({"client": client.id, "path": str(path), "pointer": None, "action": "unreadable",
                            "detail": type(e).__name__, "servers": []})
            continue
        for pointer in server_maps(client, doc):
            smap = _pointer_get(doc, pointer)
            servers, wrap_names = [], []
            for name, spec in smap.items():
                if is_aig_entry(spec):
                    servers.append(_server_view(name, spec, "aig_entry"))
                elif transport(spec) == "stdio":
                    servers.append(_server_view(name, spec, "will_wrap"))
                    wrap_names.append(name)
                elif transport(spec) == "remote":
                    servers.append(_server_view(name, spec, "remote_needs_central_gateway"))
                else:
                    servers.append(_server_view(name, spec, "invalid_left_as_is"))
            already = any(v["status"] == "aig_entry" for v in servers)
            action = "wrap" if wrap_names and not already else ("add_to_wrap" if wrap_names else ("wrapped" if already else "nothing_to_wrap"))
            actions.append({"client": client.id, "path": str(path), "pointer": list(pointer), "action": action,
                            "agent_config": str(_agent_cfg_path(s, client, path, pointer)), "servers": servers})
    return {"schema": PLAN_SCHEMA, "generated_ms": int(time.time() * 1000), "host": socket.gethostname(),
            "user": getpass.getuser(), "actions": actions,
            "summary": {"configs": len({a["path"] for a in actions}),
                        "to_wrap": sum(1 for a in actions for v in a["servers"] if v["status"] == "will_wrap"),
                        "remote": sum(1 for a in actions for v in a["servers"] if v["status"].startswith("remote")),
                        "unreadable": sum(1 for a in actions if a["action"] == "unreadable")}}


def apply(s: Settings, projects: list[Path] | None = None, only: set[str] | None = None) -> dict[str, Any]:
    p = plan(s, projects, only)
    state = load_state(s)
    clients = {c.id: c for c in CLIENTS}
    for act in p["actions"]:
        if act["action"] not in ("wrap", "add_to_wrap"):
            continue
        client, path, pointer = clients[act["client"]], Path(act["path"]), tuple(act["pointer"])
        doc = _read_json(path)
        smap: dict = _pointer_get(doc, pointer)
        cfg_path = Path(act["agent_config"])
        try:
            agent_cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else None
        except json.JSONDecodeError:
            agent_cfg = None
        agent_cfg = agent_cfg or {
            "schema": AGENT_SCHEMA, "agent": s.agent or client.id, "principal": s.principal, "policy": s.policy,
            "log": str(s.state_dir / "logs" / f"{client.id}.jsonl"), "label_store": str(s.state_dir / "labels.json"),
            "source": {"client": client.id, "path": str(path), "pointer": act["pointer"]}, "servers": {}}
        new_map: dict[str, Any] = {}
        entry = s.entry_name
        for name, spec in smap.items():
            if transport(spec) == "stdio" and not is_aig_entry(spec):
                agent_cfg["servers"][name] = {k: v for k, v in spec.items() if k in ("command", "args", "env", "cwd", "framing")}
                if spec.get("disabled"):
                    agent_cfg["servers"].pop(name)
                    agent_cfg.setdefault("disabled", {})[name] = spec
            elif is_aig_entry(spec):
                entry = name
            else:
                new_map[name] = spec
        if entry in new_map:          # a user server already uses the name
            entry = f"{entry}-gateway"
        new_map[entry] = {**({"type": "stdio"} if client.stdio_type else {}),
                          "command": s.aig_command[0], "args": [*s.aig_command[1:], "proxy", "--config", str(cfg_path)]}
        agent_cfg["wrapped_ms"] = int(time.time() * 1000)
        backup = _backup(s, path)
        _write_private(cfg_path, json.dumps(agent_cfg, indent=2))
        _pointer_set(doc, pointer, new_map)
        _write_like(path, json.dumps(doc, indent=2) + "\n")
        state["entries"][_key(path, pointer)] = {
            "client": client.id, "path": str(path), "pointer": act["pointer"], "agent_config": str(cfg_path),
            "entry": entry, "backup": str(backup), "map_sha256": _map_hash(new_map), "wrapped_ms": agent_cfg["wrapped_ms"]}
        act["applied"] = True
        act["backup"] = str(backup)
    _save_state(s, state)
    return p


# ---- check / undo -----------------------------------------------------------------------------
def check(s: Settings, projects: list[Path] | None = None, only: set[str] | None = None) -> dict[str, Any]:
    """Drift report: wrapped configs that changed, and configs with servers outside AIG."""
    state = load_state(s)
    findings = []
    for key, e in state["entries"].items():
        path, pointer = Path(e["path"]), tuple(e["pointer"])
        if not path.exists():
            findings.append({"key": key, "client": e["client"], "status": "config_missing"})
            continue
        try:
            smap = _pointer_get(_read_json(path), pointer)
        except (OSError, json.JSONDecodeError):
            findings.append({"key": key, "client": e["client"], "status": "config_unreadable"})
            continue
        smap = smap if isinstance(smap, dict) else {}
        if not is_aig_entry(smap.get(e["entry"])):
            findings.append({"key": key, "client": e["client"], "status": "gateway_removed"})
        bypass = [n for n, sp in smap.items() if transport(sp) == "stdio" and not is_aig_entry(sp)]
        if bypass:
            findings.append({"key": key, "client": e["client"], "status": "servers_outside_gateway", "servers": bypass})
        if not Path(e["agent_config"]).exists():
            findings.append({"key": key, "client": e["client"], "status": "agent_config_missing"})
    known = {(e["path"], tuple(e["pointer"])) for e in state["entries"].values()}
    for act in plan(s, projects, only)["actions"]:
        if act["action"] == "wrap" and (act["path"], tuple(act["pointer"])) not in known:
            findings.append({"key": _key(Path(act["path"]), tuple(act["pointer"])), "client": act["client"],
                             "status": "not_wrapped", "servers": [v["name"] for v in act["servers"] if v["status"] == "will_wrap"]})
    return {"schema": "aig_wrap_check.v1", "generated_ms": int(time.time() * 1000), "host": socket.gethostname(),
            "ok": not findings, "wrapped": len(state["entries"]), "findings": findings}


def undo(s: Settings) -> dict[str, Any]:
    state = load_state(s)
    restored = []
    for key, e in list(state["entries"].items()):
        path, pointer = Path(e["path"]), tuple(e["pointer"])
        if not path.exists():
            restored.append({"key": key, "status": "config_missing"})
            state["entries"].pop(key)
            continue
        doc = _read_json(path)
        smap = dict(_pointer_get(doc, pointer) or {})
        try:
            agent_cfg = json.loads(Path(e["agent_config"]).read_text())
        except (OSError, json.JSONDecodeError):
            restored.append({"key": key, "status": "agent_config_missing", "backup": e["backup"]})
            continue
        if is_aig_entry(smap.get(e["entry"])):
            smap.pop(e["entry"])
        clients = {c.id: c for c in CLIENTS}
        stdio_type = clients.get(e["client"], CLIENTS[0]).stdio_type
        for name, spec in agent_cfg.get("servers", {}).items():
            smap.setdefault(name, {**({"type": "stdio"} if stdio_type else {}), **spec})   # keep anything the user changed since
        for name, spec in agent_cfg.get("disabled", {}).items():
            smap.setdefault(name, spec)
        _pointer_set(doc, pointer, smap)
        _write_like(path, json.dumps(doc, indent=2) + "\n")
        restored.append({"key": key, "status": "restored", "servers": sorted(agent_cfg.get("servers", {}))})
        state["entries"].pop(key)
    _save_state(s, state)
    return {"schema": "aig_wrap_undo.v1", "restored": restored}


def render(report: dict[str, Any]) -> str:
    """Human-readable form of a plan, check or undo report."""
    lines = []
    if report.get("schema") == PLAN_SCHEMA:
        if not report["actions"]:
            return "No MCP client configurations found."
        for a in report["actions"]:
            where = a["path"] + (f"  [project {a['pointer'][1]}]" if a.get("pointer") and len(a["pointer"]) == 3 else "")
            verb = {"wrap": "will wrap", "add_to_wrap": "will add to the gateway", "wrapped": "already behind AIG",
                    "nothing_to_wrap": "nothing to wrap", "unreadable": "could not read"}[a["action"]]
            if a.get("applied"):
                verb = "wrapped" if a["action"] == "wrap" else "added to the gateway"
            lines.append(f"{a['client']}: {verb}\n  {where}")
            for v in a["servers"]:
                lines.append(f"    {v['name']:<24} {v['status'].replace('_', ' ')}")
        sm = report["summary"]
        lines.append(f"\n{sm['to_wrap']} server(s) to put behind AIG, {sm['remote']} remote, {sm['unreadable']} unreadable config(s).")
    elif report.get("schema") == "aig_wrap_check.v1":
        lines.append(f"{'OK' if report['ok'] else 'DRIFT'}: {report['wrapped']} wrapped config(s), {len(report['findings'])} finding(s)")
        for f in report["findings"]:
            extra = f" ({', '.join(f['servers'])})" if f.get("servers") else ""
            lines.append(f"  {f['status'].replace('_', ' ')}: {f['key']}{extra}")
    else:
        for r in report["restored"]:
            lines.append(f"{r['status'].replace('_', ' ')}: {r['key']}")
        lines = lines or ["Nothing to restore."]
    return "\n".join(lines)


# ---- onboarding: a starter policy from the tools the servers really offer --------------------
STARTER_HEADER = """\
# Starter policy written by `aig policy-init`.
#
# Every tool the servers offered is declared and allowed, so nothing changes for
# the agent: the gateway only records what it does. Watch the decisions in
# `aig console`, then tighten:
#   1. label tools that return sensitive data:      reads: [finance]
#   2. mark tools whose arguments leave the company: sink: external
#   3. add data-flow rules, e.g.
#      flows:
#        - { from: finance, to: external, action: deny, precision: value, residual: require_approval }
#   4. move risky tools from allow to require_approval or deny.
# Tools a server adds later are refused until they are declared here.
"""


def discover_tools(servers: dict[str, dict], timeout: float = 60) -> dict[str, list[dict]]:
    """Start each server, list its tools, stop it. Returns server -> tools (empty on failure)."""
    from .aggregate import Upstream, server_key

    out: dict[str, list[dict]] = {}
    for name, spec in servers.items():
        u = Upstream(server_key(name), spec, lambda *_: None)
        u.start(timeout)
        out[server_key(name)] = [] if u.error else u.tools
        if u.error:
            print(f"aig: could not list tools for {name}: {u.error}", file=sys.stderr)
        u.stop()
    return out


def starter_policy(s: Settings, projects: list[Path] | None = None, only: set[str] | None = None,
                   timeout: float = 60) -> tuple[dict[str, Any], list[str]]:
    """Observe-first policy covering every client config found on this machine."""
    tools: dict[str, dict] = {}
    agents: dict[str, dict] = {}
    notes: list[str] = []
    for act in plan(s, projects, only)["actions"]:
        if act["action"] == "unreadable":
            continue
        if act["action"] in ("wrapped", "add_to_wrap") and Path(act["agent_config"]).exists():
            servers = json.loads(Path(act["agent_config"]).read_text()).get("servers", {})
        else:
            smap = _pointer_get(_read_json(Path(act["path"])), tuple(act["pointer"])) or {}
            servers = {n: sp for n, sp in smap.items() if transport(sp) == "stdio" and not is_aig_entry(sp)
                       and not sp.get("disabled")}
        if not servers:
            continue
        found = discover_tools(servers, timeout)
        agent_id = s.agent or act["client"]
        a = agents.setdefault(agent_id, {
            "id": agent_id, "purpose": f"{act['client']} (starter policy: every discovered tool allowed, all calls recorded)",
            "on_behalf_of": ["user:*@*"], "allow": []})
        for server, ts in found.items():
            notes.append(f"{act['client']}: {server} offers {len(ts)} tool(s)")
            for t in ts:
                name = f"{server}.{t.get('name', '')}"
                tools.setdefault(name, {})
                if name not in a["allow"]:
                    a["allow"].append(name)
    policy = {"version": 1, "default": "deny", "tools": tools, "agents": list(agents.values()), "flows": []}
    return policy, notes
