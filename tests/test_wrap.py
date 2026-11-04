"""aig wrap: rewriting MCP client configs to go through the gateway, and undoing it."""
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from aig import wrap as w
from aig.cli import main

FAKE = str(Path(__file__).parent / "fixtures" / "fake_mcp.py")
SECRET = "ghp_THIS_IS_A_SECRET_TOKEN"


def files_server():
    return {"command": sys.executable, "args": [FAKE, "files"], "env": {"GITHUB_TOKEN": SECRET}}


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    desk = h / ".config" / "Claude" / "claude_desktop_config.json"
    desk.parent.mkdir(parents=True)
    desk.write_text(json.dumps({"mcpServers": {"files": files_server(),
                                               "chat": {"command": sys.executable, "args": [FAKE, "chat"]}},
                                "theme": "dark"}))
    os.chmod(desk, 0o640)
    (h / ".claude.json").write_text(json.dumps({
        "numStartups": 42, "mcpServers": {"files": files_server()},
        "projects": {"/work/app": {"mcpServers": {"chat": {"command": sys.executable, "args": [FAKE, "chat"]}},
                                   "allowedTools": []},
                     "/work/empty": {"mcpServers": {}}}}))
    (h / ".cursor").mkdir()
    (h / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "files": files_server(), "remote-crm": {"url": "https://mcp.crm.example/sse"}}}))
    vs = h / ".config" / "Code" / "User" / "mcp.json"
    vs.parent.mkdir(parents=True)
    vs.write_text(json.dumps({"servers": {"files": {"type": "stdio", **files_server()}}}))
    (h / ".codeium" / "windsurf").mkdir(parents=True)
    (h / ".codeium" / "windsurf" / "mcp_config.json").write_text("{ not json")
    return h


@pytest.fixture
def settings(home, tmp_path):
    s = w.default_settings(home)
    s.system = "Linux"
    s.aig_command = [sys.executable, "-m", "aig.cli"]
    s.principal = "user:dana@corp.example"
    return s


def desktop(home):
    return json.loads((home / ".config" / "Claude" / "claude_desktop_config.json").read_text())


def test_plan_finds_everything_and_changes_nothing(home, settings):
    before = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    p = w.plan(settings)
    assert {p for p in home.rglob("*") if p.is_file()} == set(before) and all(k.read_bytes() == v for k, v in before.items())
    by = {(a["client"], tuple(a["pointer"] or ())): a for a in p["actions"]}
    assert by[("claude-desktop", ("mcpServers",))]["action"] == "wrap"
    assert by[("claude-code", ("projects", "/work/app", "mcpServers"))]["action"] == "wrap"
    assert ("claude-code", ("projects", "/work/empty", "mcpServers")) not in by
    assert {v["name"]: v["status"] for v in by[("cursor", ("mcpServers",))]["servers"]}["remote-crm"] == "remote_needs_central_gateway"
    assert any(a["client"] == "windsurf" and a["action"] == "unreadable" for a in p["actions"])
    assert p["summary"]["to_wrap"] == 6


def test_plan_never_contains_arguments_or_secrets(settings):
    text = json.dumps(w.plan(settings))
    assert SECRET not in text and FAKE not in text and "GITHUB_TOKEN" not in text


def test_apply_rewrites_configs_and_keeps_everything_else(home, settings):
    w.apply(settings)
    d = desktop(home)
    assert d["theme"] == "dark" and list(d["mcpServers"]) == ["aig"]
    assert w.is_aig_entry(d["mcpServers"]["aig"])
    assert stat.S_IMODE((home / ".config" / "Claude" / "claude_desktop_config.json").stat().st_mode) == 0o640
    code = json.loads((home / ".claude.json").read_text())
    assert code["numStartups"] == 42 and code["projects"]["/work/app"]["allowedTools"] == []
    assert list(code["projects"]["/work/app"]["mcpServers"]) == ["aig"]
    cursor = json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]
    assert set(cursor) == {"aig", "remote-crm"}                       # remote server left as is
    vs = json.loads((home / ".config" / "Code" / "User" / "mcp.json").read_text())["servers"]
    assert vs["aig"]["type"] == "stdio"


def test_secrets_stay_on_device_in_private_files(home, settings):
    w.apply(settings)
    cfg_path = Path(desktop(home)["mcpServers"]["aig"]["args"][-1])
    cfg = json.loads(cfg_path.read_text())
    assert cfg["servers"]["files"]["env"]["GITHUB_TOKEN"] == SECRET    # the server still gets its token...
    assert stat.S_IMODE(cfg_path.stat().st_mode) == 0o600               # ...from a file only the user can read
    assert SECRET not in (home / ".config" / "Claude" / "claude_desktop_config.json").read_text()
    for b in (settings.state_dir / "backups").iterdir():
        assert stat.S_IMODE(b.stat().st_mode) == 0o600


def test_apply_is_idempotent(home, settings):
    w.apply(settings)
    first = desktop(home)
    again = w.apply(settings)
    assert desktop(home) == first
    assert not any(a.get("applied") for a in again["actions"])


def test_new_server_added_later_joins_the_gateway(home, settings):
    w.apply(settings)
    d = desktop(home)
    d["mcpServers"]["notes"] = {"command": sys.executable, "args": [FAKE, "files"]}
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(json.dumps(d))
    assert w.check(settings)["findings"][0]["status"] == "servers_outside_gateway"
    w.apply(settings)
    assert list(desktop(home)["mcpServers"]) == ["aig"]
    cfg = json.loads(Path(desktop(home)["mcpServers"]["aig"]["args"][-1]).read_text())
    assert set(cfg["servers"]) == {"files", "chat", "notes"}


def test_name_collision_with_a_users_server(home, settings):
    p = home / ".config" / "Claude" / "claude_desktop_config.json"
    p.write_text(json.dumps({"mcpServers": {"aig": {"url": "https://aig.example/mcp"}, "files": files_server()}}))
    w.apply(settings)
    assert set(desktop(home)["mcpServers"]) == {"aig", "aig-gateway"}


def test_check_reports_drift(home, settings):
    w.apply(settings)
    assert w.check(settings)["ok"]
    d = desktop(home)
    d["mcpServers"] = {"files": files_server()}                     # someone puts the original back
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(json.dumps(d))
    statuses = {f["status"] for f in w.check(settings)["findings"]}
    assert {"gateway_removed", "servers_outside_gateway"} <= statuses


def test_check_finds_new_unwrapped_clients(home, settings):
    w.apply(settings, only={"claude-desktop"})
    found = w.check(settings)["findings"]
    assert {f["client"] for f in found if f["status"] == "not_wrapped"} == {"claude-code", "cursor", "vscode"}


def test_undo_restores_and_keeps_user_changes(home, settings):
    original = desktop(home)
    w.apply(settings)
    d = desktop(home)
    d["mcpServers"]["mine"] = {"url": "https://example/mcp"}         # added by the user while wrapped
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(json.dumps(d))
    w.undo(settings)
    restored = desktop(home)
    assert restored["mcpServers"]["files"] == original["mcpServers"]["files"]
    assert restored["mcpServers"]["chat"] == original["mcpServers"]["chat"]
    assert "mine" in restored["mcpServers"] and "aig" not in restored["mcpServers"]
    assert w.load_state(settings)["entries"] == {}


def test_wrapped_entry_really_starts_the_gateway(home, settings, tmp_path, monkeypatch):
    """Launch exactly what the client config now says, and talk MCP to it."""
    monkeypatch.setenv("AIG_CHAT_LOG", str(tmp_path / "chat.jsonl"))
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    Path(settings.policy).write_text(yaml.safe_dump({"version": 1, "tools": {
        "files.read_file": {"reads": ["finance"]}, "chat.post_message": {"sink": "external"}},
        "agents": [{"id": "claude-desktop", "purpose": "Desktop assistant", "on_behalf_of": "user:*@corp.example",
                    "allow": ["files.*", "chat.*"]}],
        "flows": [{"from": "finance", "to": "external", "action": "deny"}]}))
    w.apply(settings, only={"claude-desktop"})
    entry = desktop(home)["mcpServers"]["aig"]
    proc = subprocess.Popen([entry["command"], *entry["args"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                            cwd=Path(__file__).parent.parent)
    def rpc(i, method, params=None):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())
    try:
        rpc(1, "initialize")
        assert {t["name"] for t in rpc(2, "tools/list")["result"]["tools"]} == {"files__read_file", "chat__post_message"}
        rpc(3, "tools/call", {"name": "files__read_file", "arguments": {}})
        assert rpc(4, "tools/call", {"name": "chat__post_message", "arguments": {"text": "x"}})["result"]["isError"]
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)
    assert (settings.state_dir / "logs" / "claude-desktop.jsonl").exists()


def test_cli(home, tmp_path, capsys):
    args = ["wrap", "--home", str(home), "--client", "claude-desktop"]
    assert main(args) == 0 and "Nothing was changed" in capsys.readouterr().out
    assert main(args + ["--apply"]) == 0
    assert main(args + ["--check"]) == 0
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(json.dumps({"mcpServers": {"files": files_server()}}))
    assert main(args + ["--check"]) == 1
    capsys.readouterr()
    assert main(args + ["--check", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "aig_wrap_check.v1" and not report["ok"]
