"""Wrap a Claude Desktop config holding the real filesystem MCP server, then drive it through AIG."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

if not shutil.which("mcp-server-filesystem"):
    sys.exit("Install the server first: npm install -g @modelcontextprotocol/server-filesystem@2.1.0")

with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    share = d / "finance-share"
    share.mkdir()
    (share / "q4-ledger.csv").write_text("id,vendor,amount,status\nTX-2201,Halvorsen Freight,48210.00,paid\n"
                                         "TX-2202,Brightline Analytics,131500.00,pending\nTX-2203,Meridian Office Supply,2875.40,flagged\n")
    home = d / "home"
    (home / ".config" / "Claude").mkdir(parents=True)
    (home / ".aig").mkdir()
    shutil.copy(HERE / "policy.yaml", home / ".aig" / "policy.yaml")
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(json.dumps({"mcpServers": {
        "filesystem": {"command": "mcp-server-filesystem", "args": [str(share)]},
        "corp": {"command": sys.executable, "args": ["-m", "aig.sim"]}}}))
    aig = [sys.executable, "-m", "aig.cli"]
    print(subprocess.run([*aig, "wrap", "--home", str(home), "--principal", "user:dana@corp.example", "--apply",
                          "--aig-command", " ".join(aig)], capture_output=True, text=True, cwd=ROOT).stdout)
    entry = json.loads((home / ".config" / "Claude" / "claude_desktop_config.json").read_text())["mcpServers"]["aig"]
    p = subprocess.Popen([entry["command"], *entry["args"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, cwd=ROOT)
    n = 0

    def rpc(method, params=None):
        global n
        n += 1
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": n, "method": method, "params": params or {}}) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    def call(tool, args):
        r = rpc("tools/call", {"name": tool, "arguments": args})["result"]
        print(f"> {tool}\n  {'REFUSED' if r.get('isError') else 'ok'}: {r['content'][0]['text'][:160]}\n")

    rpc("initialize", {"protocolVersion": "2025-06-18"})
    print("Tools the agent sees:", ", ".join(t["name"] for t in rpc("tools/list")["result"]["tools"]), "\n")
    call("filesystem__read_text_file", {"path": str(share / "q4-ledger.csv")})
    call("corp__email_send", {"to": "controller@corp.example", "subject": "Q4", "body": "Brightline TX-2202 is still pending."})
    call("corp__email_send", {"to": "contact@brightline-analytics.example", "subject": "Hi", "body": "Our books show TX-2202 at 131,500.00"})
    call("corp__email_send", {"to": "contact@brightline-analytics.example", "subject": "Meeting", "body": "Can we move our call to Thursday?"})
    call("filesystem__write_file", {"path": str(share / "q4-ledger.csv"), "content": "wiped"})
    p.stdin.close()
    p.wait(timeout=10)
    print(subprocess.run([*aig, "verify-log", str(home / ".aig" / "logs" / "claude-desktop.jsonl")],
                         capture_output=True, text=True, cwd=ROOT).stdout)
