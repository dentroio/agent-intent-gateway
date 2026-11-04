"""Minimal stdio MCP servers for aggregator tests.

    python fake_mcp.py files   -> read_file returns the ledger
    python fake_mcp.py chat    -> post_message records what it was asked to post (AIG_CHAT_LOG)
"""
import json
import os
import sys
import time

ROLE = sys.argv[1]
LEDGER = '[{"id": "TX-1042", "vendor": "Contoso Cloud", "amount": 72300.0}]'
TOOLS = {
    "files": [{"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
              {"name": "list_dir", "description": "List a directory", "inputSchema": {"type": "object"}}],
    "chat": [{"name": "post_message", "description": "Post to a public channel", "inputSchema": {"type": "object"}}],
}[ROLE]


def out(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    m = json.loads(line)
    rid, method = m.get("id"), m.get("method")
    if rid is None:
        continue
    if method == "initialize":
        out({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                                     "serverInfo": {"name": f"fake-{ROLE}", "version": "1"}}})
    elif method == "tools/list":
        out({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name, args = m["params"]["name"], m["params"].get("arguments", {})
        if args.get("slow"):
            time.sleep(0.3)
        if name == "read_file":
            text = LEDGER
        elif name == "list_dir":
            text = '["ledger.json", "notes.txt"]'
        elif name == "post_message":
            with open(os.environ["AIG_CHAT_LOG"], "a") as fh:
                fh.write(json.dumps(args) + "\n")
            text = "posted"
        else:
            out({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"no tool {name}"}})
            continue
        out({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}})
    else:
        out({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}})
