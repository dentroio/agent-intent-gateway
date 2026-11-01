"""Minimal MCP stdio server exposing the tools in examples/enterprise.yaml.

Every tool just echoes what it was asked to do. Used by tests and as the
starting point for the simulated enterprise.
"""
import json
import sys

TOOLS = [
    "finance.query_ledger", "finance.approve_payment", "hr.lookup_employee",
    "docs.search", "web.fetch", "email.read_inbox", "email.send",
    "ot.read_sensor", "ot.set_point",
]


def reply(req_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if rid is None:
        continue  # notification
    if method == "initialize":
        reply(rid, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mock-enterprise", "version": "0.1"}})
    elif method == "tools/list":
        reply(rid, {"tools": [{"name": t, "inputSchema": {"type": "object"}} for t in TOOLS]})
    elif method == "tools/call":
        p = msg["params"]
        reply(rid, {"content": [{"type": "text", "text": f"executed {p['name']} {json.dumps(p.get('arguments', {}))}"}]})
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}}) + "\n")
        sys.stdout.flush()
