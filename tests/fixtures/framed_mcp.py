"""An MCP server that only speaks Content-Length framing, like ai-lab's lab_mcp_server.

A standard JSON line is read as a header line, so the server waits for a blank
line that never comes, exactly the behaviour seen in the field.
"""
import json
import sys

TOOLS = [{"name": "lab_health", "description": "Control-plane health", "inputSchema": {"type": "object"}},
         {"name": "lab_memory_search", "description": "Search lab memory", "inputSchema": {"type": "object"}}]


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            raise EOFError
        if line in (b"\r\n", b"\n"):
            break
        text = line.decode("ascii", errors="replace").strip()
        if ":" in text:
            k, v = text.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return json.loads(sys.stdin.buffer.read(int(headers["content-length"])))


def write_message(msg):
    raw = json.dumps(msg, separators=(",", ":")).encode()
    sys.stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
    sys.stdout.buffer.flush()


while True:
    try:
        m = read_message()
    except (EOFError, KeyError):
        break
    rid, method = m.get("id"), m.get("method")
    if rid is None:
        continue
    if method == "initialize":
        write_message({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05",
                       "capabilities": {"tools": {}}, "serverInfo": {"name": "ai-lab", "version": "0.1.0"}}})
    elif method == "tools/list":
        write_message({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        q = json.dumps(m["params"].get("arguments", {}))
        write_message({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": f'{{"ok": true, "q": {q}}}'}]}})
    else:
        write_message({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}})
