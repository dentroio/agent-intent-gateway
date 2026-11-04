# Live example: the official filesystem MCP server behind AIG

A Claude Desktop config with two servers: the real, unmodified `@modelcontextprotocol/server-filesystem` on a "finance share", and company email (AIG's simulated enterprise). `aig wrap --apply` puts both behind one gateway, then the run below drives it exactly as the client would.

```bash
npm install -g @modelcontextprotocol/server-filesystem@2.1.0
python examples/live-filesystem/run.py
```

What it shows (recorded 2026-11-03):

| Call | Result |
|---|---|
| `tools/list` | 8 of the server's 14 tools; write, edit, move and other undeclared tools hidden |
| `filesystem__read_text_file` the ledger CSV | allowed |
| `corp__email_send` ledger values to `controller@corp.example` | allowed (internal) |
| `corp__email_send` "TX-2202 at 131,500.00" to an outside address | **refused**: carries finance values from `filesystem.read_text_file` |
| `corp__email_send` an unrelated note to the same outside address | allowed |
| `filesystem__write_file` over the ledger | **refused**: outside the agent's purpose; file unchanged |

The decision log verifies with `aig verify-log`.
