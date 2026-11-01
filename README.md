# Agent Intent Gateway

Enforcement for AI agent tool calls that understands **who** the agent is acting for, **why** it exists, and **where data is allowed to go** — not just which tools it may call.

```
agent  <--MCP stdio-->  aig proxy  <--MCP stdio-->  upstream MCP server
                           │
                           ├─ identity:  known agent? acting for an allowed principal?
                           ├─ intent:    tool inside the agent's declared purpose?
                           ├─ data flow: given what this session already read, may data reach this sink?
                           └─ ledger:    hash-chained, tamper-evident decision log
```

## Why per-call ACLs aren't enough

Most agent guardrails decide each tool call on its own. Real attacks chain allowed calls:

| Attack | Each call alone | Gateway outcome |
|---|---|---|
| Read ledger, then email it to an outside address | both allowed | **deny**: session holds `finance` data, flow to `external` is denied |
| Read a poisoned inbound email, then approve a payment | read allowed, payment needs approval | **deny**: `untrusted` content may not drive `risk:high` actions |
| Agent invoked by someone it doesn't serve (confused deputy) | tool allowed | **deny**: principal not in `on_behalf_of` |
| Mixed recipients: one internal, one external | looks internal | **deny**: one external recipient makes the call external |

Every decision carries plain-language reasons and the rule IDs that produced it, including where tainting data came from (`session holds 'finance' data (from finance.query_ledger)`).

## Policy

```yaml
version: 1
default: deny
tools:
  finance.query_ledger: { reads: [finance] }
  email.send:
    sink: external
    egress_rules: [{ arg: to, pattern: "*@corp.example", sink: internal }]
agents:
  - id: expense-bot
    purpose: Reconcile employee expense reports against the ledger
    on_behalf_of: ["group:finance"]
    allow: [finance.query_ledger, email.send]
flows:
  - { id: no-finance-egress, from: finance, to: external, action: deny }
```

See [`examples/enterprise.yaml`](examples/enterprise.yaml) for a fuller example. Outcomes are `allow`, `require_approval` or `deny`; the most restrictive applicable rule wins, and flow rules can only tighten a decision.

## Usage

```bash
pip install -e ".[dev]"

# Put the gateway in front of any stdio MCP server
aig proxy --policy examples/enterprise.yaml --agent expense-bot --principal group:finance \
    --log decisions.jsonl -- python examples/mock_mcp_server.py

# Dry-run one decision
aig check --policy examples/enterprise.yaml --agent expense-bot --principal group:finance \
    email.send --args '{"to":"drop@evil.example"}' --labels finance

# Prove the decision log hasn't been edited, reordered or truncated mid-chain
aig verify-log decisions.jsonl
```

Denied calls never reach the upstream server. The agent receives a normal MCP tool result with `isError: true` and the reason, so it can recover. Out-of-scope tools are hidden from `tools/list` by default.

## Design notes

- **One gateway per agent session.** That is how the gateway knows agent identity and principal, which the network layer can't see when a human and an agent share a host.
- **Conservative tainting.** A session is labelled at decision time for every allowed read, before the result returns. Taint is session-wide, not per-value; finer-grained content tracking is on the roadmap.
- **Denied calls don't taint.** Probing a forbidden tool can't poison a session.

## Roadmap

- [x] Intent policy schema, engine, data-flow tainting, MCP stdio proxy, tamper-evident ledger
- [ ] Simulated enterprise: richer mock tools, legitimate agent workloads
- [ ] Red-team harness: attack campaigns, scoreboard, bypass → regression test
- [ ] Intent proofs: check statically that no allowed call sequence violates a stated rule
- [ ] Live dashboard
