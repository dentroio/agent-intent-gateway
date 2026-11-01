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

# Put the gateway in front of any stdio MCP server (here: the simulated enterprise).
# Gateways for different agents share --label-store so labels follow data between them.
aig proxy --policy examples/enterprise.yaml --agent expense-bot --principal group:finance \
    --log decisions.jsonl --label-store labels.json -- python -m aig.sim

# Run the red team: every attack scenario and legitimate workload, scored
aig redteam --policy examples/enterprise.yaml --md reports/scoreboard.md --json reports/scoreboard.json

# Dry-run one decision
aig check --policy examples/enterprise.yaml --agent expense-bot --principal group:finance \
    email.send --args '{"to":"drop@evil.example"}' --labels finance

# Prove the decision log hasn't been edited, reordered or truncated mid-chain
aig verify-log decisions.jsonl
```

Denied calls never reach the upstream server. The agent receives a normal MCP tool result with `isError: true` and the reason, so it can recover. Out-of-scope tools are hidden from `tools/list` by default.

## Red team

[`scenarios/`](scenarios) holds an attack library (exfiltration chains, recipient smuggling, argument smuggling, indirect prompt injection, confused deputy, spoofed agents, cross-agent laundering) and legitimate workloads that measure false positives. The harness drives every scenario through the real gateway path in front of a stateful [simulated enterprise](aig/sim/enterprise.py), with a poisoned inbox email and a ledger worth stealing, and checks what actually left the building.

The first run against the v0.1 engine ([`reports/baseline.md`](reports/baseline.md)) found **5 bypasses**:

| Bypass | Fix |
|---|---|
| `to: "drop@evil.example,cfo@corp.example"` matched `*@corp.example` | `kind: email` egress rules split recipient strings and require each piece to be one well-formed address |
| `drop@evil.example#@corp.example` | same: exactly one `@`, strict characters, fail closed |
| Internal `to`, external `bcc` | egress rules cover every listed argument; one external value keeps the call external |
| Invented `forward_to` argument | tools can declare their arguments; anything else is refused |
| Finance agent writes the ledger into shared docs, research agent reads it and posts it out | **labels follow data through shared stores**, across agents and gateway processes |

Current result ([`reports/scoreboard.md`](reports/scoreboard.md)): **17/17 attacks blocked, 9/10 workloads complete.** The remaining false positive is documented: replying to a vendor after reading the ledger is refused, because session-level tainting can't see that the reply carries no ledger data.

Every scenario runs in CI (`tests/test_redteam.py`), so a fixed bypass can never quietly return.

## Design notes

- **One gateway per agent session.** That is how the gateway knows agent identity and principal, which the network layer can't see when a human and an agent share a host.
- **Conservative tainting.** A session is labelled at decision time for every allowed read, before the result returns. Taint is session-wide, not per-value.
- **Labels outlive sessions.** Writes into a declared store (`stores:`) stamp the item with the writer's labels; reads (`loads:`) pick them up, with provenance like `docs.search <- finance.query_ledger, written to docs:notes/q4 by expense-bot`. A search without an item key inherits labels from the whole store, which is conservative.
- **Denied calls don't taint.** Probing a forbidden tool can't poison a session.
- **The harness's evidence check is stricter than the policy.** It parses recipients the way a lenient mail server would, so it catches escapes the enforcement layer misjudged.

## Roadmap

- [x] Intent policy schema, engine, data-flow tainting, MCP stdio proxy, tamper-evident ledger
- [x] Simulated enterprise, attack library, legitimate workloads
- [x] Red-team harness: scoreboard, bypass → fix → regression test
- [ ] Value-level tracking to remove the session-taint false positive
- [ ] LLM-driven adversaries that generate new attack chains against the policy
- [ ] Intent proofs: check statically that no allowed call sequence violates a stated rule
- [ ] Live dashboard
