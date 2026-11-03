# Agent Intent Gateway

Enforcement for AI agent tool calls that understands **who** the agent is acting for, **why** it exists, and **where data is allowed to go** — not just which tools it may call.

```
agent  <--MCP stdio-->  aig proxy  <--MCP stdio-->  upstream MCP server
                           │
                           ├─ identity:  known agent? acting for an allowed principal?
                           ├─ intent:    tool inside the agent's declared purpose?
                           ├─ data flow: does this call carry data that may not reach this sink?
                           └─ ledger:    hash-chained, tamper-evident decision log
```

## Why per-call ACLs aren't enough

Most agent guardrails decide each tool call on its own. Real attacks chain allowed calls:

| Attack | Each call alone | Gateway outcome |
|---|---|---|
| Read ledger, then email it to an outside address | both allowed | **deny**: `body` carries `finance` values (`'tx1042'`, …) from `finance.query_ledger` |
| Same, but base64 / hex / URL-encoded / spaced out | both allowed | **deny**: the gateway decodes and normalises before matching |
| Read a poisoned inbound email, then approve a payment | read allowed, payment needs approval | **deny**: `untrusted` content may not drive `risk:high` actions |
| Agent invoked by someone it doesn't serve (confused deputy) | tool allowed | **deny**: principal not in `on_behalf_of` |
| Mixed recipients: one internal, one external | looks internal | **deny**: one external recipient makes the call external |

Every decision carries plain-language reasons and the rule IDs that produced it, including which argument carried which values and where they came from.

## Value-level data flow

Research systems such as Google DeepMind's CaMeL and Microsoft's FIDES showed that tracking where data came from is the principled defence for agents, but they live inside the agent, so the agent has to be rebuilt around them. MCP gateways work with unmodified agents but judge each call on its own. AIG does information-flow control **outside the agent**, in front of any MCP client:

1. Labelled tool results passing back through the gateway are broken into values: identifiers, amounts, emails and distinctive words, keyed by JSON value only, never field names.
2. Outgoing arguments are decoded (URL, HTML, base64, hex, nested JSON) and normalised (case, Unicode, spacing, punctuation), then matched against those values with a prefix index. That takes about 3.5 ms per call against a 75,000-value index.
3. A flow rule with `precision: value` applies its `action` only when the call carries values of that label. If the session has seen the label but sends none of it, the rule's `residual` action applies instead (`allow`, `require_approval` or `deny`; default `require_approval`).

```yaml
flows:
  - { id: no-finance-egress, from: finance, to: external, action: deny, precision: value, residual: allow }
  - { id: untrusted-no-high-risk, from: untrusted, to: "risk:high", action: deny }   # stays session-level
```

**What it can't see, by design:** data an LLM has rewritten in new words ("the cloud vendor is owed about seventy-two thousand"). That gap is a scenario in the red team (`ATK-ENC-007`) rather than a hidden assumption. Policies that can't accept it keep `precision: session` or use `residual: require_approval`. **Integrity rules should stay session-level:** whether injected text *influenced* a decision isn't visible in values. If the per-session index fills up, affected labels fail closed back to session-level behaviour.

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

## HTTP gateway mode (behind the AegisFlux steering gateway)

`aig serve` runs the gateway as an MCP Streamable HTTP service, so it can sit behind AegisFlux's steering gateway as the content-aware layer that ADR-GW-003 leaves out of phase one:

```
agent ──captured──► steering gateway ─── only allowed MCP destination ───► aig serve ──► MCP servers
         (eBPF/WFP)   destination control,                                  tool-level intent,
                      per-stream token                                       data-flow labels
```

Agents use the gateway *as* their MCP server, so nothing is intercepted and no gateway CA is needed. **Identity comes only from the per-stream token**, never from the agent:

| Claim | Source | Meaning |
|---|---|---|
| `dev`, `aiid`, `cls`, `pv`, `aud`, `exp`, `jti` | AegisFlux ADR-GW-002 | device, `agent_instance_id`, policy class, policy version, audience, expiry, nonce |
| `agt`, `prn` | proposed extension | which intent applies, and the principal the instance acts for |

Tokens are compact JWS signed with Ed25519, matching how AegisFlux already signs bundles. The gateway enforces:

- signature, audience, expiry, a lifetime of minutes, the policy version, and a revocation list;
- **session binding:** a session stays tied to the device, instance, agent and principal that opened it, so a token for anyone else gets `403`;
- **replay:** a token id is bound to one session;
- **class tightening:** the newest token's class applies to the very next request, so moving an instance to `quarantine` mid-session works immediately. Classes can only tighten decisions, and unknown classes are refused.

```bash
aig token keygen --out issuer                      # mock AegisFlux issuer (lab only)
aig serve --policy examples/enterprise.yaml --key issuer.pub --audience aegis-gateway-01   # --upstream sim|URL
aig token issue --key issuer.key --agent expense-bot --principal group:finance \
    --class development --instance inst-42 --device dev-7 --audience aegis-gateway-01 --policy-version 2026.11.1
```

Transport: POST of single JSON-RPC messages, JSON responses, `Mcp-Session-Id`, `202` for notifications, `DELETE` to end a session, `405` for the optional GET stream, and Origin checks against DNS rebinding. The stdio proxy stays for local MCP servers, whose traffic never touches the network.

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

Current result ([`reports/scoreboard.md`](reports/scoreboard.md)): **23 of 24 attacks blocked, 11 of 11 workloads complete.** Value-level tracking removed the last false positive: replying to a vendor after reading the ledger now works. It also blocks six disguised-exfiltration attacks (base64, hex, URL-encoding, character spacing, reformatted amounts, vendor names). The one attack that gets through is the documented paraphrase gap above.

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
- [x] MCP Streamable HTTP mode with AegisFlux per-stream token identity, classes, session binding
- [ ] Emit decisions as AegisFlux evidence events; compile Clarion `segmentation_policy_intent.v1` to gateway policy
- [x] Value-level tracking outside the agent: decoding, normalisation, residual actions
- [ ] Semantic matching for paraphrase (probabilistic; would sit behind `residual`, never replace deterministic matches)
- [ ] LLM-driven adversaries that generate new attack chains against the policy
- [ ] Intent proofs: check statically that no allowed call sequence violates a stated rule
- [ ] Live dashboard
