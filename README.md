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
2. Outgoing arguments are decoded (URL, HTML, base64, base32, hex, gzip/zlib, nested JSON, reversal, ROT13) and normalised (case, Unicode including other scripts' digits, invisible characters, spacing, punctuation), then matched against those values with a prefix index. Each argument is also checked joined with the others and continued from the same argument in earlier calls to the same destination, so data split into chunks is caught on the chunk that completes a value. That takes about 20 ms for a 9 KB argument against a 75,000-value index.
3. A flow rule with `precision: value` applies its `action` only when the call carries values of that label. If the session has seen the label but sends none of it, the rule's `residual` action applies instead (`allow`, `require_approval` or `deny`; default `require_approval`).

```yaml
flows:
  - { id: no-finance-egress, from: finance, to: external, action: deny, precision: value, residual: allow }
  - { id: untrusted-no-high-risk, from: untrusted, to: "risk:high", action: deny }   # stays session-level
```

**What it can't see, by design:** data an LLM has rewritten in new words ("the cloud vendor is owed about seventy-two thousand"), or data leaked through a covert channel that carries no values at all (one bit per email in subject-line capitalisation). Both gaps are scenarios in the red team (`ATK-ENC-007`, `ATK-ADV-012`) rather than hidden assumptions. Chunked data is caught on the chunk that completes a value, so fragments sent before it, which carry no whole value, still leave. Policies that can't accept it keep `precision: session` or use `residual: require_approval`. **Integrity rules should stay session-level:** whether injected text *influenced* a decision isn't visible in values. If the per-session index fills up, affected labels fail closed back to session-level behaviour.

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

## Deploying on endpoints: `aig wrap` and aggregator mode

On a machine where AI clients use local MCP servers, `aig wrap` puts AIG in front of them:

```bash
aig wrap                 # plan: which clients and servers it would wrap (writes nothing)
aig wrap --apply         # rewrite the configs, with backups
aig wrap --check         # drift: gateway removed, servers added outside it, unwrapped clients (exit 1)
aig wrap --undo          # restore everything
```

It knows Claude Desktop, Claude Code (user and per-project), Cursor, Windsurf and VS Code. For each server map it moves the stdio servers into one **aggregator config** and leaves the client a single entry:

```json
"mcpServers": { "aig": { "command": "aig", "args": ["proxy", "--config", "~/.aig/agents/claude-desktop-93beeb50.json"] } }
```

`aig proxy --config` starts all of that agent's servers behind **one gateway session**, so data read through one server and sent out through another is caught. Tools appear to the agent as `server__tool` and in policy as `server.tool` (for example `filesystem.read_text_file`). Secrets stay in the aggregator config, which is readable only by the user; `--json` plans never contain server arguments or environment values. Remote (URL) servers are reported, not rewritten: they need the central gateway or traffic steering.

[`examples/live-filesystem/`](examples/live-filesystem) runs this against the official filesystem MCP server: ledger values emailed outside are refused, ordinary mail goes through, and writes to the share are refused.

AegisFlux can drive `aig wrap` from its endpoint agent (plan, apply, drift findings, process lineage). That is written up as a [draft AegisFlux work order](docs/proposals/AEGISFLUX-WO-DRAFT-endpoint-mcp-gateway-wrapping.md), not yet filed.

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

## Console

`aig console` serves the AIG console for a running gateway: overview, agents, decisions with full reasons, approvals, data flows, rules and Clarion intents, tools, red-team results, the evidence log with in-browser chain verification, and integrations.

```bash
aig console --policy examples/clarion/gateway-base.yaml --overlay finance.bundle.json --overlay-key compiler.pub \
    --log decisions.jsonl --events events.jsonl --redteam reports/scoreboard.json      # http://127.0.0.1:3040
```

It follows the Clarion and AegisFlux console conventions (shell, sidebar, section tabs, cards, palette, light and dark themes), so it feels like the same product family. The source is in [`ui/console/`](ui/console) (React, Tailwind, lucide). `npm run build` there produces one self-contained page, installed into `aig/console_static/` so the Python package serves it without Node. `python scripts/build_console_demo.py` builds a demo copy with an embedded snapshot, generated by replaying the scenario library through the Clarion-managed gateway.

## Clarion intent in, AegisFlux evidence out

AIG is deliberately standalone while Clarion and AegisFlux build out their own integration. It consumes their contracts read-only and changes nothing in either repository. See [ADR-001](docs/ADR-001-standalone-integration-boundary.md) for the boundary and the list of integration proposals.

The gateway is one placement in a larger loop: **Clarion** decides what should happen, **AegisFlux** controls hosts and traffic steering, and AIG enforces at the tool layer. It speaks both products' existing contracts, vendored unchanged in [`contracts/aegisflux/`](contracts/aegisflux) and checked in tests:

```
Clarion intent ──► aig compile ──► signed compiled artifact ──► aig serve --overlay ──► decisions
(segmentation_policy_intent.v1)    (platform_path: proxy_broker)                          │
                                                                                          ▼
                                  AegisFlux evidence ◄── segmentation_outcome_event.v1 (match_blocked / match_observed)
```

```bash
aig compile --intent examples/clarion/finance-egress.intent.json --policy examples/clarion/gateway-base.yaml \
    --key compiler.key --key-id clarion-lab-1 --out finance.bundle.json
aig serve ... --overlay finance.bundle.json --overlay-key compiler.pub --emit-events events.jsonl   # or --emit-url
```

**What an intent means at the tool layer:**

| Intent field | Compiled to |
|---|---|
| `data_rules` classification / sensitivity | data label, and a flow rule to `external`: `restricted` → deny (session), `confidential` → deny (value, residual approval), `internal` → approval (value, residual allow), `public` → none |
| `subject.agent_class` / `device_ids` | rule scope: the agent's class in gateway policy, the device in its token |
| `action_mode`, `blocking_enabled`, `proxy_broker.max_action_mode` | `enforce`, or `observe` (record "would block" without blocking) |
| `lifecycle_status`, `approval`, `ttl` | refused unless approved and live; rules expire with the intent |
| `destination_rules`, `process_selectors` | reported as handed to the steering gateway and host; never silently ignored |

**Guarantees:**
- Overlays are Ed25519-signed and hash-checked, and their provenance (intent, artifact, approval) comes from the signed artifact. Tampered, expired, duplicate or wrongly signed overlays are refused at load.
- Intent only adds rules; it can never loosen the base policy or switch off the local integrity rules.
- Outcome events carry **no data values**, only a redacted reason. The full reason stays in the local tamper-evident log, which each event references by hash.
- Every `match_blocked` cites the approved change that authorised blocking, as AegisFlux requires.
- Event delivery is best-effort and off the decision path, so a dead collector never changes or delays a decision.
- AegisFlux's own example intent (`code_agent_mcp_bridge`) compiles, downgraded to observe, with explicit warnings for the parts the gateway can't act on.

**Two findings from building it:**

1. **Scope data rules to the data, not the agent.** A finance rule scoped to `agent_class: finance_automation` lets the cross-agent laundering attack through, because the research agent isn't in scope. The compiler warns when shared stores exist, and a test proves the bypass.
2. **Sensitivity sets the trade-off.** On the Clarion-managed gateway ([`examples/clarion/`](examples/clarion)), the base policy alone blocks 10 of 39 attacks. With the three intents it blocks **39 of 39**, including the paraphrase and covert-channel attacks, because `confidential` means "ask a human when the agent has seen the data but sends none of it". The price is that two legitimate vendor replies need approval (9 of 11 workloads run without a human). The hand-tuned `examples/enterprise.yaml` makes the opposite choice: 37 of 39 attacks blocked, 11 of 11 workloads.

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

Current result ([`reports/scoreboard.md`](reports/scoreboard.md)): **37 of 39 attacks blocked, 11 of 11 workloads complete.** The two that get through are the documented no-value gaps above: paraphrase and the covert channel.

### Adversarial pass

The first 24 attacks were written while the defences were being built, so they partly tested what was already known to block. A second pass ([`scenarios/attacks_adversarial.yaml`](scenarios/attacks_adversarial.yaml)) attacked AIG's own mechanisms after reading its design. Before any fix ([`reports/adversarial-baseline.md`](reports/adversarial-baseline.md)), **11 of 15** got through the hand-tuned policy, and three got through the Clarion-managed one too:

| Bypass | Fix |
|---|---|
| Ledger split a few characters per email, or across subject and body | Arguments are checked joined, and continued from the same argument in earlier calls to the same destination |
| IDs and amounts in Arabic-Indic digits | Any script's decimal digits normalise to ASCII |
| Reversed, ROT13, base32, gzip + base64 | Added to the decoder; decompression is size-bounded |
| Internal email used as a shared store nobody declared | `email.send` stores into `mail`, `email.read_inbox` loads from it. Any internal sink another agent can read is a store |
| Poisoned email makes the agent rewrite the shared travel policy | New integrity rule: `untrusted` content may not write shared documents without approval |
| `user:mallory@evil.example#@corp.example` passes `user:*@corp.example` | `*` in identity patterns no longer crosses `@`, `:`, `#`, `/` or whitespace |
| Two in-flight calls reusing one JSON-RPC id could swap results and mislabel data | Reused in-flight ids are refused |

It also found a false-positive source: words inside email addresses (`example` in `ap@fabrikam.example`) counted as data. They no longer do.

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
- [x] Compile Clarion `segmentation_policy_intent.v1` to signed `proxy_broker` overlays; emit AegisFlux outcome events
- [x] Adversarial pass: 15 attacks against AIG's own mechanisms, 11 bypasses found and closed
- [x] Demo page ([`docs/demo/`](docs/demo), rebuilt from real runs by `python scripts/build_demo.py`)
- [x] Value-level tracking outside the agent: decoding, normalisation, residual actions
- [ ] Semantic matching for paraphrase (probabilistic; would sit behind `residual`, never replace deterministic matches)
- [ ] LLM-driven adversaries that generate new attack chains against the policy
- [ ] Intent proofs: check statically that no allowed call sequence violates a stated rule
- [ ] Live dashboard
