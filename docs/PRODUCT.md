# Agent Intent Gateway: product brief

**dentro.io** · Draft, 2026-11-03

## What it is

Data loss prevention for AI agents. AIG sits between AI agents and the tools they use over MCP (email, file stores, CRM, finance systems) and decides, for every tool call, whether the data in it may go where it is going.

## Why now

Agents now read sensitive systems and act on their own. The usual controls judge each tool call by itself: who is calling, and is this tool allowed. Real data theft chains calls that are each allowed: read the ledger, then email it; copy it into a shared document another agent posts to the web; follow instructions hidden in an inbound email.

## What makes it different

| Approach | Decides on | What it misses |
|---|---|---|
| MCP gateways | Who is calling and which tool, one call at a time | Chains of allowed calls; data moving between agents |
| AI guardrails | Classifier scores on prompts and tool calls | Deterministic, explainable decisions about where data may go |
| Static flow analysis | Risky tool combinations, before deployment | Enforcement at runtime |
| Research information-flow control | Where each value came from, inside the agent | Unmodified agents: the agent has to be rebuilt around it |
| **AIG** | **Where data may go, across calls and agents, in front of any MCP agent; tested continuously by its own red team** | Data an LLM rewrites in new words, and covert channels, are stated limits |

In lab testing against 39 attacks, per-call access control blocked 8. AIG blocked 37 with a hand-tuned policy (the two misses are the stated limits) and 39 with Clarion-managed policy, without breaking legitimate work.

## Who buys it

The CISO or security architecture lead at an enterprise rolling out agents connected to sensitive systems. They already budget for DLP and already worry about agents leaking data.

**First use case:** agents connected to finance, HR, CRM and email through MCP.

## Product shape

AIG stands alone, and integrates with the rest of dentro.io when present (see [ADR-001](ADR-001-standalone-integration-boundary.md)):

- **Alone:** local policy, single sign-on, credential brokering so agents can't go around it, its own console, tamper-evident decision log and SIEM export.
- **With Clarion:** policy compiled from enterprise intent, and evidence for Clarion's Verify stage.
- **With AegisFlux:** endpoint-proven agent identity, traffic steering, and evidence joined with host activity.

Each product sells on its own. Together they enforce one intent at the network, on the host and at the tool layer, which no single competitor covers.

**Packaging:** open-source engine and red-team harness (adoption, credibility, research). Commercial: Clarion-managed policy, the console, identity and data-label integrations, evidence export, support.

## Roadmap to a first release

1. **Credential brokering** for two or three real systems (Google Workspace, Slack, GitHub). This makes AIG enforceable without an endpoint agent.
2. **Single sign-on** (Okta, Entra) for principals.
3. **Approvals in Slack or Teams.**
4. **Observe-mode report:** "here is what we would have blocked this week."
5. **Existing data labels** (for example Microsoft Purview) instead of hand-written ones.
6. **Production engineering:** Go port, high availability, full MCP feature set, SIEM export, security review.

## Design-partner plan

| Weeks | Goal |
|---|---|
| 1–2 | This brief; three design partners rolling out agents |
| 3–6 | Credential brokering, single sign-on, weekly observe-mode report |
| 7–12 | Pilots in observe mode; measure would-blocks and false positives; enforce one rule per partner |
| Decision | Real would-blocks on real traffic → AIG leads the dentro.io agent story. Mostly noise → open-source research artifact |

## Risks

- Crowded market: Cisco, the cloud providers and many startups work on MCP security.
- MCP is still changing quickly.
- "Deterministic" applies to value matching. Paraphrase and covert channels are real limits, and sales material must say so.
- Founder bandwidth across three products: AIG ships standalone in its smallest useful form first.
