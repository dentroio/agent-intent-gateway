# WO-INT-0xx (proposed): Endpoint wrapping of MCP clients behind the Agent Intent Gateway

> **Proposal from the AIG repository, not filed in AegisFlux.** Written in AegisFlux's work-order format for the owner and PM to review. Per AegisFlux's process it would enter as **Draft**; the PM assigns the ID. Nothing in the AegisFlux repository has been changed. AIG side: [ADR-001](../ADR-001-standalone-integration-boundary.md), `aig wrap` ([`aig/wrap.py`](../../aig/wrap.py)), aggregator ([`aig/aggregate.py`](../../aig/aggregate.py)).

**Status:** Draft (proposed)
**Priority:** P2
**Effort:** L (three phases; each phase can be its own WO)
**Owner:** Steven Gerhart
**Lane:** Agent runtime
**Services / Areas:** linux-agent, windows-agent, agent-core; a new per-user helper; console (Phase 1)
**Program:** AegisFlux ↔ Clarion integration and AI-BOM ([ADR-INT-001](../../../adr/ADR-INT-001-aegisflux-clarion-authority-and-integration.md)); AIG integration (dentro.io ADR-001)

## Problem

The AI-BOM collectors (WO-AIBOM-002, WO-AIBOM-003) find MCP clients and their servers, but nothing controls what those servers are used for. The Agent Intent Gateway (AIG) decides every MCP tool call by identity, purpose and data flow, but only for servers placed behind it, and today that means editing each client's JSON by hand. AegisFlux is already on the endpoint and already knows which clients and servers exist. It should put them behind AIG, keep them there, and report when they drift, without the endpoint agent learning to rewrite every client's config format itself.

## Decision Context

- **AIG owns config rewriting.** `aig wrap` already discovers Claude Desktop, Claude Code (user and per-project), Cursor, Windsurf and VS Code configs, moves each server map's stdio servers into one aggregator config, and leaves the client a single `aig` entry. It plans by default; `--apply` writes atomically with backups and keeps mode and owner; `--check` reports drift; `--undo` restores. AegisFlux invokes it rather than reimplementing it, which keeps the endpoint agent lightweight (charter: "Lightweight Endpoint, Deep Platform") and keeps one implementation of each client's format.
- **Field limits hold.** `aig wrap --json` (`aig_wrap_plan.v1`, `aig_wrap_check.v1`) never contains server arguments or environment values, only server names, transports and command basenames: the same limits as WO-AIBOM-002 acceptance criterion 2. Secrets stay in the user's aggregator config (mode 0600) on the device.
- **Privilege: reading is already an open decision; writing is a bigger one.** The Linux unit runs as `aegis` with `ProtectHome=true` (WO-AIBOM-003 follow-on 1), so it cannot read user homes today. Granting the system service write access to every home (`ProtectHome=false` plus `CAP_DAC_OVERRIDE`) would make the agent a broad write primitive. **Proposed instead: a per-user helper** (systemd user unit / macOS LaunchAgent / Windows logon task in the user's context) that runs `aig wrap` as the user when the service asks over a local, authenticated channel. Files keep their owner naturally, and the service gains no new privilege. Windows (LocalSystem) could write directly, but should use the same helper for parity and least privilege.
- **Per user, not per device.** AI-BOM keeps one item per product key per device (the first user's config wins). Wrapping and drift must be tracked per user.
- **Why lineage matters.** Local MCP servers talk to the client over stdio pipes, which eBPF and WFP do not see. The control for "nothing goes around AIG" is therefore **process lineage**: an MCP server process should have `aig proxy` as its parent. AegisFlux's process telemetry can check that; network steering (WO-SEG-007) covers remote MCP servers.
- **Identity.** Phase 1 identifies the principal from the OS login (`--principal user:<login>@<domain>`). When WO-SEG-006 tokens exist, the helper passes a token instead (AIG follow-up: `aig proxy --config` accepting a token file, verified as `aig serve` already does).

## What To Build / Fix

**Phase 0: Observe (read-only, no writes).** Run `aig wrap --check --json` per user on the existing collection cycle (after the ProtectHome read decision) and report coverage: servers behind AIG, servers outside it, remote servers, unreadable configs. This gives value before any write: "N MCP servers on M devices are not behind a gateway".

**Phase 1: Wrap with operator approval.**
- Per-user helper: receives "plan" / "apply" / "undo" from the service; runs `aig wrap` as the user; returns the JSON report.
- Console: per device group, wrapping is *Off* (default), *Report only* (Phase 0) or *Wrap*. Applying needs the same approval path as other blocking-capable controls.
- After apply, report the plan and result. Undo is one action.

**Phase 2: Keep it wrapped.**
- Drift: `aig wrap --check` findings (`gateway_removed`, `servers_outside_gateway`, `not_wrapped`) become findings. Optional auto re-apply per device group.
- Lineage: flag MCP server processes (known from AI-BOM) whose parent is not `aig proxy`. Detection first; any blocking goes through a separate gated WO.

## Expected Change Surface

- **File ownership:** `agents/agent-core/src/**` (helper protocol, report types), `agents/linux-agent/src/**` and `agents/windows-agent/src/**` (invocation, scheduling), new helper packaging under each agent's `packaging/`; Phase 1 console pages under `ui/console/**`.
- **Do not touch:** `schemas/**` (a new event for wrap coverage and drift needs its own schema WO first), `backend/**` beyond what the schema WO defines.
- Docs/status: this WO, `docs/architecture/02-endpoint-agents.md` (collection and account rows). Parallel agents do not edit `WORK_ORDER_STATUS.md`.

## Out Of Scope

- Rewriting configs in Rust inside the agent (AIG owns that).
- Remote (URL) MCP servers: steering (WO-SEG-007) or AIG's central gateway.
- Blocking unwrapped servers or killing processes.
- VS Code `settings.json` (JSONC); only `mcp.json` files are rewritten.

## Do NOT Change

- Safety boundaries: no endpoint LLM; no blocking outside gated WOs; the endpoint never asserts a trusted SGT; AI output never authorizes.
- No secrets, tokens, keys or `.env` values in commits, logs, fixtures, PR text or events. MCP arguments and env values are never emitted.
- The system service's account and sandbox, except through the separate ProtectHome decision.
- Collection cycle timing and existing events.

## Acceptance Criteria

1. Phase 0: on a lab host with Claude Desktop and Cursor configs, coverage is reported per user with server names and transports and no arguments or env values (test).
2. Phase 1: with wrapping set to *Wrap*, the helper wraps both clients as the user; files keep their owner and mode; backups exist; *Undo* restores the servers (test plus lab).
3. Phase 1: the wrapped client still works. Its tools appear as `<server>__<tool>` and calls are decided by AIG (lab: one allowed call, one refused).
4. Phase 2: removing the `aig` entry or adding a server outside it produces a finding within one cycle (test).
5. The system service gains no new capability on Linux, and no write access to user homes on any OS (review).
6. `make ci-local` passes.

## Validation Plan

- Automated: fixture homes for each client (the AIG repo's `tests/test_wrap.py` fixtures can be reused); helper protocol tests; field-limit tests.
- Lab (owner): aegis-linux and aegis-windows with Claude Desktop and Cursor; one agent session through AIG; drift by hand-editing a config.

## Dependencies

- ProtectHome read decision (WO-AIBOM-003 follow-on 1), for Phase 0 on Linux.
- WO-SEG-006 (stream tokens) for identity beyond the OS login.
- WO-SEG-010 / `agent_instance_id` to join AIG decisions to AI-BOM instances.
- AIG ships `aig` on the endpoint (package or bundled binary) and a token-file option for `aig proxy --config`.

## Execution

- **Branch:** to be assigned
- **Claimed by:**

## Closeout

-
