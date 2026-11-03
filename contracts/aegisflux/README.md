# Vendored AegisFlux contracts

Copied unchanged from `dentroio/aegisflux` at commit `114fbc9` (2026-11-01), `schemas/segmentation/`:

| File | Used for |
|---|---|
| `segmentation-policy-intent.v1.schema.json` | Clarion intents that `aig compile` accepts |
| `segmentation-compiled-artifact.v1.schema.json` | The signed artifact `aig compile` produces (`platform_path: proxy_broker`) |
| `segmentation-outcome-event.v1.schema.json` | Events AIG emits for every intent-derived decision |
| `example.code_agent_mcp_bridge.intent.json` | AegisFlux's own example intent, used as a compatibility test |

Tests validate AIG's inputs and outputs against these copies. When AegisFlux changes a contract, re-copy it and the tests show what broke.

To see whether AegisFlux has moved on: `python scripts/check_contracts.py <path-to-aegisflux-checkout>`. See [ADR-001](../../docs/ADR-001-standalone-integration-boundary.md) for why AIG pins these copies instead of tracking upstream.
