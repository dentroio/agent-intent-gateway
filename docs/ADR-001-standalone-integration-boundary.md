# ADR-001: AIG stays standalone; Clarion and AegisFlux contracts are consumed read-only

**Status:** Accepted (2026-11-02)

## Context

Clarion and AegisFlux are both under active development, and the integration between them has only just started. AIG sits between the two, compiling Clarion intent and emitting AegisFlux evidence. If AIG required changes in either product, it would put pressure on an integration that is still being designed.

## Decision

1. **AIG is its own repository and release.** It is not part of Clarion or AegisFlux for now.
2. **Contracts are consumed, never changed.** AIG uses copies of the AegisFlux schemas pinned to a known commit ([`contracts/aegisflux/`](../contracts/aegisflux)). It makes no changes in either repository.
3. **One adapter boundary.** Only these modules know the other products' formats:

   | Module | Knows |
   |---|---|
   | `aig/clarion.py` | `segmentation_policy_intent.v1` in, `segmentation_compiled_artifact.v1` out |
   | `aig/aegis.py` | `segmentation_outcome_event.v1` out |
   | `aig/token.py` | ADR-GW-002 stream-token claims |

   The engine, values tracking, gateway and red team stay product-neutral.
4. **Integration needs are proposals, not dependencies.** AIG runs fully on its own: file-based overlays, a mock token issuer, events written to a file. These changes are written down for when Clarion and AegisFlux are ready, and nothing in AIG waits on them:
   - enable the `proxy_broker` adapter in AegisFlux's intent preview (currently `supported: false`);
   - an AegisFlux ingest path for `segmentation_outcome_event.v1` with `platform_path: proxy_broker` (cf. WO-SEG-013);
   - backend-minted stream tokens (WO-SEG-006), plus the proposed `agt`/`prn` claims as an ADR-GW-002 amendment;
   - the steering gateway class policy routing MCP traffic to AIG (WO-SEG-007);
   - an owner for `proxy_broker` placement decisions (Clarion owns placement, AegisFlux owns local enforcement, and AIG is neither).
5. **Drift is detected, not absorbed silently.** `python scripts/check_contracts.py <path-to-aegisflux-checkout>` compares the pinned copies with a current checkout. When AegisFlux changes a contract, AIG decides deliberately whether and when to follow.

## Consequences

- Clarion and AegisFlux can change freely, and AIG notices through the drift check and its contract tests.
- Production deployment of AIG behind the steering gateway waits on items under point 4. Lab and demo use don't.
- Revisit when the Clarion-AegisFlux integration has stable contracts. A likely outcome is a Go port of the gateway next to `aegis-gateway-agent`.
