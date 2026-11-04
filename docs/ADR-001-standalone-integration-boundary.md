# ADR-001: AIG is a standalone dentro.io product; Clarion and AegisFlux integrations are optional

**Status:** Accepted (2026-11-02), amended 2026-11-03

## Context

dentro.io is the umbrella for three products: Clarion (enterprise policy intent), AegisFlux (endpoint and agent evidence, local control) and AIG (data-flow enforcement for AI agent tool calls). Clarion and AegisFlux are both under active development, and the integration between them has only just started. AIG sits between the two: it compiles Clarion intent and emits AegisFlux evidence. If AIG required changes in either product, it would put pressure on an integration that is still being designed. Customers should also be able to start with any one product.

## Decision

1. **AIG is a standalone product in the dentro.io suite.** It has its own repository and release, and it works without Clarion or AegisFlux.
2. **Each integration upgrades something AIG already does on its own; none is required:**

   | Capability | AIG standalone | With Clarion | With AegisFlux |
   |---|---|---|---|
   | Policy | Local policy, plus rules suggested from observe mode | Compiled from enterprise intent, approved and versioned centrally | — |
   | Agent identity | Single sign-on for the principal, plus its own agent registration | — | Endpoint-proven identity (device, process, agent instance) |
   | Can't be bypassed | Credential brokering: the gateway holds the upstream credentials | — | Traffic steering: the only route to MCP is the gateway |
   | Data labels | Labels from the customer's existing data classification | Sensitivity from intent | — |
   | Evidence | Its own tamper-evident log, console and SIEM export | Clarion Verify: intended versus actual outcomes | Joined with host and flow evidence |
   | Response | Its own quarantine (revoke an agent's access) | — | Quarantine triggered by host detections |

3. **One console look across the suite.** AIG's console follows the Clarion and AegisFlux console conventions: the same shell, navigation, components, palette and theme behaviour, so an operator moves between products without relearning anything.
4. **Contracts are consumed, never changed.** AIG uses copies of the AegisFlux schemas pinned to a known commit ([`contracts/aegisflux/`](../contracts/aegisflux)). It makes no changes in either repository.
5. **One adapter boundary.** Only these modules know the other products' formats:

   | Module | Knows |
   |---|---|
   | `aig/clarion.py` | `segmentation_policy_intent.v1` in, `segmentation_compiled_artifact.v1` out |
   | `aig/aegis.py` | `segmentation_outcome_event.v1` out |
   | `aig/token.py` | ADR-GW-002 stream-token claims |

   The engine, value tracking, gateway and red team stay product-neutral.
6. **Integration needs are proposals, not dependencies.** These are written down for when Clarion and AegisFlux are ready, and nothing in AIG waits on them:
   - enable the `proxy_broker` adapter in AegisFlux's intent preview (currently `supported: false`);
   - an AegisFlux ingest path for `segmentation_outcome_event.v1` with `platform_path: proxy_broker` (cf. WO-SEG-013);
   - backend-minted stream tokens (WO-SEG-006), plus the proposed `agt`/`prn` claims as an ADR-GW-002 amendment;
   - the steering gateway class policy routing MCP traffic to AIG (WO-SEG-007);
   - an owner for `proxy_broker` placement decisions (Clarion owns placement, AegisFlux owns local enforcement, and AIG is neither).
7. **Drift is detected, not absorbed silently.** `python scripts/check_contracts.py <path-to-aegisflux-checkout>` compares the pinned copies with a current checkout.
8. **Later, a shared contracts package.** Once the Clarion–AegisFlux integration settles, the pinned schemas move to one dentro.io contracts package (intent, artifact, outcome event, identity token). Each product then depends on that package, never on another product.

## Consequences

- Clarion and AegisFlux can change freely, and AIG notices through the drift check and its contract tests.
- AIG's standalone gaps are explicit: single sign-on, credential brokering, existing data labels and SIEM export. They are also the work that makes the integrations worth having.
- Production deployment behind the steering gateway waits on items under point 6. Standalone use, lab and demos don't.
- Revisit when the suite's contracts are stable. A likely outcome is a Go port of the gateway next to `aegis-gateway-agent`.
