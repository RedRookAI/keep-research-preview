/**
 * Finding 2.4 — the CROSS-AGENT TAINT barrier (the third fleet-composition barrier).
 *
 * R32 (taint_tracer) labels + propagates taint WITHIN one agent's dataflow and feeds the per-decision
 * provenance veto. But a forbidden source→sink path can be SPLIT ACROSS AGENTS: one agent retrieves
 * untrusted/sensitive content, a second transforms it, a third emits it externally — "no individual
 * step looks malicious, yet the composed workflow realizes exfiltration or policy override" (SafeFlow).
 * Each hop's OWN inputs look clean to its per-agent gate; the danger is only in the cross-agent chain
 * (R39, scenario 4). The failure the per-decision gate cannot see is TRUST INHERITANCE — a consuming
 * agent implicitly trusting an upstream agent's output.
 *
 * This barrier preserves the cross-agent provenance chain and BLOCKS THE STAGED FINAL RELEASE: taint
 * does NOT reset at the agent boundary, and an external-sink effect whose cross-agent chain is
 * untrusted is denied. It composes ABOVE the per-decision gate and ALONGSIDE 2.2/2.3, feeding the
 * existing provenance veto; it does not modify the gate, R32, or the 2.2/2.3 barriers.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - SafeFlow / workflow-level IFC: preserve the cross-agent dependency, block the staged final release
 *    at the sink (taint mode: enforce downstream at the exit).
 *  - Trust inheritance is the bug: "prompt-level defenses fail across agent chains; implicit peer trust
 *    enables escalation." So taint MUST cross the boundary — a consuming agent inherits upstream taint.
 *  - Chain-of-custody: the taint label follows the value through transformation, composition, and
 *    TRANSFER across handlers; check at the exit. Any unknown link ⇒ quarantine.
 *  - Structural, not intent: the forbidden PATH is a structural property of the workflow topology
 *    (detectable "not because models are malicious"). The barrier catches the path regardless of whether
 *    the coordination is intentional collusion or emergent — and it does NOT need to determine intent.
 *  - Conservative join (reuse R32): any tainted-or-unknown hop makes the whole chain untrusted.
 *  - Authority-gated declassification (reuse R32): no agent self-declassifies the cross-agent flow.
 *
 * BUILT vs SEAM: BUILT + proven in-env is the chain logic (cross-boundary propagation, conservative
 * join, sink check, fail-safe, authority-gated declassify) + the compose helper. The real CROSS-PROCESS
 * / CROSS-HOST label propagation — carrying the taint label across actual agent/service boundaries — is
 * the SEAM. Scenario 4's FORBIDDEN-PATH composition is caught structurally; intentional-collusion INTENT
 * and purely IMPLICIT/covert channels (control-influence, timing, side channels that carry no explicit
 * label) remain DETECTION/attribution, not structural prevention (the decomposability residue).
 */

import type { Taint, Authority } from "../provenance/taint_tracer.js";

/** One hop in a cross-agent provenance chain. `taint` undefined = unknown ⇒ fail-safe (untrusted). */
export interface Hop {
  readonly agent: string;
  readonly taint: Taint | undefined;
  readonly source: string;
}

export interface ProvenanceChain {
  readonly hops: readonly Hop[];
}

export type FlowCheck =
  | { readonly clean: true }
  | { readonly clean: false; readonly reason: string };

/** An effect at a potential sink, carrying the cross-agent provenance that led to it. */
export interface SinkEffect {
  readonly agent: string;
  /** Does this effect emit externally (the staged final release / exfiltration point)? */
  readonly externalSink: boolean;
  readonly chain: ProvenanceChain;
}

/**
 * The chain's effective taint — the conservative join across ALL hops. Trusted iff every hop is
 * KNOWN-trusted; an untrusted hop OR an unknown (undefined) hop OR an empty chain ⇒ untrusted. This is
 * what makes taint cross the agent boundary: a later "trusted" hop cannot wash out an earlier tainted one.
 */
export function chainTaint(chain: ProvenanceChain): Taint {
  if (chain.hops.length === 0) return "untrusted"; // empty/unknown chain ⇒ fail-safe
  for (const h of chain.hops) {
    if (h.taint !== "trusted") return "untrusted"; // undefined (unknown) or untrusted ⇒ untrusted
  }
  return "trusted";
}

/** Extend the chain with the next agent's hop — prior hops are PRESERVED (no trust reset at the boundary). */
export function extendChain(chain: ProvenanceChain, hop: Hop): ProvenanceChain {
  return { hops: [...chain.hops, hop] };
}

/**
 * The sink check: an EXTERNAL-SINK effect whose cross-agent chain is untrusted is denied (the staged
 * final release is blocked), even if the emitting agent's own inputs look clean. A non-sink effect is
 * not a release — it does not violate here (the taint is still carried forward in its chain).
 */
export function checkCrossAgentFlow(effect: SinkEffect): FlowCheck {
  if (effect === null || typeof effect !== "object" || !validText(effect.agent, 128) || typeof effect.externalSink !== "boolean" || effect.chain === null || typeof effect.chain !== "object" || !Array.isArray(effect.chain.hops) || effect.chain.hops.length < 1 || effect.chain.hops.length > 1_024) {
    return { clean: false, reason: "unknown-provenance-chain" };
  }
  for (const hop of effect.chain.hops) {
    if (hop === null || typeof hop !== "object" || !validText(hop.agent, 128) || !validText(hop.source, 512) || (hop.taint !== "trusted" && hop.taint !== "untrusted" && hop.taint !== undefined)) {
      return { clean: false, reason: "unknown-provenance-hop" };
    }
  }
  if (!effect.externalSink) return { clean: true }; // not the release point
  if (chainTaint(effect.chain) !== "trusted") {
    const src = effect.chain.hops.find((h) => h.taint !== "trusted");
    return { clean: false, reason: `cross-agent-tainted-sink:${src?.source ?? "unknown"}@${src?.agent ?? "?"}` };
  }
  return { clean: true };
}

function validText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

/**
 * Authority-gated declassification of the whole chain. Only an AUTHORIZED trusted step clears the flow;
 * an unauthorized attempt (an agent self-declassifying the cross-agent flow) is IGNORED.
 */
export function declassifyChain(chain: ProvenanceChain, authority: Authority): ProvenanceChain {
  if (authority.authorized !== true) return chain; // no self-declassify
  return { hops: chain.hops.map((h) => ({ ...h, taint: "trusted" as Taint })) };
}

/**
 * Compose ABOVE the per-decision gate (and alongside 2.2/2.3), feeding the provenance veto: proceed only
 * if the gate auto-proceeds AND the cross-agent flow is clean. The barrier only ADDS caution.
 */
export function crossAgentAdmit(
  gateAutoProceed: boolean,
  check: FlowCheck,
): { readonly proceed: boolean; readonly reason: string } {
  if (!gateAutoProceed) return { proceed: false, reason: "per-decision-gate-hold" };
  if (!check.clean) return { proceed: false, reason: `fleet-${check.reason}` };
  return { proceed: true, reason: "gate-and-cross-agent-flow-cleared" };
}
