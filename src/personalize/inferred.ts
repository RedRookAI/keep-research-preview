/**
 * LEARNED PREFERENCE INFERENCE feeding the safe envelope — clamped, consequence-gated, NO rubber-stamp.
 *
 * Routing every inferred preference to a human confirmation is the rubber-stamp anti-pattern: it trains the
 * operator to click "yes" and violates gate-on-consequence. So an inferred preference flows through the SAME
 * envelope as an explicit one (validate → CP-net scope → `applyWithinPolicy` clamp → `RevisionStore.revise`) and
 * AUTO-APPLIES without a human — because the clamp structurally guarantees the only thing an inferred preference
 * can touch is CONVENIENCE within policy bounds. The worst case of a wrong inference is a reversible cosmetic
 * default. The human is never interrupted; they keep PULL agency (inspect / override / supersede any inferred
 * preference), never PUSH confirmation. Anything an inference reaches toward a SAFETY knob is dropped outright
 * (the clamp is a hard bound, not a tap).
 *
 * Two structural guards make autonomy safe (both BUILT + proven; the ESTIMATOR that produces the raw signal is
 * the SEAM):
 *   - ANTI-THRASH (non-stationarity: drift vs shift). A noisy signal must not oscillate the current view. An
 *     inferred candidate must persist a minimum DWELL of consistent observations AND clear a DEAD-BAND on the
 *     posterior lower-confidence bound before it may supersede (hysteresis — an asymmetric flip threshold). The
 *     consistency posterior reuses the routing Beta apparatus (`priorPosterior`/`updatePosterior`/`successLCB`).
 *     (Active change-point detection — CUSUM — is a SEAM refinement, not needed for v1's passive dwell/dead-band.)
 *   - CP-net SCOPE. An inferred candidate carries the scope it was OBSERVED in and supersedes only that scope's
 *     preference; resolution (the envelope) then applies it only on context match — no overgeneralization.
 *
 * SAFETY RULE for inferred: inference may only ever write COSMETIC dimensions. Any candidate on a safety-relevant
 * dimension (minReliability / autonomy / modelTier) is dropped — inference cannot touch a safety knob at all,
 * even to increase caution (a quiet self-restriction is still a surprise the operator didn't ask for). The
 * envelope's `applyWithinPolicy` is the second lock: even a relaxing value that somehow reached the spine is
 * neutralized at read time.
 */

import {
  applyWithinPolicy,
  validate,
  type PreferenceDimension,
  type PolicyBounds,
  type PersonalizeContext,
} from "./personalize.js";
import type { RevisionStore } from "../frontdoor/revision_store.js";
import {
  priorPosterior,
  updatePosterior,
  successLCB,
  type SuccessPosterior,
} from "../routing/uncertainty_router.js";

/** The dimensions inference is permitted to write — CONVENIENCE only. */
const COSMETIC: ReadonlySet<PreferenceDimension> = new Set<PreferenceDimension>(["promptFormat", "verbosity"]);

export interface InferredTarget {
  readonly dimension: PreferenceDimension;
  readonly value: string;
  readonly scope?: string | undefined; // the CP-net scope the signal was observed in
}

export interface CandidatePreference {
  readonly dimension: PreferenceDimension;
  readonly value: string;
  readonly scope?: string | undefined;
  readonly origin: "inferred";
  readonly posterior: SuccessPosterior; // consistency posterior (dwell-confidence)
  readonly observations: number; // dwell count
}

export interface AdmitPolicy {
  readonly minDwell: number; // minimum consistent observations before a flip is allowed
  readonly flipLCB: number; // dead-band: the posterior LCB must clear this to flip (hysteresis)
  readonly k: number; // caution level for the confidence bound
}

export interface ApplyResult {
  readonly applied: boolean;
  readonly reason: string;
}

/** Fold a sequence of observations (each: did the signal agree with the candidate?) into a candidate with a
 *  consistency posterior + dwell count. The observations come from the SEAM estimator. */
export function proposeInferred(target: InferredTarget, observations: readonly boolean[]): CandidatePreference {
  const posterior = observations.reduce<SuccessPosterior>((p, ok) => updatePosterior(p, ok), priorPosterior());
  return {
    dimension: target.dimension,
    value: target.value,
    scope: target.scope,
    origin: "inferred",
    posterior,
    observations: observations.length,
  };
}

/**
 * The ANTI-THRASH gate. Admit an inferred candidate to supersede the incumbent ONLY when it has (a) persisted a
 * minimum DWELL of observations, and (b) cleared the DEAD-BAND — the posterior lower-confidence bound exceeds
 * `flipLCB` (we are confident the signal is consistent, not noise). If the candidate value already equals the
 * incumbent there is nothing to flip. This is hysteresis: the bar to change is deliberately above zero, so an
 * oscillating or single-shot signal cannot flip the current view.
 */
export function admitInferred(candidate: CandidatePreference, incumbentValue: string | undefined, policy: AdmitPolicy): boolean {
  if (candidate.value === incumbentValue) return false; // already current — no flip
  if (candidate.observations < policy.minDwell) return false; // DWELL not met
  return successLCB(candidate.posterior, policy.k) >= policy.flipLCB; // DEAD-BAND / hysteresis
}

function itemKeyFor(dim: PreferenceDimension, scope: string | undefined): string {
  return `pref:${dim}${scope !== undefined ? "@" + scope : ""}`;
}

/** Provenance is carried in the spine's `reason` channel (the Version has no `origin` field and we do not modify
 *  the spine). An inferred write tags the reason; `provenanceOf` reads it back. */
export function provenanceString(candidate: CandidatePreference): string {
  return `inferred|obs=${candidate.observations}|lcb=${successLCB(candidate.posterior).toFixed(3)}`;
}
export function provenanceOf(reason: string | undefined): "inferred" | "operator" {
  return reason !== undefined && reason.startsWith("inferred") ? "inferred" : "operator";
}

/**
 * Auto-apply an inferred candidate — NO human step. Drops any safety-dimension candidate (the clamp is a hard
 * bound). For a cosmetic candidate: validates the value (data-not-instructions, reusing the envelope's
 * `validate`), runs the anti-thrash gate against the current incumbent for this dimension+scope, and if admitted
 * SUPERSEDES the incumbent on the spine tagged `origin=inferred`. The effective profile then reflects it via the
 * envelope's `resolveProfile` (which re-applies `applyWithinPolicy` — the second safety lock).
 */
export function applyInferred(
  store: RevisionStore,
  candidate: CandidatePreference,
  ctx: PersonalizeContext,
  bounds: PolicyBounds,
  policy: AdmitPolicy,
): ApplyResult {
  if (!COSMETIC.has(candidate.dimension)) {
    // Hard bound: inference may not touch a safety knob. Demonstrate the clamp would neutralize it anyway.
    void applyWithinPolicy({ [candidate.dimension]: coerce(candidate.value) }, bounds);
    return { applied: false, reason: "inferred safety-target dropped (clamp is a hard bound, not a tap)" };
  }
  if (validate(candidate.dimension, candidate.value) === undefined) {
    return { applied: false, reason: "invalid value rejected as data (not obeyed)" };
  }
  const key = itemKeyFor(candidate.dimension, candidate.scope);
  const incumbent = store.current(key)?.content;
  if (!admitInferred(candidate, incumbent, policy)) {
    return { applied: false, reason: "not admitted — dwell/dead-band not cleared (anti-thrash)" };
  }
  const reason = provenanceString(candidate);
  if (store.current(key) !== undefined) {
    store.revise(key, candidate.value, reason);
  } else {
    store.create(key, "preference", candidate.value); // first write (spine `create` carries no reason — noted)
  }
  return { applied: true, reason: "auto-applied (cosmetic, admitted) — no human step" };
}

function coerce(value: string): string | number {
  const n = Number(value);
  return Number.isFinite(n) && value.trim() !== "" ? n : value;
}

export { COSMETIC };
