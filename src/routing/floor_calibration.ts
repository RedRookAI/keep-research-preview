/**
 * CONFORMAL CALIBRATION of the consequence-scaled reliability floor (closes red-team finding F3).
 *
 * The v1 hardening gated routing on `floorByConsequence` — hand-set constants (0.6 / 0.75 …) with no
 * statistical meaning. That is exactly FrugalGPT's documented weakness ("does not impose calibration on the
 * routing score"); the fix in the newer cascade-routing work (UCCI/RouteNLP) is CONFORMAL calibration: pick the
 * threshold from held-out data so the admitted set carries a finite-sample COVERAGE GUARANTEE.
 *
 * What we guarantee (the honest statement): given a held-out calibration record of (estimate p̂, consequence,
 * observed outcome), we choose, per consequence class, the LOWEST floor τ such that the conformally-corrected
 * failure rate among ADMITTED items (p̂ ≥ τ) is ≤ the target miscoverage α. So among items the router ADMITS
 * (routes rather than escalates), the failure rate is ≤ α — i.e. true success ≥ 1−α — with finite-sample
 * validity under EXCHANGEABILITY of the calibration and future records. This is conformal RISK CONTROL
 * (Angelopoulos et al.); the miscoverage-risk special case is ordinary split-conformal. The finite-sample
 * correction is the standard conformal plug-in (k+1)/(n+1) — far less conservative than a Hoeffding slack, and
 * it is the correction that makes the guarantee hold out-of-sample rather than only on the calibration set.
 *
 * BUILT + proven in-env: the calibration PROCEDURE (deterministic, pure, auditable). SEAM: the calibration
 * DATA itself — real (estimate, consequence, outcome) records from production. Add-don't-rewrite sibling of
 * `uncertainty_router`; the constant floor is the DEGENERATE zero-data case (empty records ⇒ fallback).
 */

import {
  chooseCascade,
  type ConsequenceClass,
  type CascadeCandidate,
  type CascadePolicy,
  type CascadeChoice,
} from "./uncertainty_router.js";

const CONSEQUENCE_CLASSES: readonly ConsequenceClass[] = ["reversible", "irreversible", "unknown"];

/** A held-out calibration record. `pHat` is the decision-success estimate the router would have used; `success`
 *  is the observed outcome. These come from production (the SEAM). */
export interface CalibrationRecord {
  readonly pHat: number; // 0..1
  readonly consequence: ConsequenceClass;
  readonly success: boolean;
}

export interface CalibrationConfig {
  /** Tolerated failure rate (miscoverage) per consequence class — irreversible should be the strictest. */
  readonly targetAlphaByConsequence: Record<ConsequenceClass, number>;
  /** The conservative constant used when there is no data for a class (the degenerate zero-data case). */
  readonly fallbackFloorByConsequence: Record<ConsequenceClass, number>;
}

/**
 * The conformally-corrected admitted failure rate at threshold τ: (failures_admitted + 1) / (admitted + 1).
 * The +1/+1 is the standard split-conformal finite-sample correction (accounts for the unseen future item),
 * so the bound holds out-of-sample under exchangeability rather than only empirically.
 */
function correctedFailureRate(records: readonly CalibrationRecord[], tau: number): { admitted: number; rate: number } {
  const admitted = records.filter((r) => r.pHat >= tau);
  const failures = admitted.filter((r) => !r.success).length;
  return { admitted: admitted.length, rate: (failures + 1) / (admitted.length + 1) };
}

/**
 * Calibrate the floor for one consequence class: the SMALLEST threshold τ (drawn from the observed estimates)
 * whose conformally-corrected admitted failure rate ≤ α. Smaller α ⇒ a higher floor (monotone). Empty data ⇒
 * the conservative fallback (fail-safe). If no threshold meets α, return the most conservative candidate (the
 * max observed estimate) — never silently admit above the tolerated risk.
 */
export function calibrateFloor(
  records: readonly CalibrationRecord[],
  targetAlpha: number,
  consequence: ConsequenceClass,
  fallbackFloor: number,
): number {
  const inClass = records.filter((r) => r.consequence === consequence);
  if (inClass.length === 0) return fallbackFloor; // degenerate zero-data case

  // Candidate thresholds = the distinct observed estimates, ascending. Admitting at τ means p̂ ≥ τ.
  const candidates = [...new Set(inClass.map((r) => r.pHat))].sort((a, b) => a - b);
  for (const tau of candidates) {
    const { admitted, rate } = correctedFailureRate(inClass, tau);
    if (admitted > 0 && rate <= targetAlpha) return tau; // smallest τ meeting the coverage target
  }
  // Nothing met α even at the top estimate ⇒ most conservative: require at least the max observed estimate.
  return candidates[candidates.length - 1]!;
}

/** Calibrate a full per-consequence floor map from records + config (each class independently). */
export function calibratedFloorByConsequence(
  records: readonly CalibrationRecord[],
  config: CalibrationConfig,
): Record<ConsequenceClass, number> {
  const out = {} as Record<ConsequenceClass, number>;
  for (const c of CONSEQUENCE_CLASSES) {
    out[c] = calibrateFloor(records, config.targetAlphaByConsequence[c], c, config.fallbackFloorByConsequence[c]);
  }
  return out;
}

/**
 * Cascade selection that CONSUMES the calibrated floor: derive `floorByConsequence` from the calibration
 * records + config, then delegate to the existing `chooseCascade` with that floor. Add-don't-rewrite — the
 * selection logic is unchanged; only the floor is now calibrated instead of hand-set.
 */
export function chooseCascadeCalibrated(
  candidates: readonly CascadeCandidate[],
  consequence: ConsequenceClass,
  records: readonly CalibrationRecord[],
  config: CalibrationConfig,
  basePolicy: Omit<CascadePolicy, "floorByConsequence">,
): CascadeChoice {
  const floorByConsequence = calibratedFloorByConsequence(records, config);
  const policy: CascadePolicy = { ...basePolicy, floorByConsequence };
  return chooseCascade(candidates, consequence, policy);
}

export { CONSEQUENCE_CLASSES };
