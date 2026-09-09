import { decideAsk, type AskGateConfig, type AskVerdict } from "./ask_gate.js";
import { blendUncertainty, featurizeUncertainty } from "./uncertainty_featurizer.js";
import type { ConsequenceClass } from "../routing/uncertainty_router.js";

export interface CueAblationCase {
  readonly message: string;
  readonly intentUncertainty: number;
  readonly consequence: ConsequenceClass;
  readonly desiredVerdict: AskVerdict;
}

export interface CueAblationResult {
  readonly cases: number;
  readonly baselineErrors: number;
  readonly cueErrors: number;
  readonly changedDecisions: number;
  readonly harmfulFlips: number;
  readonly correctedHarmfulFlipRate: number;
  readonly maxHarmfulFlipRate: number;
  readonly enabled: boolean;
  readonly reason: string;
}

function verdictFor(c: CueAblationCase, uncertainty: number, config?: AskGateConfig): AskVerdict {
  return decideAsk({ intentUncertainty: uncertainty, consequence: c.consequence }, config).verdict;
}

/** Deploy linguistic uncertainty cues only after a bounded paired held-out ablation earns their use. */
export function evaluateCueAblation(cases: readonly CueAblationCase[], maxHarmfulFlipRate: number, config?: AskGateConfig): CueAblationResult {
  if (!(maxHarmfulFlipRate > 0 && maxHarmfulFlipRate <= 1)) throw new Error("maxHarmfulFlipRate must be in (0, 1]");
  if (cases.length > 10_000) throw new Error("cue ablation exceeds the 10000-case bound");
  for (const c of cases) {
    if (typeof c.message !== "string" || c.message.length > 16_384 || !Number.isFinite(c.intentUncertainty) || c.intentUncertainty < 0 || c.intentUncertainty > 1 || !(["reversible", "irreversible", "unknown"] as const).includes(c.consequence) || !(["ask", "proceed", "proceed-with-note"] as const).includes(c.desiredVerdict)) throw new Error("cue ablation case is malformed or outside bounds");
  }
  let baselineErrors = 0;
  let cueErrors = 0;
  let changedDecisions = 0;
  let harmfulFlips = 0;
  for (const c of cases) {
    const baseline = verdictFor(c, c.intentUncertainty, config);
    const withCues = verdictFor(c, blendUncertainty(c.intentUncertainty, featurizeUncertainty(c.message).uncertainty), config);
    const baselineCorrect = baseline === c.desiredVerdict;
    const cueCorrect = withCues === c.desiredVerdict;
    if (!baselineCorrect) baselineErrors++;
    if (!cueCorrect) cueErrors++;
    if (baseline !== withCues) { changedDecisions++; if (baselineCorrect && !cueCorrect) harmfulFlips++; }
  }
  const correctedHarmfulFlipRate = (harmfulFlips + 1) / (changedDecisions + 1);
  const improves = cueErrors < baselineErrors;
  const riskControlled = changedDecisions > 0 && correctedHarmfulFlipRate <= maxHarmfulFlipRate;
  const enabled = cases.length > 0 && improves && riskControlled;
  const reason = cases.length === 0 ? "no held-out cases" : !improves ? "cue arm did not strictly reduce decision errors" : !riskControlled ? `corrected harmful-flip rate ${correctedHarmfulFlipRate.toFixed(3)} exceeds ${maxHarmfulFlipRate.toFixed(3)}` : `cue arm reduced errors and corrected harmful-flip rate ${correctedHarmfulFlipRate.toFixed(3)} is within ${maxHarmfulFlipRate.toFixed(3)}`;
  return { cases: cases.length, baselineErrors, cueErrors, changedDecisions, harmfulFlips, correctedHarmfulFlipRate, maxHarmfulFlipRate, enabled, reason };
}
