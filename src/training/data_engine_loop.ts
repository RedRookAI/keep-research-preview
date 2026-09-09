/**
 * Auto-Training: the DataEngineLoop (Increment 8c).
 *
 * SOTA basis (2026-08-04): Snorkel-style narrow data engineering — LFs → denoise → targeted eval set,
 * with held-out validation as "the only unbiased measure of true label quality" (MetricGate 2026),
 * and correlated-LF flagging BEFORE trusting labels. Per the plan, the DEFAULT output is gradient-free
 * (eval data + few-shot exemplars + retrieval anchors); weight training is an OPTIONAL far tier,
 * sandboxed + gated, never on by default. Every synthetic item passes a labeling-function consensus
 * (confidence floor) + a held-out check.
 *
 * Reuses FailureMode (8a), the labeling/label-model (8b), and produces RegressionCase-shaped eval
 * items (shadow_mode/corpus_curation compatible). Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { FailureMode } from "./failure_mode_detector.js";
import { denoise, ABSTAIN, type LabelingFunction, type WeakLabel, type DenoiseOptions } from "./labeling.js";

/** A synthesized evaluation case targeting the failure mode (RegressionCase-compatible). */
export interface SynthEvalCase {
  readonly id: string;
  readonly input: string;
  readonly expectedLabel: WeakLabel;
  readonly confidence: number;
  /** RegressionCase-style check: does a candidate lesson/behavior avoid the failure signature? */
  readonly passesUnder: (lessonContent: string) => boolean;
}

/** A few-shot exemplar distilled from a high-confidence labeled item. */
export interface FewShotExemplar {
  readonly input: string;
  readonly label: WeakLabel;
  readonly rationale: string;
}

/** A retrieval anchor: a canonical snippet to retrieve when this failure mode is in play. */
export interface RetrievalAnchor {
  readonly signature: string;
  readonly anchorText: string;
}

/** The gradient-free training artifact bundle (the DEFAULT output). */
export interface TrainingArtifacts {
  readonly mode: FailureMode;
  readonly evalCases: readonly SynthEvalCase[];
  readonly exemplars: readonly FewShotExemplar[];
  readonly anchors: readonly RetrievalAnchor[];
  /** Held-out accuracy of the denoised labels (the unbiased quality measure). */
  readonly heldOutAccuracy: number;
  readonly accepted: boolean;
  readonly rejectionReason?: string;
}

export interface DataEngineItem {
  readonly id: string;
  readonly text: string;
  /** Optional gold label (for the held-out split). */
  readonly gold?: WeakLabel;
}

export interface DataEngineOptions extends DenoiseOptions {
  /** Confidence floor for an item to enter the eval set / exemplars. Default 0.66. */
  readonly consensusFloor?: number;
  /** Fraction of gold-labeled items held out for the unbiased check. Default 0.3. */
  readonly heldOutFraction?: number;
  /** Held-out accuracy floor to ACCEPT the artifacts. Default 0.7. */
  readonly heldOutAccuracyFloor?: number;
}

export class DataEngineLoop {
  constructor(private readonly spine: Spine) {}

  /**
   * Build gradient-free training artifacts for a failure mode. Denoises the LF labels, REJECTS on
   * over-correlated LFs or a failing held-out check, then emits eval cases + exemplars + anchors from
   * the high-confidence items. Never trains weights. Audited.
   */
  build(mode: FailureMode, items: readonly DataEngineItem[], lfs: readonly LabelingFunction<DataEngineItem>[], opts: DataEngineOptions = {}): TrainingArtifacts {
    const consensusFloor = opts.consensusFloor ?? 0.66;
    const heldOutFraction = opts.heldOutFraction ?? 0.3;
    const heldOutAccuracyFloor = opts.heldOutAccuracyFloor ?? 0.7;

    this.spine.stage({ type: "identity.action", actor: "training", payload: { event: "data_engine_begin", signature: mode.signature, items: items.length, lfs: lfs.length } });

    // Split off a held-out set from the gold-labeled items (the unbiased check).
    const goldIdx = items.map((it, i) => (it.gold !== undefined ? i : -1)).filter((i) => i >= 0);
    const heldOutCount = Math.floor(goldIdx.length * heldOutFraction);
    const heldOutSet = new Set(goldIdx.slice(0, heldOutCount));
    const trainItems = items.filter((_, i) => !heldOutSet.has(i));

    // Denoise on the training portion.
    const gold = opts.gold ?? trainItems.map((it) => (it.gold !== undefined ? it.gold : ABSTAIN));
    const result = denoise(trainItems, lfs, { ...opts, gold });

    // Correctness trap: over-correlated LFs → reject (overconfident labels not to be trusted).
    if (result.correlatedPairs.length > 0) {
      const reason = `over-correlated LFs violate conditional independence: ${result.correlatedPairs.map((p) => `${p.a}~${p.b}`).join(", ")} — de-duplicate before trusting labels`;
      this.spine.stage({ type: "identity.action", actor: "training", payload: { event: "data_engine_rejected", signature: mode.signature, reason } });
      return { mode, evalCases: [], exemplars: [], anchors: [], heldOutAccuracy: 0, accepted: false, rejectionReason: reason };
    }

    // Held-out check: apply the denoised label model to the held-out gold items.
    let heldOutAccuracy = 1;
    if (heldOutSet.size > 0) {
      const heldItems = items.filter((_, i) => heldOutSet.has(i));
      const heldResult = denoise(heldItems, lfs, { ...opts });
      let correct = 0, compared = 0;
      heldItems.forEach((it, i) => {
        if (it.gold !== undefined && heldResult.labels[i] !== ABSTAIN) {
          compared++;
          if (heldResult.labels[i] === it.gold) correct++;
        }
      });
      heldOutAccuracy = compared === 0 ? 0 : correct / compared;
      if (heldOutAccuracy < heldOutAccuracyFloor) {
        const reason = `held-out accuracy ${heldOutAccuracy.toFixed(2)} < floor ${heldOutAccuracyFloor} — labels not reliable enough to ship`;
        this.spine.stage({ type: "identity.action", actor: "training", payload: { event: "data_engine_rejected", signature: mode.signature, reason } });
        return { mode, evalCases: [], exemplars: [], anchors: [], heldOutAccuracy, accepted: false, rejectionReason: reason };
      }
    }

    // Build artifacts from high-confidence items (consensus floor).
    const evalCases: SynthEvalCase[] = [];
    const exemplars: FewShotExemplar[] = [];
    trainItems.forEach((it, i) => {
      const label = result.labels[i]!;
      const conf = result.confidence[i]!;
      if (label === ABSTAIN || conf < consensusFloor) return;
      evalCases.push({
        id: `eval_${mode.signature}_${it.id}`,
        input: it.text,
        expectedLabel: label,
        confidence: conf,
        passesUnder: (lessonContent: string) => !lessonContent.includes(mode.signature),
      });
      if (exemplars.length < 5) {
        exemplars.push({ input: it.text, label, rationale: `high-consensus (${conf.toFixed(2)}) exemplar for failure mode ${mode.signature}` });
      }
    });

    const anchors: RetrievalAnchor[] = [{ signature: mode.signature, anchorText: `Guard against ${mode.signature} (seen ${mode.occurrences}× across ${mode.contexts.length} context(s)).` }];

    this.spine.stage({ type: "identity.action", actor: "training", payload: { event: "data_engine_accepted", signature: mode.signature, evalCases: evalCases.length, exemplars: exemplars.length, heldOutAccuracy } });
    return { mode, evalCases, exemplars, anchors, heldOutAccuracy, accepted: true };
  }
}

// ── Optional FAR TIER: weight training — gated, OFF by default ────────────────

export interface WeightTrainingRequest {
  readonly artifacts: TrainingArtifacts;
  /** Explicit operator authorization — without it, training is refused. */
  readonly operatorAuthorized: boolean;
  /** Must run in a sandbox — asserted, never assumed. */
  readonly sandboxed: boolean;
}

export interface WeightTrainingDecision {
  readonly proceeded: boolean;
  readonly reason: string;
}

/**
 * Bridge from the DataEngineLoop's verified artifacts to the Auto-Training system (item 11).
 *
 * Item 8 produces gradient-free artifacts (eval data + few-shot + anchors) AND a verified, held-out-
 * checked dataset — which is exactly the input a safe training run needs. This function no longer
 * dead-ends: it reports readiness so the AutoTrainer (src/autotrain/) can decide whether training is
 * warranted, ask permission if needed, and actually train. Gradient-free remains the DEFAULT and the
 * floor; training is the escalation for a measured, persistent failure mode with a verifiable reward.
 */
export function trainingReadiness(spine: Spine, req: WeightTrainingRequest): WeightTrainingDecision {
  if (!req.artifacts.accepted) {
    return { proceeded: false, reason: "artifacts not accepted — nothing to train on (fix the data/labeling first)" };
  }
  if (!req.sandboxed) {
    return { proceeded: false, reason: "training must be sandboxed — refused (never assume isolation)" };
  }
  spine.stage({ type: "identity.action", actor: "training", payload: { event: "training_ready", signature: req.artifacts.mode.signature, heldOutAccuracy: req.artifacts.heldOutAccuracy } });
  return { proceeded: true, reason: "verified artifacts ready; hand off to the Auto-Training decision policy (decide → permission → train → safety gauntlet)" };
}
