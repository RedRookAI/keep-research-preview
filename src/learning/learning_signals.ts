/**
 * Learning-signals suite — the human-in-the-loop learning inputs + PR-time signals.
 *
 * Two learning signals the solve-outcome wire doesn't cover:
 *  - edit-delta distillation: the diff between what Keep PRODUCED and what the human SHIPPED is high-signal — it encodes a
 *    real preference. Keep distills a GENERALIZED lesson (the pattern, not the literal text) into memory, and likewise
 *    turns a human's finding-DISMISSAL into a suppression lesson. This closes the human-correction → lesson loop that
 *    then feeds retrieval + application.
 *  - PR-time signals: a lesson BADGE (which CONFIRMED lessons a change relied on — merge-readiness), and objective
 *    SPEC-DRIFT detection (a required capability not evidenced, or the spec-encoding tests failing). Spec-drift is
 *    anchored to the approved spec + test outcomes — it never asks one agent to judge another.
 *
 * SOTA basis (2026-08-08): learning a reusable rule from an accepted human edit is the Cursor Bugbot "Learned Rules" /
 * Qodo "attribution" pattern; the generalization (pattern signature, not literal text) is what makes it reusable and
 * keeps it from overfitting one diff. What would change it: promoting a captured lesson into an APPLIED skill is the
 * existing skill-distiller path — these lessons are captured + retrievable; auto-promotion to skills is that separate loop.
 */

import { distillFromEdit, distillFromDismissal, type EditDelta, type FindingDismissal, type DistilledLesson } from "./edit_delta.js";
import { buildLessonBadge, detectSpecDrift, type LessonBadge, type SpecDriftInput, type SpecDriftResult } from "./badges_drift.js";
import { MemoryStore } from "../memory/store.js";
import type { Lesson } from "../memory/model.js";
import type { Spine } from "../spine/spine.js";
import type { ModelGateway } from "../gateway/gateway.js";

export interface LearningSignals {
  /** The memory human-feedback lessons are captured into (probation/candidate tier, origin external). */
  readonly memory: MemoryStore;
  /** Capture a human edit (produced vs shipped) as a generalized lesson. Undefined if there's no structural signal. */
  recordEdit(produced: string, shipped: string, context: string): Promise<DistilledLesson | undefined>;
  /** Capture a human's finding dismissal as a suppression lesson (stops that finding class resurfacing here). */
  recordDismissal(category: string, patternSignature: string, context: string): Promise<Lesson | undefined>;
  /** Build a PR merge-readiness badge from the lessons a change relied on (only CONFIRMED lessons earn authority). */
  lessonBadge(reliedOn: readonly Lesson[]): LessonBadge;
  /** Objective spec-drift detection (required capability not evidenced, or spec-encoding tests failing). */
  specDrift(input: SpecDriftInput): SpecDriftResult;
}

export function buildLearningSignals(spine: Spine, gateway: ModelGateway): LearningSignals {
  const memory = new MemoryStore(spine, gateway);
  return {
    memory,
    recordEdit: (produced, shipped, context) => distillFromEdit(memory, { produced, shipped, context } satisfies EditDelta),
    recordDismissal: (category, patternSignature, context) =>
      distillFromDismissal(memory, { category, patternSignature, context } satisfies FindingDismissal),
    lessonBadge: (reliedOn) => buildLessonBadge(reliedOn),
    specDrift: (input) => detectSpecDrift(input),
  };
}
