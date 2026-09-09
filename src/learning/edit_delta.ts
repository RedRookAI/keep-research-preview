/**
 * Edit-delta distillation (Phase 3.5, Feature 5) — human feedback -> lessons.
 *
 * The diff between what Keep PRODUCED and what the human SHIPPED is high-signal: it
 * encodes a real preference the objective build outcome can later confirm. Keep
 * distills a candidate lesson from that edit-delta (the Cursor Bugbot "Learned
 * Rules" / Qodo "attribution" 2026 pattern), and from human DISMISSALS of findings
 * (a dismissal should stop that finding class resurfacing — CodeAnt "Learnings").
 *
 * Objective-anchored: distilled lessons enter Phase 1 memory on PROBATION and must
 * earn graduation via Keep's own verified outcomes — never trusted on the human
 * signal alone (delta-learning degrades when the quality gap is noisy).
 */

import type { MemoryStore } from "../memory/store.js";
import type { Lesson } from "../memory/model.js";
import { analyzeEdit, type EditPatternKind } from "./edit_differ.js";

export interface EditDelta {
  /** What Keep produced. */
  readonly produced: string;
  /** What the human actually shipped (the correction). */
  readonly shipped: string;
  /** The change/PR context (repo/file) for provenance. */
  readonly context: string;
}

export interface FindingDismissal {
  /** The finding category the human dismissed (e.g. "style"). */
  readonly category: string;
  /** A short signature of the dismissed pattern, so it stops resurfacing. */
  readonly patternSignature: string;
  readonly context: string;
}

/** The distilled result: a generalized lesson + its structural pattern signature. */
export interface DistilledLesson {
  readonly lesson: Lesson;
  readonly patternKind: EditPatternKind;
  /** Signature that matches recurrences of the PATTERN, not the literal text. */
  readonly patternSignature: string;
}

/**
 * Distill a GENERALIZED, reusable lesson from an edit-delta into memory (probation,
 * origin external). Uses the structural differ: the stored lesson describes the
 * pattern (e.g. "operator direction", "added null guard"), and the pattern signature
 * lets the shadow-mode corpus and retrieval match recurrences of the pattern.
 * Returns undefined if there is no meaningful structural change (no signal) or the
 * ingestion gate rejected the content.
 */
export async function distillFromEdit(store: MemoryStore, delta: EditDelta): Promise<DistilledLesson | undefined> {
  const analyzed = analyzeEdit(delta.produced, delta.shipped);
  if (!analyzed.hasChange) return undefined; // no correction => no signal

  const p = analyzed.pattern;
  const content = `[${p.kind}] ${p.lesson} (observed in ${delta.context})`;
  const lesson = await store.ingest(content, { origin: "external", scope: "project" });
  if (!lesson) return undefined;
  return { lesson, patternKind: p.kind, patternSignature: p.signature };
}

/**
 * Distill a suppression lesson from a human dismissal (probation). The lesson
 * records that this finding class was dismissed in-context, so the display layer
 * can down-weight it (stops resurfacing). Objective-anchored: if it turns out the
 * suppressed class later correlates with regressions, negative-flip demotes it.
 */
export async function distillFromDismissal(store: MemoryStore, d: FindingDismissal): Promise<Lesson | undefined> {
  const content =
    `In ${d.context}, the human dismissed "${d.category}" findings matching ` +
    `"${d.patternSignature}" — down-weight this finding class here unless severity rises.`;
  return store.ingest(content, { origin: "external", scope: "project" });
}
