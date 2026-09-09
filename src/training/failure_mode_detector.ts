/**
 * Auto-Training: the failure-mode detector (Increment 8a).
 *
 * SOTA basis (2026-08-04): Auto-Training is the Snorkel tier — it fires only when a SPECIFIC,
 * MEASURED failure mode RECURS (not bulk). So the detector clusters recurring regression signatures
 * from observed BuildOutcomes and surfaces only modes that cross a recurrence threshold; a one-off
 * regression must NOT trigger narrow data engineering (that would be the "bulk" anti-pattern).
 *
 * Reuses BuildOutcome (corpus_curation) — every regressed build already carries a structural
 * `regressionSignature`. This detector is the trigger that gates the DataEngineLoop (8b/8c). Zero deps.
 */

import type { BuildOutcome } from "../learning/corpus_curation.js";

/** A recurring, measured failure mode worth targeting with narrow data engineering. */
export interface FailureMode {
  /** The structural regression signature that recurs. */
  readonly signature: string;
  /** How many observed builds exhibited it. */
  readonly occurrences: number;
  /** Distinct build contexts it appeared in (breadth — a mode across contexts is higher-value). */
  readonly contexts: readonly string[];
  /** The build ids exhibiting it (provenance for the eval set). */
  readonly buildIds: readonly string[];
  /** Most recent occurrence timestamp (recency — stale modes may already be fixed). */
  readonly lastSeenTs: number;
}

export interface FailureModeDetectorOptions {
  /** Minimum occurrences for a signature to count as a recurring mode. Default 3 (measured, not one-off). */
  readonly recurrenceThreshold?: number;
  /** Only consider outcomes at/after this timestamp (recency window). Default: all. */
  readonly since?: number;
}

/**
 * Detect recurring, measured failure modes from observed build outcomes. Clusters regressed builds
 * by their structural signature; returns only signatures that recur at/above the threshold, sorted
 * by occurrences (then breadth). A single regression does not qualify — the trigger is recurrence.
 */
export function detectFailureModes(outcomes: readonly BuildOutcome[], opts: FailureModeDetectorOptions = {}): FailureMode[] {
  const threshold = opts.recurrenceThreshold ?? 3;
  const since = opts.since ?? -Infinity;

  const bySig = new Map<string, { count: number; contexts: Set<string>; buildIds: string[]; lastSeen: number }>();
  for (const o of outcomes) {
    if (o.cleanResolved) continue; // only regressed/failed builds carry a failure signature
    if (o.ts < since) continue;
    const sig = o.regressionSignature;
    if (!sig) continue;
    let entry = bySig.get(sig);
    if (!entry) { entry = { count: 0, contexts: new Set(), buildIds: [], lastSeen: 0 }; bySig.set(sig, entry); }
    entry.count++;
    entry.contexts.add(o.context);
    entry.buildIds.push(o.buildId);
    if (o.ts > entry.lastSeen) entry.lastSeen = o.ts;
  }

  const modes: FailureMode[] = [];
  for (const [signature, e] of bySig) {
    if (e.count < threshold) continue; // not yet recurring — do NOT trigger training
    modes.push({ signature, occurrences: e.count, contexts: [...e.contexts], buildIds: e.buildIds, lastSeenTs: e.lastSeen });
  }
  modes.sort((a, b) => b.occurrences - a.occurrences || b.contexts.length - a.contexts.length);
  return modes;
}
