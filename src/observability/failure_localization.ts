/**
 * Failure localization with confirm-by-rerun (Phase 4, #43).
 *
 * The sharpest insight from the spec: failure attribution inferred from logs is an
 * UNTESTED HYPOTHESIS unless validated by execution (DoVer/AgentDebugX, 2026). So
 * localization is two steps:
 *   1. Triage (free, deterministic): walk the hierarchical trace to find the ROOT
 *      failing span — a root cause in one sub-agent propagates downstream, so the
 *      earliest failing span in a failing subtree is the hypothesis. Produce a TYPED
 *      diagnosis (llm/tool/timeout) with root cause, evidence, confidence.
 *   2. Confirm (opt-in): apply a targeted edit at the implicated step and RERUN;
 *      only a rerun that recovers CONFIRMS the hypothesis (18-49% recovery in the
 *      research). A guess that doesn't recover is reported as unconfirmed.
 */

import type { Span } from "./tracing.js";

export type FailureType = "llm-error" | "tool-error" | "timeout-error";

export interface Diagnosis {
  readonly implicatedSpanId: string;
  readonly failureType: FailureType;
  readonly rootCause: string;
  readonly evidence: readonly string[];
  /** Pre-confirmation confidence in [0,1] from deterministic triage. */
  readonly triageConfidence: number;
}

/**
 * Triage: find the root failing span in a trace. The earliest-starting failing span
 * whose parent (if any) did NOT itself fail is the root hypothesis — downstream
 * failures are treated as propagation.
 */
export function triageFailure(spans: readonly Span[]): Diagnosis | undefined {
  const failing = spans.filter((s) => s.status !== "ok");
  if (failing.length === 0) return undefined;
  const byId = new Map(spans.map((s) => [s.spanId, s]));

  // A failing span is a ROOT if it has no failing ancestor.
  const rootFailures = failing.filter((s) => {
    let cur: Span | undefined = s.parentId ? byId.get(s.parentId) : undefined;
    while (cur) {
      if (cur.status !== "ok") return false; // has a failing ancestor -> propagation
      cur = cur.parentId ? byId.get(cur.parentId) : undefined;
    }
    return true;
  });

  // Earliest-starting root failure is the primary hypothesis.
  const root = rootFailures.sort((a, b) => a.startTs - b.startTs)[0] ?? failing[0]!;
  const failureType = root.status as FailureType;
  const downstream = failing.filter((s) => s.spanId !== root.spanId).length;

  return {
    implicatedSpanId: root.spanId,
    failureType,
    rootCause: rootCauseFor(failureType, root),
    evidence: [
      `span "${root.name}" status=${root.status}`,
      `${downstream} downstream failure(s) consistent with propagation`,
      root.agent ? `agent=${root.agent}` : "agent=unknown",
    ],
    // More downstream propagation from a single root => higher triage confidence.
    triageConfidence: Math.min(0.9, 0.5 + downstream * 0.1),
  };
}

function rootCauseFor(type: FailureType, span: Span): string {
  switch (type) {
    case "llm-error":
      return `LLM step "${span.name}" produced an error/invalid output`;
    case "tool-error":
      return `tool call in "${span.name}" failed`;
    case "timeout-error":
      return `step "${span.name}" exceeded its deadline`;
  }
}

export interface ConfirmationResult {
  readonly confirmed: boolean;
  readonly recovered: boolean;
  readonly note: string;
}

/**
 * Confirm a diagnosis by rerunning the implicated step with a targeted edit. The
 * caller supplies `rerun`, which applies the fix and returns whether the task now
 * succeeds. Only a recovering rerun CONFIRMS the hypothesis.
 */
export async function confirmByRerun(
  diagnosis: Diagnosis,
  rerun: (implicatedSpanId: string) => Promise<boolean>,
): Promise<ConfirmationResult> {
  const recovered = await rerun(diagnosis.implicatedSpanId);
  return {
    confirmed: recovered,
    recovered,
    note: recovered
      ? `hypothesis confirmed: targeted fix at ${diagnosis.implicatedSpanId} recovered the task`
      : `hypothesis NOT confirmed: fix at ${diagnosis.implicatedSpanId} did not recover — attribution remains unproven`,
  };
}
