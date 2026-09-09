/**
 * Observability suite composition — the operator's window into autonomous runs.
 *
 *  - TraceRecorder: hierarchical span recording (wired into the autonomy loop's stages; each stage → a span with status).
 *  - failure localization: triage the ROOT failing span (earliest failing span with no failing ancestor), then confirm
 *    the hypothesis by RERUN — because attribution inferred from logs is an untested hypothesis until a targeted fix
 *    actually recovers the task (DoVer/AgentDebugX, 2026).
 *  - cost attribution: roll spend up per task / agent / node / LESSON (the per-lesson grain is enabled by memory
 *    provenance + spine cost — the novel grain).
 *
 * SOTA basis (2026-08-07): log-inferred failure attribution is a HYPOTHESIS, not a conclusion; only execution
 * (confirm-by-rerun) validates it. What would change it: finer instrumentation of the model-gateway + tool layer would
 * give failure localization a real propagation TREE (nested llm/tool/timeout spans) and populate the per-call cost
 * attribution — today the autonomy loop contributes per-stage spans with zero model-cost; that call-level instrumentation
 * is the follow-on that unlocks the propagation analysis and the per-lesson cost grain end-to-end.
 */

import { TraceRecorder, attributeCost, type Span, type Attribution } from "./tracing.js";
import { triageFailure, confirmByRerun, type Diagnosis, type ConfirmationResult } from "./failure_localization.js";
import type { Spine } from "../spine/spine.js";

export interface ObservabilitySuite {
  readonly recorder: TraceRecorder;
  /** Triage the root failing span across ALL recorded spans (or a specific run's trace). */
  diagnose(traceId?: string): Diagnosis | undefined;
  /** Confirm a diagnosis by rerunning the implicated step with a targeted fix (only recovery confirms). */
  confirm(diagnosis: Diagnosis, rerun: (implicatedSpanId: string) => Promise<boolean>): Promise<ConfirmationResult>;
  /** Attribute spend across task / agent / node / lesson (optionally scoped to one trace). */
  attribute(traceId?: string): Attribution;
}

export function buildObservabilitySuite(spine: Spine, recorder: TraceRecorder = new TraceRecorder(spine)): ObservabilitySuite {
  const spansFor = (traceId?: string): Span[] => (traceId ? recorder.trace(traceId) : recorder.all());
  return {
    recorder,
    diagnose: (traceId) => triageFailure(spansFor(traceId)),
    confirm: (diagnosis, rerun) => confirmByRerun(diagnosis, rerun),
    attribute: (traceId) => attributeCost(spansFor(traceId)),
  };
}
