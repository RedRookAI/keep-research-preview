/**
 * Review intake + the closed loop (Increment W3). This is the WIRE that turns Keep's separately-built pieces —
 * trigger ingress (W0), the solve pipeline, the decision packet (S1), notifications (W2), the review flow — into
 * one end-to-end flow: a real ticket arrives → is solved → a human-gated review is recorded → only the dangerous
 * few notify → the human decides → the outcome feeds calibration (F2).
 *
 * SOTA basis (2026-08-06): human-in-the-loop review "sits between AI recommendation and AI execution" — the loop
 * NEVER merges; it produces a review and waits (ampcuscyber, agno, galileo). And a STABLE CORRELATION ID must be
 * threaded end-to-end so "trigger received" ties to "approval granted" as one traceable episode on the audit
 * spine (auth0, prefactor; the decision-episode-GUID pattern). The correlation id here is the trigger episode =
 * the Issue id (`source:ticketId`), recorded on review.pending so trigger → review → decision are one chain.
 *
 * Zero deps. What would change it: a distributed deployment would carry the correlation id as a W3C traceparent
 * across process boundaries; the id + the human gate stay the same.
 */

import type { Spine } from "../spine/spine.js";
import type { NotificationRouter } from "../notify/notification_router.js";
import type { PrManifest } from "../git/pull_request.js";
import type { Issue, SolveExecutionContext } from "../solve/issue_model.js";
import type { SolveToPrResult } from "../pipeline/keep_pipeline.js";
import type { TriggerHandler } from "../ingress/trigger_ingress.js";

/** The solve seam: an Issue → a human-gated PR result. Wired to KeepPipeline.solveIssueToPR at deploy time. */
export type SolveFn = (issue: Issue, context?: SolveExecutionContext) => Promise<SolveToPrResult>;

export interface ReviewIntakeDeps {
  readonly spine: Spine;
  readonly notifications: NotificationRouter;
}

export interface ReviewIntakeExtras {
  readonly brief?: unknown;
  readonly forecast?: unknown;
  /** The trigger episode id (Issue id) — threads trigger → review → decision for end-to-end traceability. */
  readonly correlationId?: string;
}

/** Shared intake: stage review.pending (+ correlation id) and route the W2 notification (only the dangerous few
 *  interrupt). Used by BOTH the CLI solve command and the closed loop, so the two paths behave identically. */
export function recordReviewPending(deps: ReviewIntakeDeps, manifest: PrManifest, now: number, extras: ReviewIntakeExtras = {}): void {
  deps.spine.stage({
    type: "identity.action",
    actor: "review-intake",
    payload: {
      event: "review.pending",
      reviewId: manifest.id,
      manifest,
      ...(extras.brief ? { brief: extras.brief } : {}),
      ...(extras.forecast ? { forecast: extras.forecast } : {}),
      ...(extras.correlationId ? { correlationId: extras.correlationId } : {}),
      ts: now,
    },
  });
  // W2: only the dangerous few interrupt; routine auto-approved work is suppressed or batched.
  deps.notifications.notify(manifest);
}

/**
 * Close the loop (W3): return a TriggerHandler that runs the solve for an ingressed Issue and records a
 * human-gated review. The human decision remains the gate — this NEVER merges. If the solve produces no manifest
 * (it gave up), the durable trigger.accepted record stands and no review is created. A thrown solve propagates to
 * the ingress's bounded-retry / dead-letter path (so a permanently failing solve is parked for a human, not
 * retried forever).
 */
export function makeClosedLoopHandler(deps: ReviewIntakeDeps, solve: SolveFn, now: () => number = Date.now): TriggerHandler {
  return async (issue: Issue) => {
    const result = await solve(issue);
    if (result.manifest) {
      recordReviewPending(deps, result.manifest, now(), {
        ...(result.safety?.decisionBrief ? { brief: result.safety.decisionBrief } : {}),
        ...(result.safety?.patchForecast ? { forecast: result.safety.patchForecast } : {}),
        correlationId: issue.id,
      });
    }
  };
}
