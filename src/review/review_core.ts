/**
 * Review core — the single source of truth for reading pending reviews off the spine and applying a human
 * decision. Both the CLI (`keep review`) and the web review UI (S2) go through THIS module, so the two surfaces
 * can never drift on what counts as pending or on how a decision is recorded + fed back to calibration.
 *
 * `applyReviewDecision` is the one decision path: it stages `review.decided` AND feeds the F2 calibration wire in
 * a single call, so no surface can record a decision while forgetting to close the learning loop. Pure over the
 * spine; zero deps.
 */

import type { KeepApp } from "../compose.js";
import type { PrManifest } from "../git/pull_request.js";
import type { DecisionBrief } from "../pipeline/decision_brief.js";
import type { ForecastVerdict } from "../pipeline/consequence_forecast.js";
import { assembleDecisionPacket, type AssembleInputs } from "../cli/decision_packet.js";
import type { Principal } from "../identity/rbac.js";
import type { StagedEvent } from "../spine/event.js";

export interface PendingEvent {
  event: string;
  reviewId: string;
  tenant?: string;
  manifest: PrManifest | undefined;
  brief: DecisionBrief | undefined;
  forecast: ForecastVerdict | undefined;
  decision: string | undefined;
  ts: number;
}

/** A change needs a human decision unless it was auto-approved (default fail-safe: treat unknown as needing one). */
export function needsDecision(m: PrManifest): boolean {
  return (m.oversight?.disposition ?? "human-approval-required") !== "auto-approved";
}

/** Select authority before joining review/correlation IDs. Omitted tenant selects
 * personal, unlabelled records; it never adopts an organization's identity. */
export function reviewScopeEvents(app: KeepApp, tenant?: string): readonly StagedEvent[] {
  return app.spine.currentEvents().filter(event => event.payload["tenant"] === tenant);
}

function pendingEvents(events: readonly StagedEvent[]): PendingEvent[] {
  const out: PendingEvent[] = [];
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    const ev = p["event"];
    if (ev === "review.pending" || ev === "review.decided") {
      out.push({ event: String(ev), reviewId: String(p["reviewId"]), manifest: p["manifest"] as PrManifest | undefined, brief: p["brief"] as DecisionBrief | undefined, forecast: p["forecast"] as ForecastVerdict | undefined, decision: p["decision"] as string | undefined, ts: Number(p["ts"] ?? 0), ...(p["tenant"] !== undefined ? { tenant: String(p["tenant"]) } : {}) });
    }
  }
  return out;
}

export function reviewEvents(app: KeepApp, tenant?: string): PendingEvent[] {
  return pendingEvents(reviewScopeEvents(app, tenant));
}

export function isDecided(app: KeepApp, id: string, tenant?: string): boolean {
  return reviewEvents(app, tenant).some((e) => e.event === "review.decided" && e.reviewId === id);
}

export function getManifest(app: KeepApp, id: string, events?: readonly PendingEvent[], tenant?: string): PrManifest | undefined {
  for (const e of events ?? reviewEvents(app, tenant)) if (e.tenant === tenant && e.event === "review.pending" && e.reviewId === id && e.manifest?.id === id) return e.manifest;
  return undefined;
}

export function getPacketInputs(app: KeepApp, id: string, tenant?: string): AssembleInputs | undefined {
  const events = reviewEvents(app, tenant), manifest = getManifest(app, id, events, tenant);
  if (!manifest) return undefined;
  for (const e of events) {
    if (e.event === "review.pending" && e.reviewId === id && e.manifest === manifest) {
      return { manifest, ...(e.brief ? { brief: e.brief } : {}), ...(e.forecast ? { forecast: e.forecast } : {}) };
    }
  }
  return undefined;
}

export function listPendingReviews(app: KeepApp, tenant?: string): PrManifest[] {
  const events = reviewEvents(app, tenant);
  const decided = new Set(events.filter((e) => e.event === "review.decided").map((e) => e.reviewId));
  const seen = new Set<string>();
  const out: PrManifest[] = [];
  for (const e of events) {
    if (e.event === "review.pending" && e.manifest?.id === e.reviewId && !decided.has(e.reviewId) && !seen.has(e.reviewId)) {
      seen.add(e.reviewId); out.push(e.manifest);
    }
  }
  return out;
}

export function auditTrail(app: KeepApp, id: string, tenantId?: string): string[] {
  const lines: string[] = [];
  // The existing local owner audit is complete. Explicit tenant views select
  // their scope before joining IDs and never include unlabelled records.
  for (const e of pendingEvents(tenantId === undefined ? app.spine.currentEvents() : reviewScopeEvents(app, tenantId))) {
    if (e.reviewId !== id) continue;
    const when = e.ts ? new Date(e.ts).toISOString().replace("T", " ").slice(0, 19) : "";
    if (e.event === "review.pending") lines.push(`${when}  Keep proposed a change and requested your review.`);
    else if (e.event === "review.decided") lines.push(`${when}  You ${e.decision} the change.`);
  }
  return lines;
}

export interface DecisionOutcome {
  readonly ok: boolean;
  readonly reason?: "not-found" | "already-decided" | "forbidden";
  readonly band?: "low" | "medium" | "high";
  readonly reversible?: boolean;
}

/**
 * The ONE decision path. Records `review.decided` on the spine AND feeds the calibration wire (F2) so Keep learns
 * from real human decisions — together, so no surface can do one without the other. Idempotent: a second decision
 * on the same id is refused. The human merge remains a separate manual action; this never merges.
 *
 * X0: if an `actor` is supplied, the decision is authorized first (deny → audited `authz.denied`, no state change).
 * With no actor the local N=1 owner acts only on unlabelled personal reviews. Organization reviews
 * require their original tenant through an authenticated human actor. The deciding principal is recorded on `review.decided` for accountability.
 */
export function applyReviewDecision(app: KeepApp, id: string, approved: boolean, ts: number, actor?: Principal): DecisionOutcome {
  const tenant = actor?.tenant;
  const inputs = getPacketInputs(app, id, tenant);
  if (!inputs) return { ok: false, reason: "not-found" };
  if (actor) {
    const action = approved ? "review.approve" : "review.decline";
    const decision = actor.kind === "human" ? app.authorization.authorize(actor, action) : { allow: false, reason: "review decisions require a human principal" };
    if (!decision.allow) {
      app.spine.stage({ type: "identity.action", actor: "rbac", payload: { event: "authz.denied", who: actor.id, role: actor.role, action, reviewId: id, reason: decision.reason, ts, ...(tenant === undefined ? {} : { tenant }) } });
      return { ok: false, reason: "forbidden" };
    }
  }
  if (isDecided(app, id, tenant)) return { ok: false, reason: "already-decided" };
  const packet = assembleDecisionPacket(inputs);
  const band = inputs.manifest.oversight?.band ?? "medium";
  app.spine.stage({ type: "identity.action", actor: "review", payload: { event: "review.decided", reviewId: id, decision: approved ? "approved" : "declined", by: actor?.id ?? "owner", ts, ...(tenant === undefined ? {} : { tenant }) } });
  app.calibrationWire.recordDecision(band, packet.reversible, approved);
  return { ok: true, band, reversible: packet.reversible };
}
