/**
 * TriggerIngress (Increment W0) — turns a hostile external tracker event into a deduped, normalized Keep Issue
 * handed to the solve seam, under the standing invariants. The FOUR independent controls the 2026 SOTA requires
 * are all present and ordered correctly:
 *   1. authenticity/integrity  → WebhookVerifier (HMAC over raw bytes, constant-time)   [verify FIRST]
 *   2. freshness               → timestamp max-age window (in the verifier)
 *   3. idempotency             → spine-backed dedup on the delivery id (this module)     [before any effect]
 *   4. schema validation       → TriggerRouter.normalize returns undefined on unrecognized payloads
 * "Never treat 2xx as success before authenticity is proven." Every path is fail-closed and audited.
 *
 * Invariants honored: I1 deterministic-primary (pure verification + dedup, no model in the trust path);
 * I5 N=1 safe-by-default (the handler produces a human-gated review — never an auto-merge); I6 merge gate
 * permanent (ingress never merges); I7 no islands (this WIRES the tracker adapters + normalizer, previously
 * standalone); I8 honesty (the HTTP listener is a thin seam; verify+dedup+route is BUILT + proven here).
 *
 * The polling fallback shares this module's dedup+dispatch path, so a webhook redelivery and a poll of the same
 * ticket are idempotent through the SAME mechanism. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import { createHash } from "node:crypto";
import type { GovernanceLedger } from "../governance/decision_record.js";
import type { NormalizedTrigger, TrackerSource, TriggerRouter } from "../ecosystem/integrations.js";
import type { Issue } from "../solve/issue_model.js";
import { WebhookVerifier } from "./webhook_verifier.js";

/** The solve seam: what to do with a freshly-normalized Issue. Wired to KeepPipeline.solveIssueToPR at deploy
 *  time (produces a human-gated review). Default: the durable `trigger.accepted` spine record IS the artifact. */
export type TriggerHandler = (issue: Issue, trigger: NormalizedTrigger) => Promise<void>;

export interface WebhookInput {
  readonly source: TrackerSource;
  readonly rawBody: string;
  readonly headers: Readonly<Record<string, string>>;
}

export type IngressResult =
  | { readonly status: "accepted"; readonly issueId: string; readonly deliveryId: string }
  | { readonly status: "duplicate"; readonly deliveryId: string }
  | { readonly status: "rejected"; readonly reason: string }
  /** The handler failed transiently AFTER a valid, deduped event — NOT marked processed, so a redelivery
   *  RETRIES it (the ticket is never silently dropped). The HTTP layer maps this to 503 so the sender retries. */
  | { readonly status: "error"; readonly reason: string }
  /** Retries exhausted: parked for a human (terminal — the sender should stop retrying). */
  | { readonly status: "dead-letter"; readonly reason: string };

export interface TriggerIngressConfig {
  readonly verifier: WebhookVerifier;
  readonly router: TriggerRouter;
  readonly spine: Spine;
  /** Signing secret per source (operator-supplied; never hardcoded). Missing secret → fail-closed reject. */
  readonly secretFor: (source: TrackerSource) => string | undefined;
  readonly handler?: TriggerHandler;
  readonly governance?: GovernanceLedger;
  /** How to derive the Issue.repoRef from a trigger (default: the tracker source). */
  readonly repoRefFor?: (trigger: NormalizedTrigger) => string;
  readonly now?: () => number;
  readonly maxAgeSec?: number;
  /** Bound handler retries: after this many consecutive failures a ticket is dead-lettered (default 3). */
  readonly maxHandlerRetries?: number;
  /** Called when a ticket is dead-lettered (retries exhausted) — wired to the notification router (W2). */
  readonly onDeadLetter?: (ticketId: string, reason: string) => void;
}

export class TriggerIngress {
  private readonly cfg: TriggerIngressConfig;
  private handler: TriggerHandler | undefined;
  /** Durable dedup: a key in a TERMINAL state (succeeded or dead-lettered) is a duplicate and never re-runs.
   *  Seeded from the spine so it survives restarts. */
  private readonly terminal = new Map<string, "accepted" | "dead-lettered">();
  /** Consecutive handler-failure count per key — BOUNDS retries (dead-letter after the cap) so a permanently
   *  failing ticket can't cause a retry storm (unbounded handler runs + unbounded trigger.failed spine growth). */
  private readonly failCount = new Map<string, number>();
  /** Process-local in-flight guard so a concurrent redelivery dedups while the first is still running. */
  private readonly inFlight = new Set<string>();
  private readonly maxHandlerRetries: number;

  constructor(cfg: TriggerIngressConfig) {
    this.cfg = cfg;
    this.maxHandlerRetries = cfg.maxHandlerRetries ?? 3;
    this.handler = cfg.handler;
    for (const e of cfg.spine.currentEvents()) {
      const p = e.payload as Record<string, unknown>;
      const key = p["dedupKey"];
      if (typeof key !== "string") continue;
      const ev = p["event"];
      if (ev === "trigger.completed") { this.terminal.set(key, "accepted"); this.failCount.delete(key); }
      else if (ev === "trigger.dead-lettered") this.terminal.set(key, "dead-lettered");
      else if (ev === "trigger.failed") this.failCount.set(key, (this.failCount.get(key) ?? 0) + 1);
      // trigger.accepted is only a CLAIM (not terminal): a claim with no later completed/failed means the run was
      // interrupted mid-handler → left retryable on purpose (interrupted work is not lost).
    }
  }

  /** Wire (or replace) the solve handler after construction — used to close the loop once a provider+repo solve
   *  is available (W3). Absent handler → the durable trigger.accepted record is the artifact. */
  setHandler(handler: TriggerHandler): void {
    this.handler = handler;
  }

  /** Receive a signed webhook. Verify → dedup → normalize → Issue → handler. Fail-closed + audited. */
  async receive(input: WebhookInput): Promise<IngressResult> {
    const secret = this.cfg.secretFor(input.source) ?? "";
    const now = (this.cfg.now ?? Date.now)();
    const verdict = this.cfg.verifier.verify({ source: input.source, rawBody: input.rawBody, headers: input.headers, secret, now, ...(this.cfg.maxAgeSec !== undefined ? { maxAgeSec: this.cfg.maxAgeSec } : {}) });
    if (!verdict.ok) return this.reject(input.source, verdict.reason);

    // Schema validation: parse the (now-authenticated) body and normalize; unrecognized → reject.
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(input.rawBody) as Record<string, unknown>;
    } catch {
      return this.reject(input.source, "unparseable JSON body");
    }
    const trigger = this.cfg.router.route(input.source, payload);
    if (!trigger) return this.reject(input.source, "unrecognized or unsupported payload (no normalizer matched)");

    // Idempotency is on the LOGICAL event content (below, in dispatch) so a webhook redelivery AND a poll of the
    // same ticket state dedup through ONE mechanism, across transports. The delivery id is kept for audit.
    return this.dispatch(trigger, verdict.deliveryId);
  }

  /**
   * Polling path: an item pulled from a tracker API (authenticated by the API token used to fetch it, so no
   * signature). Deduped through the SAME spine mechanism on a stable per-ticket key.
   */
  async ingestPolled(trigger: NormalizedTrigger): Promise<IngressResult> {
    return this.dispatch(trigger, `${trigger.source}:poll:${trigger.ticketId}:${trigger.kind}`);
  }

  /** The transport-agnostic logical-event key: same underlying ticket state → same key (dedup across webhook +
   *  polling); a genuine change to the ticket → different content → new key → processed. */
  private dedupKey(trigger: NormalizedTrigger): string {
    const content = `${trigger.kind}\u0000${trigger.title}\u0000${trigger.body}\u0000${[...trigger.labels].sort().join(",")}`;
    return `${trigger.source}:${trigger.ticketId}:${createHash("sha256").update(content, "utf8").digest("hex").slice(0, 24)}`;
  }

  /** Ingest a raw NATIVE tracker payload (no signature) — for polling + the `keep ingest` file/air-gapped path.
   *  Authenticated by the operator's local access, not an inbound secret. Deduped through the same mechanism. */
  async ingestNative(source: TrackerSource, native: Readonly<Record<string, unknown>>): Promise<IngressResult> {
    const trigger = this.cfg.router.route(source, native);
    if (!trigger) return this.reject(source, "unrecognized or unsupported payload (no normalizer matched)");
    return this.dispatch(trigger, `${trigger.source}:local:${trigger.ticketId}:${trigger.kind}`);
  }

  private async dispatch(trigger: NormalizedTrigger, deliveryId: string): Promise<IngressResult> {
    const dedupKey = this.dedupKey(trigger);
    // Idempotency BEFORE any effect. Terminal (succeeded OR dead-lettered) → duplicate. A concurrent redelivery
    // still in flight → duplicate. A previously-FAILED-but-not-exhausted key falls through and RETRIES.
    if (this.terminal.has(dedupKey)) return { status: "duplicate", deliveryId };
    if (this.inFlight.has(dedupKey)) return { status: "duplicate", deliveryId };
    this.inFlight.add(dedupKey);
    const issue = this.toIssue(trigger);
    this.cfg.spine.stage({
      type: "identity.action",
      actor: "trigger-ingress",
      payload: { event: "trigger.accepted", deliveryId, dedupKey, issueId: issue.id, source: trigger.source, kind: trigger.kind, ticketId: trigger.ticketId, ts: (this.cfg.now ?? Date.now)() },
    });
    this.cfg.governance?.record({
      action: "ingress.accept",
      actor: "trigger-ingress",
      policy: { effect: "allow", ruleId: "trigger-ingress", reason: `verified ${trigger.source} ${trigger.kind} ${trigger.ticketId} → issue ${issue.id}`, matchedRuleIds: ["trigger-ingress"], policyVersion: "1" },
      outcome: "proceeded",
    });
    if (!this.handler) {
      this.terminal.set(dedupKey, "accepted");
      this.inFlight.delete(dedupKey);
      return { status: "accepted", issueId: issue.id, deliveryId };
    }
    try {
      await this.handler(issue, trigger);
      this.terminal.set(dedupKey, "accepted");
      this.failCount.delete(dedupKey);
      this.inFlight.delete(dedupKey);
      this.cfg.spine.stage({ type: "identity.action", actor: "trigger-ingress", payload: { event: "trigger.completed", deliveryId, dedupKey, issueId: issue.id, ts: (this.cfg.now ?? Date.now)() } });
      return { status: "accepted", issueId: issue.id, deliveryId };
    } catch (e) {
      this.inFlight.delete(dedupKey);
      const attempts = (this.failCount.get(dedupKey) ?? 0) + 1;
      this.failCount.set(dedupKey, attempts);
      if (attempts >= this.maxHandlerRetries) {
        // BOUNDED retry reached → DEAD-LETTER (terminal): stop re-running the handler + growing the spine, and
        // surface it for a human. Prevents the retry-storm / cost runaway a permanent failure would otherwise cause.
        this.terminal.set(dedupKey, "dead-lettered");
        this.cfg.spine.stage({ type: "identity.action", actor: "trigger-ingress", payload: { event: "trigger.dead-lettered", deliveryId, dedupKey, issueId: issue.id, attempts, reason: (e as Error).message, ts: (this.cfg.now ?? Date.now)() } });
        this.cfg.governance?.record({ action: "ingress.dead-letter", actor: "trigger-ingress", policy: { effect: "deny", ruleId: "trigger-ingress", reason: `handler failed ${attempts}× for ${issue.id} — dead-lettered for human attention (retries stopped)`, matchedRuleIds: ["trigger-ingress"], policyVersion: "1" }, outcome: "escalated-to-human" });
        this.cfg.onDeadLetter?.(trigger.ticketId, (e as Error).message);
        return { status: "dead-letter", reason: `handler failed ${attempts} times; parked for human attention (retries stopped)` };
      }
      this.cfg.spine.stage({ type: "identity.action", actor: "trigger-ingress", payload: { event: "trigger.failed", deliveryId, dedupKey, issueId: issue.id, attempts, reason: (e as Error).message, ts: (this.cfg.now ?? Date.now)() } });
      this.cfg.governance?.record({ action: "ingress.handler-failed", actor: "trigger-ingress", policy: { effect: "warn", ruleId: "trigger-ingress", reason: `handler failed for ${issue.id} (attempt ${attempts}/${this.maxHandlerRetries}); will retry on redelivery`, matchedRuleIds: ["trigger-ingress"], policyVersion: "1" }, outcome: "escalated-to-human" });
      return { status: "error", reason: `handler failed (attempt ${attempts}/${this.maxHandlerRetries}); will retry on redelivery` };
    }
  }

  private reject(source: TrackerSource, reason: string): IngressResult {
    this.cfg.spine.stage({ type: "identity.action", actor: "trigger-ingress", payload: { event: "trigger.rejected", source, reason, ts: (this.cfg.now ?? Date.now)() } });
    this.cfg.governance?.record({
      action: "ingress.reject",
      actor: "trigger-ingress",
      policy: { effect: "deny", ruleId: "trigger-ingress", reason: `rejected ${source}: ${reason}`, matchedRuleIds: ["trigger-ingress"], policyVersion: "1" },
      outcome: "blocked",
    });
    return { status: "rejected", reason };
  }


  private toIssue(trigger: NormalizedTrigger): Issue {
    const repoRef = this.cfg.repoRefFor ? this.cfg.repoRefFor(trigger) : trigger.source;
    const body = trigger.body.trim();
    return { id: `${trigger.source}:${trigger.ticketId}`, text: body ? `${trigger.title}\n\n${body}` : trigger.title, repoRef };
  }
}
