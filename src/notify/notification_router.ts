/**
 * NotificationRouter (Increment W2) — decides what actually reaches the human, so Keep surfaces only the
 * dangerous few and NEVER notifies per-PR for routine auto-approved work. This is the anti-rubber-stamping
 * principle made real at the notification boundary.
 *
 * SOTA basis (2026-08-06), unanimous (Courier, incident.io, oneuptime, LogicMonitor, Google SRE):
 *  - "Action-first, alert-second": the only question is "does this deserve the interruption?" If a human can
 *    take NO action (an already auto-approved PR), it must generate NO alert — "if an alert fires and the
 *    on-call can't take a specific action, it should not exist."
 *  - Categorize every item actionable / informational / noise; route by severity to different channels; batch
 *    the routine into a digest so nothing is lost without interrupting.
 *  - "Learn from behavior: if a user ignores a type, reduce its frequency" — here, a class with an active
 *    reduced-escalation policy (F2 calibration) is suppressed from interrupts.
 *  - A per-window ceiling on actionable interrupts (Google SRE ~2–3/shift) is a HEALTH signal: too many means
 *    the risk assessment is miscalibrated — surfaced, but a dangerous alert is NEVER dropped to hit the ceiling.
 *
 * Tiers: urgent (interrupt now) · notify (async, non-interrupting) · digest (batched routine) · suppress (none).
 * The channel is a PORT (email/Slack/webhook/pager are deployment seams); the routing LOGIC is BUILT + proven.
 * Every routing decision is audited. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { GovernanceLedger } from "../governance/decision_record.js";
import type { PrManifest } from "../git/pull_request.js";
import type { CalibrationWire } from "../oversight/calibration_wire.js";
import type { RiskBand } from "../oversight/pr_risk.js";

export type NotificationTier = "suppress" | "digest" | "notify" | "urgent";

export interface Notification {
  readonly tier: NotificationTier;
  readonly kind: "review" | "dead-letter" | "digest";
  readonly subjectId: string;
  readonly title: string;
  readonly body: string;
  readonly band?: RiskBand;
  readonly ts: number;
}

/** The delivery port. Real adapters (email/Slack/webhook/pager) are deployment seams; the default collects. */
export interface NotificationChannel {
  send(n: Notification): void | Promise<void>;
}

/** An in-memory channel (the N=1 default + the test double). Nothing is lost; the operator reads it via status. */
export class CollectingChannel implements NotificationChannel {
  readonly sent: Notification[] = [];
  send(n: Notification): void {
    this.sent.push(n);
  }
}

export interface NotificationDigestEntry {
  readonly subjectId: string;
  readonly title: string;
  readonly band: RiskBand;
  readonly disposition: string;
}

export interface NotificationDigest {
  readonly total: number;
  readonly entries: readonly NotificationDigestEntry[];
  readonly summary: string;
}

export interface NotificationRouterConfig {
  readonly channel?: NotificationChannel;
  readonly spine?: Spine;
  readonly governance?: GovernanceLedger;
  /** Consulted so a class with an active human-authorized reduced-escalation policy is suppressed from interrupts. */
  readonly calibration?: CalibrationWire;
  /** Fatigue ceiling: actionable interrupts per digest window before an overload HEALTH warning (default 3). */
  readonly maxUrgentPerWindow?: number;
  readonly now?: () => number;
}

export class NotificationRouter {
  private readonly channel: NotificationChannel;
  private readonly digestBuffer: NotificationDigestEntry[] = [];
  private urgentThisWindow = 0;
  private readonly maxUrgent: number;
  constructor(private readonly cfg: NotificationRouterConfig = {}) {
    this.channel = cfg.channel ?? new CollectingChannel();
    this.maxUrgent = cfg.maxUrgentPerWindow ?? 3;
  }

  /** Pure classification — the heart of "only the dangerous few interrupt." */
  tierFor(manifest: PrManifest): NotificationTier {
    const o = manifest.oversight;
    if (!o) return "notify"; // unknown oversight → safe default: notify (never silently drop)
    // Dangerous → interrupt. Blocked or "requires immediate attention" always interrupts.
    if (o.disposition === "blocked" || o.requiresImmediateAttention) return "urgent";
    // Needs a human decision but not immediate → async notify.
    if (o.disposition === "human-approval-required") return "notify";
    // Auto-approved routine: a proven-clean class (F2 policy) or a low-risk silent-auto → SUPPRESS (no per-PR
    // interrupt — the whole point). Auto-approved medium → digest (informational, batched).
    const cls = o.band;
    if (this.cfg.calibration?.activePolicyGates().has(cls)) return "suppress";
    if (o.mode === "silent-auto" || o.band === "low") return "suppress";
    return "digest";
  }

  /** Route a review manifest. Returns the tier actually applied. Audited. */
  notify(manifest: PrManifest): NotificationTier {
    const tier = this.tierFor(manifest);
    const o = manifest.oversight;
    const band = (o?.band ?? "medium") as RiskBand;
    const now = (this.cfg.now ?? Date.now)();
    const title = `Change ${manifest.id} (${band} risk, ${o?.disposition ?? "unknown"})`;
    if (tier === "urgent") {
      this.urgentThisWindow++;
      this.channel.send({ tier, kind: "review", subjectId: manifest.id, title, body: `Needs your attention now: ${o?.reasons?.join("; ") ?? "requires review"}`, band, ts: now });
      if (this.urgentThisWindow > this.maxUrgent) {
        // HEALTH signal only — the alert was still delivered; too many urgents ⇒ investigate risk calibration.
        this.audit("notification.overload", `urgent interrupts this window (${this.urgentThisWindow}) exceeded the ceiling (${this.maxUrgent}) — risk assessment may be miscalibrated`, "warned-and-proceeded");
      }
    } else if (tier === "notify") {
      this.channel.send({ tier, kind: "review", subjectId: manifest.id, title, body: "Waiting for your decision (not urgent). It won't proceed without you.", band, ts: now });
    } else if (tier === "digest") {
      this.digestBuffer.push({ subjectId: manifest.id, title, band, disposition: o?.disposition ?? "auto-approved" });
    }
    // suppress → nothing delivered (available via status/digest).
    this.audit("notification.route", `${manifest.id} → ${tier}`, tier === "urgent" ? "escalated-to-human" : "proceeded");
    return tier;
  }

  /** A dead-lettered ingress ticket (retries exhausted) always interrupts — it needs a human. */
  notifyDeadLetter(ticketId: string, reason: string): void {
    const now = (this.cfg.now ?? Date.now)();
    this.urgentThisWindow++;
    this.channel.send({ tier: "urgent", kind: "dead-letter", subjectId: ticketId, title: `Ticket ${ticketId} could not be processed`, body: `Parked after repeated failures: ${reason}`, ts: now });
    this.audit("notification.dead-letter", `${ticketId} dead-lettered → urgent`, "escalated-to-human");
  }

  /** Flush the batched routine as ONE digest (time/cadence-driven; nothing lost). Resets the fatigue window. */
  flushDigest(): NotificationDigest | null {
    this.urgentThisWindow = 0;
    if (this.digestBuffer.length === 0) return null;
    const entries = [...this.digestBuffer];
    this.digestBuffer.length = 0;
    const digest: NotificationDigest = { total: entries.length, entries, summary: `${entries.length} routine auto-approved change(s) — spot-check only, none require a decision.` };
    this.channel.send({ tier: "digest", kind: "digest", subjectId: "digest", title: `Keep digest: ${entries.length} routine change(s)`, body: digest.summary, ts: (this.cfg.now ?? Date.now)() });
    this.audit("notification.digest", `flushed ${entries.length} routine item(s) as one digest`, "proceeded");
    return digest;
  }

  pendingDigestCount(): number {
    return this.digestBuffer.length;
  }

  /**
   * True once the batch reaches `threshold` routine items — a count-based trigger to surface the digest ("ten to fifty is
   * a number a human can evaluate honestly", 2026 HITL SOTA), complementing the time/cadence flush. High-risk items are
   * never in this buffer (they escalate urgent), so a risky change can't hide inside a benign batch under bulk approval
   * (the ATR-2026-00118 "approval-fatigue exploitation" defense).
   */
  digestReady(threshold: number): boolean {
    return this.digestBuffer.length >= threshold;
  }

  private audit(action: string, reason: string, outcome: "proceeded" | "escalated-to-human" | "warned-and-proceeded"): void {
    this.cfg.spine?.stage({ type: "identity.action", actor: "notification-router", payload: { event: action, reason, ts: (this.cfg.now ?? Date.now)() } });
    this.cfg.governance?.record({ action, actor: "notification-router", policy: { effect: outcome === "proceeded" ? "allow" : "warn", ruleId: "notification-router", reason, matchedRuleIds: ["notification-router"], policyVersion: "1" }, outcome });
  }
}
