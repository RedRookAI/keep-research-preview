/**
 * Multi-solve monitor (Increment S4) — a live view of every ticket in flight, folded from the spine's real
 * lifecycle trail (trigger.* → resolve.* → review.*). It is READ-ONLY observability: it shows what Keep is working
 * on, what's stuck, what's costing money, and what needs a human decision — it never acts.
 *
 * SOTA basis (2026-08-06): silent failure defines agent monitoring — a final status code doesn't capture the
 * reasoning path, so trace-level state matters ("dashboards show totals; traces show decisions", Augment Code).
 * Keep's spine IS the trace; this folds it per ticket. Stuck/loop detection surfaces work that has stalled
 * (Raindrop's "Agent Stuck" signal). Cost visibility catches a ticket silently burning 10× via repeated
 * escalations (AI Magicx). And — action-first (Keep's W2 principle) — tickets that NEED a human (awaiting review,
 * deferred, dead-lettered, stuck) are surfaced first; healthy in-flight work is summarized, not itemized, so the
 * operator isn't drowned. Zero deps, pure.
 *
 * What would change it: an OpenTelemetry export (Langfuse/Datadog) is a seam — the same folded state can be shipped
 * out; this is the built-in, dependency-free view.
 */

import type { StagedEvent } from "../spine/event.js";

export type TicketPhase =
  | "solving"
  | "awaiting-review"
  | "deferred-to-human"
  | "decided"
  | "completed"
  | "dead-lettered"
  | "rejected";

export interface TicketState {
  readonly issueId: string;
  readonly phase: TicketPhase;
  readonly stuck: boolean;
  readonly needsAttention: boolean;
  readonly ageMs: number;       // since the first event for this ticket
  readonly idleMs: number;      // since the last event for this ticket
  readonly escalations: number;
  readonly tiersUsed: readonly string[];
  readonly costUsd: number;
  readonly source?: string;
  readonly ticketId?: string;
}

export interface MonitorSnapshot {
  readonly tickets: readonly TicketState[];
  /** Tickets needing a human, surfaced first (awaiting-review, deferred, dead-lettered, or stuck). */
  readonly needsAttention: readonly TicketState[];
  readonly counts: Readonly<Record<TicketPhase, number>> & { readonly stuck: number };
  readonly inFlight: number;    // non-terminal tickets
  readonly totalCostUsd: number;
}

const TERMINAL: ReadonlySet<TicketPhase> = new Set<TicketPhase>(["decided", "completed", "dead-lettered", "rejected"]);
const NON_TERMINAL_ATTENTION: ReadonlySet<TicketPhase> = new Set<TicketPhase>(["awaiting-review", "deferred-to-human"]);

interface Acc {
  issueId: string;
  firstTs: number;
  lastTs: number;
  hasAccepted: boolean;
  hasCompleted: boolean;
  hasDeadLetter: boolean;
  hasRejected: boolean;
  hasReviewPending: boolean;
  hasReviewDecided: boolean;
  cascadeDoneDeferred: boolean;
  escalations: number;
  tiersUsed: string[];
  costUsd: number;
  source: string | undefined;
  ticketId: string | undefined;
}

function phaseOf(a: Acc): TicketPhase {
  if (a.hasDeadLetter) return "dead-lettered";
  if (a.hasRejected) return "rejected";
  if (a.hasReviewDecided) return "decided";
  if (a.hasReviewPending) return "awaiting-review";
  if (a.cascadeDoneDeferred) return "deferred-to-human";
  if (a.hasCompleted) return "completed";
  return "solving";
}

/** Fold the spine event trail into a per-ticket snapshot. `stalenessMs` marks a stalled non-terminal ticket stuck. */
export function computeMonitor(events: readonly StagedEvent[], now: number, opts: { stalenessMs?: number } = {}): MonitorSnapshot {
  const stalenessMs = opts.stalenessMs ?? 15 * 60_000; // 15 min default
  const accs = new Map<string, Acc>();
  const reviewToIssue = new Map<string, string>();

  // First pass: map reviewId → issueId (closed-loop correlation) from review.pending.
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    if (p["event"] === "review.pending") {
      const reviewId = String(p["reviewId"]);
      const issueId = p["correlationId"] !== undefined ? String(p["correlationId"]) : reviewId;
      reviewToIssue.set(reviewId, issueId);
    }
  }

  const keyFor = (p: Record<string, unknown>): string | undefined => {
    const ev = String(p["event"] ?? "");
    if (ev.startsWith("trigger.") || ev.startsWith("resolve.")) return p["issueId"] !== undefined ? String(p["issueId"]) : undefined;
    if (ev === "review.pending") return p["correlationId"] !== undefined ? String(p["correlationId"]) : String(p["reviewId"]);
    if (ev === "review.decided") return reviewToIssue.get(String(p["reviewId"])) ?? String(p["reviewId"]);
    return undefined;
  };

  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    const ev = String(p["event"] ?? "");
    const key = keyFor(p);
    if (!key) continue;
    const ts = Number(p["ts"] ?? 0);
    let a = accs.get(key);
    if (!a) { a = { issueId: key, firstTs: ts, lastTs: ts, hasAccepted: false, hasCompleted: false, hasDeadLetter: false, hasRejected: false, hasReviewPending: false, hasReviewDecided: false, cascadeDoneDeferred: false, escalations: 0, tiersUsed: [], costUsd: 0, source: undefined, ticketId: undefined }; accs.set(key, a); }
    a.firstTs = Math.min(a.firstTs, ts);
    a.lastTs = Math.max(a.lastTs, ts);

    switch (ev) {
      case "trigger.accepted": a.hasAccepted = true; a.source = p["source"] ? String(p["source"]) : a.source; a.ticketId = p["ticketId"] ? String(p["ticketId"]) : a.ticketId; break;
      case "trigger.completed": a.hasCompleted = true; break;
      case "trigger.dead-lettered": a.hasDeadLetter = true; break;
      case "trigger.rejected": a.hasRejected = true; break;
      case "review.pending": a.hasReviewPending = true; break;
      case "review.decided": a.hasReviewDecided = true; break;
      case "resolve.cascade.tier": a.tiersUsed.push(String(p["tier"])); a.costUsd += Number(p["estCostUsd"] ?? 0); break;
      case "resolve.cascade.escalate": a.escalations += 1; break;
      case "resolve.cascade.done": if (p["escalateToHuman"] === true) a.cascadeDoneDeferred = true; break;
      default: break;
    }
  }

  const tickets: TicketState[] = [];
  const counts = { solving: 0, "awaiting-review": 0, "deferred-to-human": 0, decided: 0, completed: 0, "dead-lettered": 0, rejected: 0, stuck: 0 } as Record<TicketPhase, number> & { stuck: number };

  for (const a of accs.values()) {
    const phase = phaseOf(a);
    const idleMs = Math.max(0, now - a.lastTs);
    const stuck = !TERMINAL.has(phase) && idleMs > stalenessMs;
    const needsAttention = NON_TERMINAL_ATTENTION.has(phase) || phase === "dead-lettered" || stuck;
    counts[phase] += 1;
    if (stuck) counts.stuck += 1;
    tickets.push({
      issueId: a.issueId, phase, stuck, needsAttention,
      ageMs: Math.max(0, now - a.firstTs), idleMs,
      escalations: a.escalations, tiersUsed: a.tiersUsed, costUsd: Math.round(a.costUsd * 100) / 100,
      ...(a.source ? { source: a.source } : {}), ...(a.ticketId ? { ticketId: a.ticketId } : {}),
    });
  }

  // Order: needs-attention first, then by longest idle (most stale first).
  tickets.sort((x, y) => (Number(y.needsAttention) - Number(x.needsAttention)) || (y.idleMs - x.idleMs));
  const needsAttention = tickets.filter((t) => t.needsAttention);
  const inFlight = tickets.filter((t) => !TERMINAL.has(t.phase)).length;
  const totalCostUsd = Math.round(tickets.reduce((s, t) => s + t.costUsd, 0) * 100) / 100;

  return { tickets, needsAttention, counts, inFlight, totalCostUsd };
}

/** Render the monitor as text (CLI). Action-first: what needs a human, then a healthy-work summary. */
export function renderMonitor(snap: MonitorSnapshot, now: number): string {
  const L: string[] = [];
  L.push("Keep — work in flight");
  L.push("");
  if (snap.tickets.length === 0) { L.push("Nothing in flight."); return L.join("\n"); }

  const mins = (ms: number) => `${Math.round(ms / 60000)}m`;
  const label: Record<TicketPhase, string> = { "solving": "solving", "awaiting-review": "NEEDS DECISION", "deferred-to-human": "deferred to you", "decided": "decided", "completed": "done", "dead-lettered": "DEAD-LETTERED", "rejected": "rejected" };

  if (snap.needsAttention.length > 0) {
    L.push(`Needs your attention (${snap.needsAttention.length}):`);
    for (const t of snap.needsAttention) {
      const flags = [t.stuck ? `stuck ${mins(t.idleMs)}` : "", t.escalations > 0 ? `${t.escalations} escalation(s)` : "", t.costUsd > 0 ? `$${t.costUsd.toFixed(2)}` : ""].filter(Boolean).join(", ");
      L.push(`  • ${t.issueId} — ${label[t.phase]}${flags ? ` (${flags})` : ""}`);
    }
    L.push("");
  }
  L.push(`In flight: ${snap.inFlight}   (solving ${snap.counts.solving}, awaiting review ${snap.counts["awaiting-review"]}, deferred ${snap.counts["deferred-to-human"]}, stuck ${snap.counts.stuck})`);
  L.push(`Done: ${snap.counts.completed + snap.counts.decided}   Dead-lettered: ${snap.counts["dead-lettered"]}   Rejected: ${snap.counts.rejected}`);
  if (snap.totalCostUsd > 0) L.push(`Grounded spend in view: $${snap.totalCostUsd.toFixed(2)}`);
  return L.join("\n");
}
