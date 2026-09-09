/**
 * PUBLISH VETO QUEUE — the low-friction async veto window (the tail of the autonomy-posture guard).
 *
 * When the guard VETOES an external/irreversible action, "pause for the human" is correct but blunt: it stops the
 * whole run and waits. The veto queue makes that graceful — the action is PARKED with a veto WINDOW. During the
 * window the human can kill it with one signal (low-friction); parked items batch into a single triage digest
 * instead of N interruptions. The cardinal rule: the window is a VETO window, NOT an auto-approve timer. Elapsing
 * the window NEVER runs the action — it stays parked until the human EXPLICITLY approves. Autonomous-by-default
 * stops exactly at the outside world; nothing external ever runs itself.
 *
 * Four hard properties (each disproof-backed):
 *   - NEVER-AUTO-EXECUTE: only `approve` runs an action; `enqueue` parks (doesn't run) and window-elapse never runs.
 *   - REVERSIBLE-WHILE-PARKED: a parked item can be vetoed any time before approval; a vetoed item can't be approved.
 *   - AUDITABLE: enqueue / veto / approve all stage a spine event.
 *   - LOW-FRICTION: parked items batch into ONE digest (triage-ordered), not one interruption per item.
 *
 * BUILT + proven in-env: the park → veto/approve state machine + the batched digest. SEAM: the live wiring (the
 * autonomy loop enqueues here on a `veto` verdict instead of only returning paused-human; a channel surface renders
 * the digest and takes the one-tap veto) is the next increment. COMPOSE NOTE: `review/batch_digest.ts` is
 * PR-review-coupled (it needs MergeReadiness + EffortSignals per item), so feeding veto items through it would
 * fabricate readiness — this reuses the digest PATTERN (N → one ordered summary) in a purpose-fit shape instead.
 */

import type { Spine } from "../spine/spine.js";
import type { ExternalClass } from "./action_authorizer.js";

export type ParkStatus = "parked" | "vetoed" | "approved";

export interface ParkedActionInput {
  readonly id: string;
  readonly description: string;
  readonly externalClass: ExternalClass;
  readonly tenant?: string;
}

export interface ParkedAction {
  readonly id: string;
  readonly description: string;
  readonly externalClass: ExternalClass;
  readonly enqueuedAtMs: number;
  readonly vetoWindowMs: number;
  readonly tenant?: string;
  status: ParkStatus;
}

export interface VetoDigestEntry {
  readonly id: string;
  readonly description: string;
  readonly externalClass: ExternalClass;
  readonly windowOpen: boolean;
  readonly line: string;
}

export interface VetoDigest {
  readonly entries: readonly VetoDigestEntry[];
  readonly total: number;
  readonly windowsOpen: number;
  readonly summary: string;
}

export interface VetoQueueDeps {
  readonly spine: Spine;
  /** The executor — called ONLY on explicit approve. Never on enqueue, never on window-elapse. */
  readonly run: (action: ParkedAction) => void;
  /** Default veto window (ms). n=1 personal default; an org may pass a policy window per enqueue. */
  readonly defaultWindowMs?: number;
}

const DEFAULT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes — the low-friction one-tap-veto window

export class VetoQueue {
  private readonly items = new Map<string, ParkedAction>();

  constructor(private readonly deps: VetoQueueDeps) {}

  /** Park a vetoed action with a veto window. Does NOT run it. Auditable. */
  enqueue(input: ParkedActionInput, nowMs: number, windowMs?: number): ParkedAction {
    const item: ParkedAction = {
      id: input.id,
      description: input.description,
      externalClass: input.externalClass,
      enqueuedAtMs: nowMs,
      vetoWindowMs: windowMs ?? this.deps.defaultWindowMs ?? DEFAULT_WINDOW_MS,
      ...(input.tenant === undefined ? {} : { tenant: input.tenant }),
      status: "parked",
    };
    this.items.set(item.id, item);
    this.deps.spine.stage({ type: "identity.action", actor: "veto-queue", payload: { event: "parked", id: item.id, externalClass: item.externalClass, ...(item.tenant === undefined ? {} : { tenant: item.tenant }) } });
    return item;
  }

  /** Veto a parked item — removes it from consideration. Reversible-while-parked: allowed any time before approval. */
  veto(id: string, _nowMs: number, tenant?: string): boolean {
    const item = this.items.get(id);
    if (item === undefined || item.status !== "parked" || (tenant !== undefined && item.tenant !== tenant)) return false;
    item.status = "vetoed";
    this.deps.spine.stage({ type: "identity.action", actor: "veto-queue", payload: { event: "vetoed", id, ...(item.tenant === undefined ? {} : { tenant: item.tenant }) } });
    return true;
  }

  /** EXPLICIT human approval — the ONLY path that runs the action. A vetoed item can never be approved. */
  approve(id: string, tenant?: string): ParkedAction | null {
    const item = this.items.get(id);
    if (item === undefined || item.status !== "parked" || (tenant !== undefined && item.tenant !== tenant)) return null;
    item.status = "approved";
    this.deps.spine.stage({ type: "identity.action", actor: "veto-queue", payload: { event: "approved", id, ...(item.tenant === undefined ? {} : { tenant: item.tenant }) } });
    this.deps.run(item);
    return item;
  }

  /** Whether the low-friction veto window is still open (informational — NOT a run trigger). */
  windowOpen(id: string, nowMs: number): boolean {
    const item = this.items.get(id);
    if (item === undefined) return false;
    return nowMs < item.enqueuedAtMs + item.vetoWindowMs;
  }

  /**
   * Whether an item may run. NEVER-AUTO line: true ONLY when explicitly approved. A window that has closed WITHOUT
   * an approval is still not runnable — the window is a veto window, not an auto-approve timer.
   */
  runnable(id: string): boolean {
    return this.items.get(id)?.status === "approved";
  }

  /** The still-parked items awaiting a human decision (elapsed-but-unapproved items are STILL here). */
  parked(tenant?: string): readonly ParkedAction[] {
    return [...this.items.values()].filter((i) => i.status === "parked" && (tenant === undefined || i.tenant === tenant));
  }

  /** Batch every parked item into ONE triage-ordered digest (window-still-open first — least time to veto). */
  digest(nowMs: number, tenant?: string): VetoDigest {
    const parked = this.parked(tenant);
    const entries: VetoDigestEntry[] = parked
      .map((i) => {
        const windowOpen = this.windowOpen(i.id, nowMs);
        return {
          id: i.id,
          description: i.description,
          externalClass: i.externalClass,
          windowOpen,
          line: `${windowOpen ? "⏳" : "•"} ${i.externalClass}: ${i.description}`,
        };
      })
      .sort((a, b) => (a.windowOpen === b.windowOpen ? 0 : a.windowOpen ? -1 : 1));
    const windowsOpen = entries.filter((e) => e.windowOpen).length;
    return {
      entries,
      total: entries.length,
      windowsOpen,
      summary: `${entries.length} action${entries.length === 1 ? "" : "s"} awaiting your OK (${windowsOpen} still in the veto window).`,
    };
  }
}
