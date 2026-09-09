/**
 * Scheduler + Envelope: the Scheduler (Increment 7c) — operator-toggled scheduled autonomy.
 *
 * SOTA basis (2026-08-04): machine-directed loops don't block on per-action approval — they accrue
 * proposals and run at a scheduled cadence the operator toggles, under a one-time authorization
 * envelope (over-asking is itself a safety failure — the autonomy-calibration research). Enforcement
 * (not alerts): when the metered gateway hard-stops on a cap, the whole run stops — no further calls
 * until the operator/policy resumes (Waxell). Unrecoverable tasks go to a DEAD-LETTER QUEUE for human
 * review rather than looping forever (the 4th orchestration table-stake).
 *
 * The human merge/approval gate stays the owner's: the scheduler runs the LOOPS (research/rag/learn)
 * and accrues PROPOSALS; it never auto-merges. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { BudgetLedger, AuthorizationEnvelope, LoopClass } from "./authorization_envelope.js";
import { BudgetExceeded } from "./metered_gateway.js";

/** A task the scheduler runs under an envelope (one unit of unattended work). */
export interface ScheduledTask {
  readonly id: string;
  readonly projectId: string;
  readonly cls: LoopClass;
  /** The work; receives the runId so its model calls can be metered. Returns a proposal summary. */
  readonly run: (runId: string) => Promise<string>;
  /** How many times this task has already failed (for the unrecoverable threshold). */
  readonly priorFailures?: number;
}

/** A cadence toggle for a project (the operator's ON/OFF switch). */
export interface CadenceToggle {
  readonly projectId: string;
  readonly enabledClasses: readonly LoopClass[];
  readonly envelopeId: string;
}

/** An entry that could not be completed and needs human attention. */
export interface DeadLetterEntry {
  readonly taskId: string;
  readonly projectId: string;
  readonly cls: LoopClass;
  readonly reason: string;
  readonly kind: "budget-halted" | "unrecoverable" | "unauthorized";
  readonly ts: number;
}

/** The dead-letter queue — unrecoverable tasks land here for human review, never silently dropped. */
export class DeadLetterQueue {
  private readonly entries: DeadLetterEntry[] = [];
  constructor(private readonly spine: Spine, private readonly clock: () => number = () => Date.now()) {}

  add(e: Omit<DeadLetterEntry, "ts">): DeadLetterEntry {
    const entry: DeadLetterEntry = { ...e, ts: this.clock() };
    this.entries.push(entry);
    this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "dead_letter", taskId: entry.taskId, kind: entry.kind, reason: entry.reason } });
    return entry;
  }

  list(): readonly DeadLetterEntry[] {
    return [...this.entries];
  }

  /** Operator clears an entry after handling it (audited). */
  resolve(taskId: string, resolution: string): void {
    const i = this.entries.findIndex((e) => e.taskId === taskId);
    if (i >= 0) {
      this.entries.splice(i, 1);
      this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "dead_letter_resolved", taskId, resolution } });
    }
  }
}

export interface RunReport {
  readonly runId: string;
  readonly ranTasks: readonly string[];
  readonly proposals: readonly { taskId: string; proposal: string }[];
  readonly deadLettered: readonly string[];
  readonly halted: boolean;
  readonly haltReason?: string;
}

export interface SchedulerDeps {
  readonly spine: Spine;
  readonly ledger: BudgetLedger;
  readonly dlq: DeadLetterQueue;
  /** Tasks failing this many times or more are unrecoverable → dead-letter (not retried). Default 3. */
  readonly unrecoverableThreshold?: number;
  readonly clock?: () => number;
}

export class Scheduler {
  private readonly toggles = new Map<string, CadenceToggle>();
  private readonly unrecoverableThreshold: number;
  private readonly clock: () => number;

  constructor(private readonly deps: SchedulerDeps) {
    this.unrecoverableThreshold = deps.unrecoverableThreshold ?? 3;
    this.clock = deps.clock ?? (() => Date.now());
  }

  /** Operator toggles a project's cadence ON (binds it to an envelope) — the F2 directive path. */
  enable(toggle: CadenceToggle): void {
    this.toggles.set(toggle.projectId, toggle);
    this.deps.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "cadence_enabled", projectId: toggle.projectId, classes: toggle.enabledClasses, envelopeId: toggle.envelopeId } });
  }

  /** Operator toggles it OFF. */
  disable(projectId: string): void {
    this.toggles.delete(projectId);
    this.deps.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "cadence_disabled", projectId } });
  }

  isEnabled(projectId: string): boolean {
    return this.toggles.has(projectId);
  }

  /**
   * Run one scheduled tick for a project: for each task whose class is enabled + authorized, run it
   * under a fresh run scoped to the envelope. A BudgetExceeded from the metered gateway HALTS the
   * whole tick (enforcement). Unrecoverable tasks (too many prior failures) are dead-lettered, not
   * retried. Returns the proposals accrued (for the human to review/merge — never auto-merged).
   */
  async tick(projectId: string, tasks: readonly ScheduledTask[]): Promise<RunReport> {
    const toggle = this.toggles.get(projectId);
    const runId = `run_${projectId}_${this.clock()}`;

    if (!toggle) {
      return { runId, ranTasks: [], proposals: [], deadLettered: [], halted: true, haltReason: "cadence disabled" };
    }
    const env = this.deps.ledger.getEnvelope(toggle.envelopeId);
    if (!env || this.clock() > env.expiresAt) {
      return { runId, ranTasks: [], proposals: [], deadLettered: [], halted: true, haltReason: "no valid envelope (absent/expired)" };
    }

    this.deps.ledger.beginRun(runId, env.id);
    this.deps.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "tick_begin", projectId, runId, envelopeId: env.id } });

    const ranTasks: string[] = [];
    const proposals: { taskId: string; proposal: string }[] = [];
    const deadLettered: string[] = [];

    for (const task of tasks) {
      // Class must be both enabled by the toggle and authorized by the envelope.
      if (!toggle.enabledClasses.includes(task.cls) || !env.allowedClasses.includes(task.cls)) {
        continue;
      }
      // Unrecoverable → dead-letter, do not retry.
      if ((task.priorFailures ?? 0) >= this.unrecoverableThreshold) {
        this.deps.dlq.add({ taskId: task.id, projectId, cls: task.cls, kind: "unrecoverable", reason: `${task.priorFailures} prior failures ≥ threshold ${this.unrecoverableThreshold}` });
        deadLettered.push(task.id);
        continue;
      }

      try {
        const proposal = await task.run(runId);
        ranTasks.push(task.id);
        proposals.push({ taskId: task.id, proposal });
      } catch (err) {
        if (err instanceof BudgetExceeded) {
          // Enforcement: a cap/velocity breach halts the WHOLE tick — no further calls this run.
          this.deps.dlq.add({ taskId: task.id, projectId, cls: task.cls, kind: "budget-halted", reason: err.message });
          deadLettered.push(task.id);
          this.deps.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "tick_halted", projectId, runId, reason: err.message } });
          return { runId, ranTasks, proposals, deadLettered, halted: true, haltReason: err.message };
        }
        // Other failure: record it; the task's failure count climbs toward the unrecoverable line.
        this.deps.dlq.add({ taskId: task.id, projectId, cls: task.cls, kind: "unrecoverable", reason: String(err) });
        deadLettered.push(task.id);
      }
    }

    const spend = this.deps.ledger.runSpend(runId);
    this.deps.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "tick_complete", projectId, runId, ran: ranTasks.length, spentUsd: spend?.spentUsd ?? 0, proposals: proposals.length } });
    return { runId, ranTasks, proposals, deadLettered, halted: false };
  }
}
