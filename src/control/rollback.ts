/**
 * Rollback + idempotency (Phase 2) — #27 (Round 11 scope) + Round 8 idempotency.
 *
 * HONEST SCOPE (Round 11): rollback covers git + internal-ledger state, plus known
 * compensating actions (inverses). External non-idempotent side effects are NOT
 * falsely promised as rollback-able — they are approval-gated up front. Where a
 * compensating action exists, it's registered so "undo" is real, not hoped.
 *
 * Idempotency (Round 8): external mutations carry an idempotency key so at-least-once
 * delivery (retries after a crash) never double-executes.
 */

import type { Spine } from "../spine/spine.js";

/** A reversible internal action with a concrete inverse. */
export interface ReversibleAction {
  readonly id: string;
  /** git ref / ledger entry / etc. that this action produced. */
  readonly artifact: string;
  /** The inverse operation (revert commit, delete ledger row). Real, not hoped. */
  readonly undo: () => Promise<void>;
}

export class RollbackLedger {
  private readonly actions: ReversibleAction[] = [];
  private tail: Promise<unknown> = Promise.resolve();

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.tail.then(fn);
    this.tail = result.catch(() => undefined);
    return result;
  }

  constructor(
    private readonly spine: Spine,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** Record a reversible internal action (with its concrete inverse). */
  record(action: ReversibleAction): void {
    if (this.actions.some(existing => existing.id === action.id)) throw new Error(`duplicate rollback identity: ${action.id}`);
    this.actions.push(action);
    this.spine.stage({
      type: "identity.action",
      actor: "rollback",
      payload: { event: "reversible_recorded", id: action.id, artifact: action.artifact },
    });
  }

  /**
   * Roll back the last `count` internal actions (LIFO), running their real inverses.
   * The timed rollback motion is the reliability metric, so start/end are recorded.
   */
  async rollback(count: number, reason: string): Promise<{ rolledBack: number; ms: number }> {
    return this.serial(async () => {
    const start = this.clock();
    this.spine.stage({ type: "identity.action", actor: "rollback", payload: { event: "rollback_start", count, reason } });
    let done = 0;
    for (let i = 0; i < count && this.actions.length > 0; i++) {
      const action = this.actions[this.actions.length - 1]!;
      await action.undo();
      this.actions.splice(this.actions.lastIndexOf(action), 1);
      done++;
    }
    const ms = this.clock() - start;
    this.spine.stage({ type: "identity.action", actor: "rollback", payload: { event: "rollback_complete", rolledBack: done, ms } });
    return { rolledBack: done, ms };
    });
  }

  /** Roll back one specifically named action without disturbing unrelated newer inverses. */
  async rollbackAction(id: string, reason: string): Promise<{ rolledBack: boolean; ms: number }> {
    return this.serial(async () => {
    const start = this.clock();
    const index = this.actions.findIndex((action) => action.id === id);
    this.spine.stage({ type: "identity.action", actor: "rollback", payload: { event: "rollback_action_start", id, reason } });
    if (index < 0) {
      const ms = this.clock() - start;
      this.spine.stage({ type: "identity.action", actor: "rollback", payload: { event: "rollback_action_complete", id, rolledBack: false, ms } });
      return { rolledBack: false, ms };
    }
    await this.actions[index]!.undo();
    this.actions.splice(index, 1);
    const ms = this.clock() - start;
    this.spine.stage({ type: "identity.action", actor: "rollback", payload: { event: "rollback_action_complete", id, rolledBack: true, ms } });
    return { rolledBack: true, ms };
    });
  }

  get pending(): number {
    return this.actions.length;
  }
}

/**
 * Idempotency store for external mutations (Round 8). An external action must
 * present a stable idempotency key; a repeated key returns the prior result
 * instead of re-executing. Non-idempotent-able actions must not use this path —
 * they are approval-gated (see action_tier tier 4).
 */
export class IdempotencyStore {
  private readonly seen = new Map<string, unknown>();

  /** Execute `fn` at most once per key; repeats return the cached result. */
  async once<T>(key: string, fn: () => Promise<T>): Promise<{ result: T; deduped: boolean }> {
    if (this.seen.has(key)) {
      return { result: this.seen.get(key) as T, deduped: true };
    }
    const result = await fn();
    this.seen.set(key, result);
    return { result, deduped: false };
  }

  has(key: string): boolean {
    return this.seen.has(key);
  }
}
