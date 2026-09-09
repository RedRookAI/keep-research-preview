/** Durable, non-refundable recovery accounting. Authority remains with the caller's
 * existing admission, metering and effect gates; a budget never grants permission.
 * Uses the deployment's existing exclusive Spine lock/store, not another database.
 */
import { createHash, randomUUID } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { ProjectJobActivityTracker } from "../session/project_job_journal.js";

export interface RecoveryLimits {
  readonly maxAttempts: number;
  readonly maxElapsedMs: number;
  readonly maxPlanningCalls?: number;
  readonly maxPlanningInputBytes?: number;
  /** Optional aggregate embedding ceilings; absent means embedding work is disabled.
   * Bytes are complete outbound JSON bodies, not token prices or account charges. */
  readonly embedding?: EmbeddingWork;
}
export interface EmbeddingWork { readonly requests: number; readonly inputBytes: number; readonly windows: number }
export interface EmbeddingWorkControl {
  /** Sequential host-owned dispatch. Every retry consumes another reserved slot. */
  runRequest<T>(inputBytes: number, windows: number, send: (signal: AbortSignal) => Promise<T>): Promise<T>;
  /** Only after observed responses; thrown/late work is held by the runtime budget. */
  complete(): Promise<void>;
}
type EffectiveRecoveryLimits = Required<Omit<RecoveryLimits, "embedding">> & Pick<RecoveryLimits, "embedding">;
const workFields = ["requests", "inputBytes", "windows"] as const;
function validWork(work: EmbeddingWork | undefined, minimum: number): work is EmbeddingWork {
  return !!work && workFields.every(k => Number.isSafeInteger(work[k]) && work[k] >= minimum);
}
function copyWork(work: EmbeddingWork): EmbeddingWork { return { requests: work.requests, inputBytes: work.inputBytes, windows: work.windows }; }
export type RecoveryHoldKind = "diagnosis" | "authority" | "reconciliation";
export interface RecoverySnapshot {
  readonly status: "ready" | "exhausted" | RecoveryHoldKind;
  readonly attempts: number;
  readonly maxAttempts: number;
  readonly deadline: number;
  readonly planningCalls: number;
  readonly maxPlanningCalls: number;
  readonly planningInputBytes: number;
  readonly maxPlanningInputBytes: number;
  readonly reason?: string;
  readonly pendingAttemptId?: string;
  readonly diagnosisId?: string;
  readonly embedding?: { readonly limits: EmbeddingWork; readonly reserved: EmbeddingWork; readonly pendingWorkId?: string };
}
interface RecoveryState {
  readonly limits: EffectiveRecoveryLimits;
  readonly embedding?: { readonly reserved: EmbeddingWork; readonly pending: string | null };
  readonly startedAt: number;
  readonly lastAt: number;
  readonly attempts: number;
  readonly planningCalls: number;
  readonly planningInputBytes: number;
  readonly pending: string | null;
  readonly held: string | null;
  readonly holdKind: RecoveryHoldKind | null;
  readonly failureSet: string | null;
  readonly unproductive: number;
  readonly plans: readonly string[];
}
export interface RecoveryPermit { readonly id: string; readonly attempt: number; readonly deadline: number }
export class RecoveryHeldError extends Error {
  constructor(readonly reason: string) { super(`Recovery held: ${reason}`); }
}

export class RecoveryBudget {
  private readonly key: string;
  private readonly limits: EffectiveRecoveryLimits;
  private readonly owned = new Set<string>();
  constructor(private readonly spine: Spine, operationId: string, limits: RecoveryLimits, private readonly now: () => number = Date.now, private readonly signal?: AbortSignal, private readonly trackActivity?: ProjectJobActivityTracker) {
    if (!operationId || operationId.length > 4096) throw new Error("invalid recovery operation identity");
    if (!Number.isSafeInteger(limits.maxAttempts) || limits.maxAttempts < 1 || limits.maxAttempts > 1000 ||
        !Number.isSafeInteger(limits.maxElapsedMs) || limits.maxElapsedMs < 1 || limits.maxElapsedMs > 86_400_000) throw new Error("invalid finite recovery limits");
    const maxPlanningCalls = limits.maxPlanningCalls ?? limits.maxAttempts * 4;
    const maxPlanningInputBytes = limits.maxPlanningInputBytes ?? maxPlanningCalls * 65_536;
    if (!Number.isSafeInteger(maxPlanningCalls) || maxPlanningCalls < 1 || maxPlanningCalls > 64_000 ||
        !Number.isSafeInteger(maxPlanningInputBytes) || maxPlanningInputBytes < 1) throw new Error("invalid finite planning limits");
    this.key = createHash("sha256").update(operationId).digest("hex");
    if (limits.embedding !== undefined && !validWork(limits.embedding, 1)) throw new Error("invalid finite embedding limits");
    this.limits = Object.freeze({ maxAttempts: limits.maxAttempts, maxElapsedMs: limits.maxElapsedMs, maxPlanningCalls, maxPlanningInputBytes,
      ...(limits.embedding === undefined ? {} : { embedding: Object.freeze(copyWork(limits.embedding)) }) });
  }

  private read(): RecoveryState | undefined {
    const rows = this.spine.replay().filter(e => e.type === "identity.action" && e.actor === "solve.recovery" && e.payload["operation"] === this.key && e.payload["event"] === "recovery.state");
    const state = rows.at(-1)?.payload["state"] as RecoveryState | undefined;
    if (state === undefined) return undefined;
    if (!state || !Number.isSafeInteger(state.attempts) || state.attempts < 0 || !Number.isSafeInteger(state.startedAt) || state.startedAt < 0 ||
        !Number.isSafeInteger(state.lastAt) || state.lastAt < state.startedAt || !state.limits ||
        state.limits.maxAttempts !== this.limits.maxAttempts || state.limits.maxElapsedMs !== this.limits.maxElapsedMs ||
        state.limits.maxPlanningCalls !== this.limits.maxPlanningCalls || state.limits.maxPlanningInputBytes !== this.limits.maxPlanningInputBytes ||
        !Number.isSafeInteger(state.planningCalls) || state.planningCalls < 0 || state.planningCalls > this.limits.maxPlanningCalls ||
        !Number.isSafeInteger(state.planningInputBytes) || state.planningInputBytes < 0 || state.planningInputBytes > this.limits.maxPlanningInputBytes ||
        state.attempts > state.limits.maxAttempts || (state.pending !== null && typeof state.pending !== "string") ||
        (state.held !== null && (typeof state.held !== "string" || state.held.length === 0)) ||
        (state.holdKind !== null && !["diagnosis", "authority", "reconciliation"].includes(state.holdKind)) ||
        ((state.held === null) !== (state.holdKind === null)) || !Number.isSafeInteger(state.unproductive) || state.unproductive < 0 ||
        (state.failureSet !== null && typeof state.failureSet !== "string") || !Array.isArray(state.plans) || state.plans.length > state.limits.maxAttempts ||
        !state.plans.every(p => typeof p === "string" && /^[a-f0-9]{64}$/.test(p))) throw new RecoveryHeldError("stored recovery identity/limits invalid or changed");
    const embeddingLimits = this.limits.embedding;
    if (embeddingLimits === undefined ? state.limits.embedding !== undefined || state.embedding !== undefined :
        !validWork(state.limits.embedding, 1) || !workFields.every(k => state.limits.embedding![k] === embeddingLimits[k]) ||
        !validWork(state.embedding?.reserved, 0) || !workFields.every(k => state.embedding!.reserved[k] <= embeddingLimits[k]) ||
        (state.embedding!.pending !== null && (typeof state.embedding!.pending !== "string" || !state.embedding!.pending || !state.pending))) {
      throw new RecoveryHeldError("stored embedding identity/limits invalid or changed");
    }
    return state;
  }

  private async change<T>(fn: (state: RecoveryState, at: number) => Promise<T>): Promise<T> {
    return this.spine.withCoordinationLock(`solve.recovery:${this.key}`, async () => {
      // Includes recoverable staged reservations before reading; never refund an
      // attempt merely because its block/cursor transaction was interrupted.
      await this.spine.seal();
      const at = this.now();
      if (!Number.isSafeInteger(at) || at < 0) throw new RecoveryHeldError("invalid clock");
      const state = this.read() ?? { limits: this.limits, startedAt: at, lastAt: at, attempts: 0, planningCalls: 0, planningInputBytes: 0, pending: null, held: null, holdKind: null, failureSet: null, unproductive: 0, plans: [],
        ...(this.limits.embedding === undefined ? {} : { embedding: { reserved: { requests: 0, inputBytes: 0, windows: 0 }, pending: null } }) };
      if (at < state.lastAt) {
        await this.write({ ...state, held: "clock moved backwards", holdKind: "diagnosis" });
        throw new RecoveryHeldError("clock moved backwards");
      }
      return fn(state, at);
    });
  }

  private async write(state: RecoveryState): Promise<void> {
    this.spine.stage({ type: "identity.action", actor: "solve.recovery", payload: { event: "recovery.state", operation: this.key, state } });
    await this.spine.seal();
  }

  async reserve(): Promise<RecoveryPermit> {
    return this.change(async (state, at) => {
      this.assertNotCancelled();
      if (state.held) throw new RecoveryHeldError(state.held);
      if (state.pending) throw new RecoveryHeldError("unresolved attempt requires reconciliation; it is not a free retry");
      if (state.attempts >= state.limits.maxAttempts) throw new RecoveryHeldError("attempt budget exhausted");
      const deadline = state.startedAt + state.limits.maxElapsedMs;
      if (!Number.isSafeInteger(deadline) || at >= deadline) throw new RecoveryHeldError("wall-time budget exhausted");
      const id = randomUUID();
      await this.write({ ...state, attempts: state.attempts + 1, pending: id, lastAt: at });
      this.owned.add(id);
      return Object.freeze({ id, attempt: state.attempts + 1, deadline });
    });
  }

  async finish(permit: RecoveryPermit): Promise<void> {
    if (!this.owned.has(permit.id)) return;
    await this.change(async (state, at) => {
      if (state.pending !== permit.id) throw new RecoveryHeldError("attempt ownership changed");
      const held = state.held ?? (state.embedding?.pending ? "unresolved embedding work requires reconciliation" : at >= permit.deadline ? "wall-time budget exhausted" : null);
      const holdKind = state.holdKind ?? (held ? "reconciliation" : null);
      await this.write({ ...state, pending: holdKind === "reconciliation" || state.embedding?.pending ? state.pending : null, lastAt: at, held, holdKind });
      this.owned.delete(permit.id);
    });
  }

  /** Persist BEFORE provider dispatch. Exhaustion is an ordinary non-success;
   * identity/corruption errors are holds. New attempts and restarts never refund usage.
   * Input bytes bound exposure, not provider billing or output-token metering. */
  async reservePlanningCall(permit: RecoveryPermit, inputBytes: number): Promise<boolean> {
    if (!Number.isSafeInteger(inputBytes) || inputBytes < 1) throw new RecoveryHeldError("invalid planning input size");
    return this.change(async (state, at) => {
      this.assertNotCancelled();
      if (!this.owned.has(permit.id) || state.held || state.embedding?.pending || state.pending !== permit.id ||
          permit.attempt !== state.attempts || permit.deadline !== state.startedAt + state.limits.maxElapsedMs || at >= permit.deadline) {
        throw new RecoveryHeldError(state.held ?? "planning attempt is no longer owned and live");
      }
      if (state.planningCalls >= state.limits.maxPlanningCalls || inputBytes > state.limits.maxPlanningInputBytes - state.planningInputBytes) return false;
      await this.write({ ...state, planningCalls: state.planningCalls + 1, planningInputBytes: state.planningInputBytes + inputBytes, lastAt: at });
      return true;
    });
  }

  /** Non-refundable aggregate reservation BEFORE any batch. This meters work; it
   * does not admit a model, destination, purpose, document disclosure or dollar cost. */
  async reserveEmbeddingWork(permit: RecoveryPermit, requested: EmbeddingWork): Promise<EmbeddingWorkControl> {
    if (!validWork(requested, 1)) throw new RecoveryHeldError("invalid embedding work reservation");
    const plan = Object.freeze(copyWork(requested)), workId = randomUUID();
    const assertOwned = (state: RecoveryState, at: number) => {
      this.assertNotCancelled();
      if (!this.owned.has(permit.id) || state.held || state.pending !== permit.id || permit.attempt !== state.attempts ||
          permit.deadline !== state.startedAt + state.limits.maxElapsedMs || at >= permit.deadline) throw new RecoveryHeldError(state.held ?? "embedding attempt is no longer owned and live");
    };
    await this.change(async (state, at) => {
      assertOwned(state, at);
      const limits = state.limits.embedding, current = state.embedding;
      if (!limits || !current) throw new RecoveryHeldError("embedding work is disabled");
      if (current.pending) throw new RecoveryHeldError("unresolved embedding work requires reconciliation");
      if (workFields.some(k => plan[k] > limits[k] - current.reserved[k])) throw new RecoveryHeldError("aggregate embedding budget exhausted");
      await this.write({ ...state, lastAt: at, embedding: { pending: workId, reserved: {
        requests: current.reserved.requests + plan.requests, inputBytes: current.reserved.inputBytes + plan.inputBytes, windows: current.reserved.windows + plan.windows,
      } } });
    });
    let busy = false, closed = false;
    const used = { requests: 0, inputBytes: 0, windows: 0 };
    const assertControl = (state: RecoveryState, at: number) => {
      assertOwned(state, at);
      if (state.embedding?.pending !== workId) throw new RecoveryHeldError("embedding work ownership changed");
    };
    return Object.freeze({
      runRequest: async <T>(inputBytes: number, windows: number, send: (signal: AbortSignal) => Promise<T>): Promise<T> => {
        if (busy || closed) throw new RecoveryHeldError("embedding control is busy or closed");
        if (!validWork({ requests: 1, inputBytes, windows }, 1) || used.requests >= plan.requests ||
            inputBytes > plan.inputBytes - used.inputBytes || windows > plan.windows - used.windows) throw new RecoveryHeldError("embedding dispatch exceeds reservation");
        busy = true;
        try {
          await this.change(async (state, at) => { assertControl(state, at); });
          used.requests++; used.inputBytes += inputBytes; used.windows += windows;
          // Aggregate remains pending on crash. during() preserves unknown outcomes,
          // including adapters which ignore cancellation; no late result clears it.
          return await this.during(permit, send);
        } finally { busy = false; }
      },
      complete: async () => {
        if (busy || closed) throw new RecoveryHeldError("embedding control is busy or closed");
        busy = true;
        try {
          await this.change(async (state, at) => {
            assertControl(state, at);
            await this.write({ ...state, lastAt: at, embedding: { reserved: state.embedding!.reserved, pending: null } });
          });
          closed = true;
        } finally { busy = false; }
      },
    });
  }

  async hold(reason: string, kind: RecoveryHoldKind = "reconciliation"): Promise<void> {
    if (!reason) throw new RecoveryHeldError("empty hold reason");
    await this.change(async (state, at) => this.write({ ...state, lastAt: at, held: state.held ?? reason.slice(0, 2048), holdKind: state.holdKind ?? kind }));
  }

  async snapshot(): Promise<RecoverySnapshot> {
    return this.change(async (state, at) => {
      const deadline = state.startedAt + state.limits.maxElapsedMs;
      const exhausted = at >= deadline || state.attempts >= state.limits.maxAttempts ||
        state.planningCalls >= state.limits.maxPlanningCalls || state.planningInputBytes >= state.limits.maxPlanningInputBytes;
      return { status: state.holdKind ?? (state.pending ? "reconciliation" : exhausted ? "exhausted" : "ready"),
        attempts: state.attempts, maxAttempts: state.limits.maxAttempts, deadline,
        planningCalls: state.planningCalls, maxPlanningCalls: state.limits.maxPlanningCalls,
        planningInputBytes: state.planningInputBytes, maxPlanningInputBytes: state.limits.maxPlanningInputBytes,
        ...(state.embedding && state.limits.embedding ? { embedding: { limits: copyWork(state.limits.embedding), reserved: copyWork(state.embedding.reserved),
          ...(state.embedding.pending ? { pendingWorkId: state.embedding.pending } : {}) } } : {}),
        ...(state.held ? { reason: state.held } : exhausted ? { reason: "recovery budget exhausted" } : {}),
        ...(state.holdKind === "diagnosis" ? { diagnosisId: this.diagnosisId(state) } : {}),
        ...(state.pending ? { pendingAttemptId: state.pending } : {}) };
    });
  }

  private diagnosisId(state: RecoveryState): string {
    return createHash("sha256").update(JSON.stringify([this.key, state.attempts, state.held, state.failureSet, state.plans])).digest("hex");
  }

  /** Trusted execution evidence that the diagnosed capability/input was corrected.
   * This permits a bounded recheck, never authority escalation or budget replenishment. */
  async resumeDiagnosis(holdId: string, evidenceId: string): Promise<void> {
    if (!evidenceId || evidenceId.length > 2048) throw new RecoveryHeldError("missing diagnosis evidence");
    await this.change(async (state, at) => {
      if (state.holdKind !== "diagnosis" || state.pending || this.diagnosisId(state) !== holdId) throw new RecoveryHeldError("diagnosis evidence does not match the quiescent hold");
      this.spine.stage({ type: "identity.action", actor: "solve.recovery", payload: { event: "recovery.diagnosed", operation: this.key, holdId, evidenceId } });
      await this.write({ ...state, held: null, holdKind: null, lastAt: at });
    });
  }

  /** Bounds the whole call, including adapters which do not expose cancellation.
   * Late work stays unresolved; it is never permission to dispatch another attempt. */
  async withinDeadline<T>(fn: () => Promise<T>): Promise<T> {
    const { deadline } = await this.snapshot();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new RecoveryHeldError("wall-time budget exhausted; reconcile in-flight work")), Math.max(1, deadline - this.now()));
    });
    try {
      const run = () => { this.assertNotCancelled(); if (this.now() >= deadline) throw new RecoveryHeldError("wall-time budget exhausted before activity dispatch"); return fn(); };
      const result = await this.untilCancelled(() => Promise.race([this.trackActivity ? this.trackActivity("solve-attempt", run) : run(), timeout]));
      if (this.now() >= deadline) throw new RecoveryHeldError("wall-time budget exhausted");
      return result;
    } catch (error) {
      await this.hold(error instanceof RecoveryHeldError ? error.reason : "solve threw; reconciliation required");
      throw error;
    } finally { if (timer !== undefined) clearTimeout(timer); }
  }

  async observeFailures(failures: readonly string[]): Promise<number> {
    const fingerprint = createHash("sha256").update(JSON.stringify([...new Set(failures)].sort())).digest("hex");
    return this.change(async (state, at) => {
      const unproductive = failures.length > 0 && state.failureSet === fingerprint ? state.unproductive + 1 : 0;
      await this.write({ ...state, failureSet: fingerprint, unproductive, lastAt: at });
      return unproductive;
    });
  }

  async rememberPlan(fingerprint: string): Promise<boolean> {
    if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new RecoveryHeldError("invalid plan fingerprint");
    return this.change(async (state, at) => {
      if (state.plans.includes(fingerprint)) return false;
      if (state.plans.length >= state.limits.maxAttempts) throw new RecoveryHeldError("plan budget exhausted");
      await this.write({ ...state, plans: [...state.plans, fingerprint], lastAt: at });
      return true;
    });
  }

  async assertLive(permit: RecoveryPermit): Promise<void> {
    await this.change(async (state, at) => {
      this.assertNotCancelled();
      if (state.held || state.pending !== permit.id || at >= permit.deadline) throw new RecoveryHeldError(state.held ?? "attempt is no longer live");
    });
  }

  /** Cancellation is cooperative. If a port ignores it, the operation remains held;
   * its late result cannot authorize another effect, promotion, or automatic retry.
   */
  async during<T>(permit: RecoveryPermit, fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
    await this.assertLive(permit);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new RecoveryHeldError("wall-time budget exhausted; reconcile in-flight work")); }, Math.max(1, permit.deadline - this.now()));
    });
    try {
      const signal = this.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, this.signal]);
      const run = () => { signal.throwIfAborted(); return fn(signal); };
      const result = await this.untilCancelled(() => Promise.race([this.trackActivity ? this.trackActivity("solve-call", run) : run(), timeout]));
      await this.assertLive(permit);
      return result;
    } catch (error) {
      await this.hold(error instanceof RecoveryHeldError ? error.reason : "attempt threw; reconcile before another dispatch");
      throw error;
    } finally { if (timer !== undefined) clearTimeout(timer); }
  }

  private assertNotCancelled(): void {
    if (this.signal?.aborted) throw new RecoveryHeldError("operator cancellation requested; reconcile in-flight work");
  }

  private async untilCancelled<T>(fn: () => Promise<T>): Promise<T> {
    this.assertNotCancelled();
    if (this.signal === undefined) return fn();
    let abort!: () => void;
    const cancelled = new Promise<never>((_, reject) => {
      abort = () => reject(new RecoveryHeldError("operator cancellation requested; reconcile in-flight work"));
      this.signal!.addEventListener("abort", abort, { once: true });
    });
    try {
      const result = await Promise.race([Promise.resolve().then(() => { this.assertNotCancelled(); return fn(); }), cancelled]);
      this.assertNotCancelled();
      return result;
    } finally { this.signal.removeEventListener("abort", abort); }
  }

  /** Trusted host port: the caller must authenticate matching run/effect evidence
   * and establish that prior work is quiescent. Never called on automatic retry.
   * Counters, deadline and frozen limits are deliberately not reset.
   */
  async reconcile(pendingAttemptId: string, evidenceId: string): Promise<void> {
    if (!pendingAttemptId || !evidenceId || evidenceId.length > 2048) throw new RecoveryHeldError("missing reconciliation identity");
    await this.change(async (state, at) => {
      if (this.spine.replay().some(e => e.actor === "solve.recovery" && e.payload["operation"] === this.key && e.payload["event"] === "recovery.reconciled" && e.payload["attempt"] === pendingAttemptId && e.payload["evidenceId"] === evidenceId)) return;
      if (state.pending !== pendingAttemptId) throw new RecoveryHeldError("reconciliation does not match pending attempt");
      if (this.owned.has(pendingAttemptId)) throw new RecoveryHeldError("cannot reconcile an attempt still owned by this executor");
      if (state.holdKind && state.holdKind !== "reconciliation") throw new RecoveryHeldError("reconciliation cannot clear diagnosis or authority holds");
      this.spine.stage({ type: "identity.action", actor: "solve.recovery", payload: { event: "recovery.reconciled", operation: this.key, attempt: pendingAttemptId, evidenceId } });
      await this.write({ ...state, pending: null, held: null, holdKind: null, lastAt: at,
        ...(state.embedding ? { embedding: { ...state.embedding, pending: null } } : {}) });
    });
  }
}
