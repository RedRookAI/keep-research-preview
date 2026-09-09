/** Durable, bounded, proposal-only scheduling for measured capability-improvement needs. */

import type { Spine } from "../spine/spine.js";
import type { Learner, OutcomeSignal } from "../loop/self_improvement_bus.js";
import type { AuthorizationPort, Principal } from "../identity/rbac.js";
import { createHash } from "node:crypto";

export type NeedKind = "research" | "rag" | "skill" | "evaluation-data" | "training";
export interface NeedSignal {
  readonly id: string; readonly goal: string; readonly subject: string;
  /** Pure-recognizer compatibility only. Runtime tenant scheduling uses `forPrincipal`. */
  readonly scopeId?: string;
  readonly currentKnowledgeMissing?: boolean; readonly projectEvidenceMissing?: boolean;
  readonly repeatedSuccessfulProcedure?: boolean; readonly measuredFailureCount?: number;
  readonly evaluationCoverage?: number; readonly gradientFreeTried?: boolean;
  readonly residualFailureRate?: number; readonly verifiedExampleCount?: number;
  readonly verifiableRewardAvailable?: boolean; readonly narrowStableTask?: boolean;
}
export interface NeedProposal {
  readonly id: string; readonly signalId: string; readonly kind: NeedKind; readonly subject: string;
  readonly scopeId?: string; readonly goal: string; readonly reason: string; readonly priority: number;
  /** Training never executes from this scheduler; it requires a separate opt-in gate. */
  readonly requiresOptIn: boolean;
}
export interface NeedSchedule {
  readonly scheduled: readonly NeedProposal[];
  readonly deferred: readonly NeedProposal[];
  /** Invalid inputs are distinguished from valid observations that simply recognize no need. */
  readonly rejected?: number;
}
export interface NeedSchedulerOptions {
  readonly maxPerCycle?: number; readonly maxPerKind?: number;
  /** Per-scope durable ready-inbox ceiling. */
  readonly maxPending?: number;
  /** Per-scope durable deferred-backlog ceiling. */
  readonly maxDeferred?: number;
  readonly cooldownCycles?: number; readonly trainingProposalsEnabled?: boolean;
}
/** Opaque runtime binding minted only after canonical principal authorization. */
export interface NeedScopeBinding { readonly scopeId: string; readonly token: object; }
export interface ScopedNeedScheduler {
  readonly outcomeBinding: NeedScopeBinding;
  schedule(signals: readonly NeedSignal[]): NeedSchedule;
  pending(): readonly NeedProposal[];
  deferred(): readonly NeedProposal[];
  acknowledge(proposalId: string): boolean;
}

const PRIORITY: Record<NeedKind, number> = { research: 100, rag: 90, skill: 70, "evaluation-data": 60, training: 20 };
const N1_SCOPE = "n1";
const EVENT = "need_scheduler.transition";
const MAX_SIGNALS_PER_CYCLE = 10_000;
interface ScopeGrant { readonly scope: string; readonly principal: Principal; readonly authorization: AuthorizationPort; }
interface SchedulePlan extends NeedSchedule {
  readonly deferredAdded: readonly NeedProposal[];
  readonly deferredRemoved: readonly string[];
  readonly evictedIds: readonly string[];
}

/** Pure compatibility recognizer. Runtime scheduling rebinds scope through an authorized view. */
export function recognizeNeeds(input: NeedSignal, trainingProposalsEnabled = false): NeedProposal[] {
  const signal = inertSignal(input);
  if (signal === undefined) return [];
  return recognizeInScope(signal, signal.scopeId === undefined ? N1_SCOPE : tenantScope(signal.scopeId), trainingProposalsEnabled);
}

/** Durable scheduler and protect-class consumer; it has no proposal execution surface. */
export class BoundedNeedScheduler implements Learner {
  readonly id = "bounded-need-scheduler";
  readonly loopClass = "protect" as const;
  readonly acceptsScopeBinding = true;
  private cycle = 0;
  private readonly lastScheduled = new Map<string, number>();
  private readonly pendingById = new Map<string, NeedProposal>();
  private readonly deferredById = new Map<string, NeedProposal>();
  private readonly observedSolves = new Set<string>();
  private readonly outcomeCounts = new Map<string, { failures: number; total: number }>();
  private readonly bindings = new WeakMap<object, ScopeGrant>();
  private readonly maxPerCycle: number;
  private readonly maxPerKind: number;
  private readonly maxPending: number;
  private readonly maxDeferred: number;
  private readonly cooldownCycles: number;
  private readonly trainingEnabled: boolean;

  constructor(opts: NeedSchedulerOptions = {}, private readonly spine?: Spine) {
    this.maxPerCycle = positiveInt(opts.maxPerCycle, 3);
    this.maxPerKind = positiveInt(opts.maxPerKind, 1);
    this.maxPending = positiveInt(opts.maxPending, 1_000);
    this.maxDeferred = positiveInt(opts.maxDeferred, 1_000);
    this.cooldownCycles = nonNegativeInt(opts.cooldownCycles, 2);
    this.trainingEnabled = opts.trainingProposalsEnabled ?? false;
    this.restore();
  }

  /** Original n=1 API. Caller-supplied tenant scope is rejected; enterprise uses `forPrincipal`. */
  schedule(signals: readonly NeedSignal[]): NeedSchedule { return this.scheduleFor(N1_SCOPE, signals, true); }
  pending(): readonly NeedProposal[] { return this.readyFor(N1_SCOPE); }
  deferred(): readonly NeedProposal[] { return this.deferredFor(N1_SCOPE); }
  acknowledge(proposalId: string): boolean { return this.acknowledgeFor(N1_SCOPE, proposalId); }

  /** Bind enterprise operations to the tenant on an authorized canonical Principal. */
  forPrincipal(principal: Principal, authorization: AuthorizationPort): ScopedNeedScheduler | undefined {
    if (!validTenant(principal.tenant) || !authorization.authorize(principal, "change.solve").allow) return undefined;
    const scope = tenantScope(principal.tenant);
    const token = Object.freeze({});
    this.bindings.set(token, { scope, principal, authorization });
    const binding = Object.freeze({ scopeId: principal.tenant, token });
    return Object.freeze({
      outcomeBinding: binding,
      schedule: (signals: readonly NeedSignal[]) => authorization.authorize(principal, "change.solve").allow
        ? this.scheduleFor(scope, signals, false) : { scheduled: [], deferred: [], rejected: inertArray(signals).length },
      pending: () => authorization.authorize(principal, "audit.view").allow ? this.readyFor(scope) : [],
      deferred: () => authorization.authorize(principal, "audit.view").allow ? this.deferredFor(scope) : [],
      acknowledge: (id: string) => authorization.authorize(principal, "config.write").allow && this.acknowledgeFor(scope, id),
    });
  }

  private scheduleFor(scope: string, inputs: readonly NeedSignal[], n1: boolean): NeedSchedule {
    const proposals = new Map<string, NeedProposal>();
    let rejected = 0;
    for (const input of inertArray(inputs)) {
      const signal = inertSignal(input);
      if (signal === undefined || (n1 ? signal.scopeId !== undefined : signal.scopeId !== undefined && tenantScope(signal.scopeId) !== scope)) {
        rejected += 1;
        continue;
      }
      const rebound = signal.scopeId === undefined && scope !== N1_SCOPE ? { ...signal, scopeId: tenantIdOf(scope) } : signal;
      for (const proposal of recognizeInScope(rebound, scope, this.trainingEnabled)) {
        const prior = proposals.get(proposal.id);
        // Stronger than the preserved first-input rule: provenance is stable under input reordering.
        if (prior === undefined || proposal.signalId.localeCompare(prior.signalId) < 0) proposals.set(proposal.id, proposal);
      }
    }
    const result = this.commitSchedule(scope, [...proposals.values()]);
    return rejected === 0 ? result : { ...result, rejected };
  }

  private commitSchedule(scope: string, proposals: readonly NeedProposal[]): NeedSchedule {
    const nextCycle = this.cycle + 1;
    const plan = this.planSchedule(scope, proposals, nextCycle);
    this.record({ op: "schedule", cycle: nextCycle, scheduled: plan.scheduled,
      deferredAdded: plan.deferredAdded, deferredRemoved: plan.deferredRemoved, eviction: evictionReceipt(plan.evictedIds) });
    this.applyScheduleDelta(nextCycle, plan.scheduled, plan.deferredAdded, plan.deferredRemoved);
    return { scheduled: plan.scheduled, deferred: plan.deferred };
  }

  private planSchedule(scope: string, incoming: readonly NeedProposal[], cycle: number): SchedulePlan {
    const candidates = new Map<string, NeedProposal>();
    for (const proposal of [...this.deferredFor(scope), ...incoming]) candidates.set(proposal.id, proposal);
    const ordered = fairOrder([...candidates.values()], cycle);
    const scheduled: NeedProposal[] = [];
    const deferred: NeedProposal[] = [];
    const byScopeKind = new Map<string, number>();
    const pendingCounts = new Map<string, number>();
    for (const proposal of this.pendingById.values()) {
      const scope = scopeOf(proposal);
      pendingCounts.set(scope, (pendingCounts.get(scope) ?? 0) + 1);
    }
    for (const proposal of ordered) {
      if (this.pendingById.has(proposal.id)) continue;
      const scope = scopeOf(proposal);
      const prior = this.lastScheduled.get(proposal.id);
      const quotaKey = `${scope}\u0000${proposal.kind}`;
      const cooling = prior !== undefined && cycle - prior <= this.cooldownCycles;
      const kindFull = (byScopeKind.get(quotaKey) ?? 0) >= this.maxPerKind;
      const scopeFull = (pendingCounts.get(scope) ?? 0) >= this.maxPending;
      if (cooling || kindFull || scopeFull || scheduled.length >= this.maxPerCycle) { deferred.push(proposal); continue; }
      scheduled.push(proposal);
      byScopeKind.set(quotaKey, (byScopeKind.get(quotaKey) ?? 0) + 1);
      pendingCounts.set(scope, (pendingCounts.get(scope) ?? 0) + 1);
    }
    const boundedDeferred: NeedProposal[] = [];
    const evictedIds: string[] = [];
    const deferredByScope = new Map<string, NeedProposal[]>();
    for (const proposal of deferred) {
      const scope = scopeOf(proposal); const queue = deferredByScope.get(scope) ?? [];
      queue.push(proposal); deferredByScope.set(scope, queue);
    }
    for (const queue of deferredByScope.values()) {
      queue.sort(proposalOrder);
      boundedDeferred.push(...queue.slice(0, this.maxDeferred));
      evictedIds.push(...queue.slice(this.maxDeferred).map((proposal) => proposal.id));
    }
    boundedDeferred.sort(proposalOrder);
    const finalIds = new Set(boundedDeferred.map((proposal) => proposal.id));
    const priorIds = new Set(this.deferredFor(scope).map((proposal) => proposal.id));
    const deferredAdded = boundedDeferred.filter((proposal) => {
      const prior = this.deferredById.get(proposal.id);
      return prior === undefined || !sameProposal(prior, proposal);
    });
    const deferredRemoved = [...priorIds].filter((id) => !finalIds.has(id));
    return { scheduled, deferred: boundedDeferred, deferredAdded, deferredRemoved, evictedIds };
  }

  private applyScheduleDelta(cycle: number, scheduled: readonly NeedProposal[], deferredAdded: readonly NeedProposal[], deferredRemoved: readonly string[]): void {
    this.cycle = Math.max(this.cycle, cycle);
    for (const id of deferredRemoved) this.deferredById.delete(id);
    for (const proposal of scheduled) {
      const scope = scopeOf(proposal);
      if (this.readyFor(scope).length >= this.maxPending && !this.pendingById.has(proposal.id)) {
        this.deferredById.set(proposal.id, proposal);
        continue;
      }
      this.lastScheduled.set(proposal.id, cycle);
      this.pendingById.set(proposal.id, proposal);
      this.deferredById.delete(proposal.id);
    }
    for (const proposal of deferredAdded) {
      const scope = scopeOf(proposal);
      if (!this.pendingById.has(proposal.id) && (this.deferredById.has(proposal.id) || this.deferredFor(scope).length < this.maxDeferred)) {
        this.deferredById.set(proposal.id, proposal);
      }
    }
  }

  /** Immediate consumer for scope-bound real solve outcomes. Invalid/forged bindings are ignored. */
  onOutcome(input: OutcomeSignal): void {
    const signal = inertOutcome(input, this.bindings);
    if (signal === undefined) return;
    const observedKey = `${signal.scope}\u0000${signal.solveId}`;
    if (this.observedSolves.has(observedKey)) return;
    const countKey = `${signal.scope}\u0000${signal.taskShape}`;
    const prior = this.outcomeCounts.get(countKey) ?? { failures: 0, total: 0 };
    const next = { failures: prior.failures + (signal.testsPassed ? 0 : 1), total: prior.total + 1 };
    const proposal = !signal.testsPassed && next.failures >= 2 ? canonicalProposal({
      id: proposalId(signal.scope, "evaluation-data", signal.taskShape),
      signalId: `outcomes:${signal.scope}:${signal.solveId}`, kind: "evaluation-data", subject: signal.taskShape,
      ...(signal.scope === N1_SCOPE ? {} : { scopeId: tenantIdOf(signal.scope) }),
      goal: `retain regression evidence and improve measured outcomes for ${signal.taskShape}`,
      reason: `${next.failures} distinct execution-grounded solve failures should become regression evidence`,
      priority: PRIORITY["evaluation-data"], requiresOptIn: false,
    }) : undefined;
    const nextCycle = proposal === undefined ? this.cycle : this.cycle + 1;
    const plan: SchedulePlan = proposal === undefined
      ? { scheduled: [], deferred: [], deferredAdded: [], deferredRemoved: [], evictedIds: [] }
      : this.planSchedule(signal.scope, [proposal], nextCycle);
    // Evidence and derived queue disposition share one append: restart cannot observe only half the transition.
    this.record({ op: "outcome", solveId: signal.solveId, scope: signal.scope, taskShape: signal.taskShape,
      testsPassed: signal.testsPassed, cycle: nextCycle, scheduled: plan.scheduled,
      deferredAdded: plan.deferredAdded, deferredRemoved: plan.deferredRemoved, eviction: evictionReceipt(plan.evictedIds) });
    this.observedSolves.add(observedKey);
    this.outcomeCounts.set(countKey, next);
    this.applyScheduleDelta(nextCycle, plan.scheduled, plan.deferredAdded, plan.deferredRemoved);
  }

  private acknowledgeFor(scope: string, proposalIdValue: string): boolean {
    if (!validText(proposalIdValue, 4096)) return false;
    const existing = this.pendingById.get(proposalIdValue);
    if (existing === undefined || scopeOf(existing) !== scope) return false;
    const nextCycle = this.cycle + 1;
    const promoted = this.deferredFor(scope).filter((proposal) => {
      const prior = this.lastScheduled.get(proposal.id);
      return prior === undefined || nextCycle - prior > this.cooldownCycles;
    }).slice(0, 1);
    const promotedIds = promoted.map((proposal) => proposal.id);
    this.record({ op: "acknowledge", proposalId: proposalIdValue, scope, cycle: nextCycle,
      promoted, deferredAdded: [], deferredRemoved: promotedIds });
    this.pendingById.delete(proposalIdValue);
    this.deferredById.delete(proposalIdValue);
    this.applyScheduleDelta(nextCycle, promoted, [], promotedIds);
    return true;
  }

  private readyFor(scope: string): readonly NeedProposal[] {
    return [...this.pendingById.values()].filter((p) => scopeOf(p) === scope).sort(proposalOrder);
  }
  private deferredFor(scope: string): readonly NeedProposal[] {
    return [...this.deferredById.values()].filter((p) => scopeOf(p) === scope).sort(proposalOrder);
  }
  private record(payload: Record<string, unknown>): void {
    this.spine?.stage({ type: "identity.action", actor: this.id, payload: { event: EVENT, ...payload } });
  }
  private restore(): void {
    if (this.spine === undefined) return;
    for (const event of this.spine.currentEvents()) {
      const p = event.payload;
      if (event.actor !== this.id || p.event !== EVENT || typeof p.op !== "string") continue;
      if (p.op === "outcome" && validText(p.solveId, 512) && validScopeKey(p.scope) && validText(p.taskShape, 512) &&
        typeof p.testsPassed === "boolean" && validCycle(p.cycle)) {
        const observedKey = `${p.scope}\u0000${p.solveId}`;
        if (this.observedSolves.has(observedKey)) continue;
        this.observedSolves.add(observedKey);
        const key = `${p.scope}\u0000${p.taskShape}`;
        const prior = this.outcomeCounts.get(key) ?? { failures: 0, total: 0 };
        this.outcomeCounts.set(key, { failures: prior.failures + (p.testsPassed ? 0 : 1), total: prior.total + 1 });
        this.restoreSchedule(p.cycle as number, p);
      } else if (p.op === "schedule" && validCycle(p.cycle)) {
        this.restoreSchedule(p.cycle as number, p);
      } else if (p.op === "acknowledge" && validText(p.proposalId, 4096) && validScopeKey(p.scope) && validCycle(p.cycle)) {
        const proposal = this.pendingById.get(p.proposalId);
        if (proposal === undefined || scopeOf(proposal) !== p.scope) continue;
        this.pendingById.delete(p.proposalId);
        this.deferredById.delete(p.proposalId);
        this.restoreSchedule(p.cycle as number, { scheduled: p.promoted, deferredAdded: p.deferredAdded,
          deferredRemoved: p.deferredRemoved, deferred: p.deferred });
      }
    }
  }
  private restoreSchedule(cycle: number, payload: Readonly<Record<string, unknown>>): void {
    const scheduled = canonicalProposalArray(payload.scheduled);
    // Compatibility with the first canonical event shape: a full `deferred` snapshot becomes a delta.
    if (Array.isArray(payload.deferred) && payload.deferredAdded === undefined) {
      const snapshot = canonicalProposalArray(payload.deferred);
      const snapshotIds = new Set(snapshot.map((proposal) => proposal.id));
      this.applyScheduleDelta(cycle, scheduled, snapshot,
        [...this.deferredById.keys()].filter((id) => !snapshotIds.has(id)));
      return;
    }
    this.applyScheduleDelta(cycle, scheduled, canonicalProposalArray(payload.deferredAdded), canonicalIdArray(payload.deferredRemoved));
  }
}

function recognizeInScope(signal: NeedSignal, scope: string, trainingEnabled: boolean): NeedProposal[] {
  const out: NeedProposal[] = [];
  const add = (kind: NeedKind, reason: string): void => { out.push({
    id: proposalId(scope, kind, signal.subject), signalId: signal.id, kind, subject: signal.subject,
    ...(scope === N1_SCOPE ? {} : { scopeId: tenantIdOf(scope) }), goal: signal.goal, reason,
    priority: PRIORITY[kind], requiresOptIn: kind === "training",
  }); };
  if (signal.currentKnowledgeMissing) add("research", "current external knowledge is missing");
  if (signal.projectEvidenceMissing) add("rag", "project evidence is missing from the working context");
  if (signal.repeatedSuccessfulProcedure) add("skill", "a successful procedure has repeated and may be reusable");
  const failures = signal.measuredFailureCount ?? 0;
  const coverage = signal.evaluationCoverage ?? 1;
  if (failures >= 2 && coverage < 0.8) add("evaluation-data", `a recurring measured failure (${failures}) lacks evaluation coverage (${Math.round(coverage * 100)}%)`);
  if (trainingEnabled && failures >= 3 && signal.gradientFreeTried === true && (signal.residualFailureRate ?? 0) >= 0.15 &&
    (signal.verifiedExampleCount ?? 0) >= 500 && signal.verifiableRewardAvailable === true && signal.narrowStableTask === true) {
    add("training", "a narrow recurring failure persists after gradient-free remedies with verified data and reward");
  }
  return out;
}
function fairOrder(proposals: readonly NeedProposal[], cycle: number): NeedProposal[] {
  const queues = new Map<string, NeedProposal[]>();
  for (const proposal of proposals) {
    const scope = scopeOf(proposal); const queue = queues.get(scope) ?? [];
    queue.push(proposal); queues.set(scope, queue);
  }
  for (const queue of queues.values()) queue.sort(proposalOrder);
  const scopes = [...queues.keys()].sort();
  const offset = scopes.length === 0 ? 0 : (cycle - 1) % scopes.length;
  const rotated = [...scopes.slice(offset), ...scopes.slice(0, offset)];
  const out: NeedProposal[] = [];
  let remaining = true;
  while (remaining) {
    remaining = false;
    for (const scope of rotated) { const next = queues.get(scope)?.shift(); if (next !== undefined) { out.push(next); remaining = true; } }
  }
  return out;
}
function proposalOrder(a: NeedProposal, b: NeedProposal): number { return b.priority - a.priority || a.id.localeCompare(b.id); }
function sameProposal(a: NeedProposal, b: NeedProposal): boolean {
  return a.id === b.id && a.signalId === b.signalId && a.kind === b.kind && a.subject === b.subject && a.scopeId === b.scopeId &&
    a.goal === b.goal && a.reason === b.reason && a.priority === b.priority && a.requiresOptIn === b.requiresOptIn;
}
function scopeOf(value: { readonly scopeId?: string }): string { return value.scopeId === undefined ? N1_SCOPE : tenantScope(value.scopeId); }
function tenantScope(id: string): string { return `tenant:${id}`; }
function tenantIdOf(scope: string): string { return scope.slice("tenant:".length); }
function proposalId(scope: string, kind: NeedKind, subject: string): string {
  const prefix = scope === N1_SCOPE ? "" : `scope:${encodeURIComponent(tenantIdOf(scope))}:`;
  return `${prefix}${kind}:${encodeURIComponent(subject)}`;
}
function positiveInt(value: number | undefined, fallback: number): number { return value !== undefined && Number.isSafeInteger(value) && value > 0 ? value : fallback; }
function nonNegativeInt(value: number | undefined, fallback: number): number { return value !== undefined && Number.isSafeInteger(value) && value >= 0 ? value : fallback; }
function validCycle(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0; }
function wellFormed(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const n = value.charCodeAt(++i); if (!(n >= 0xdc00 && n <= 0xdfff)) return false; }
    else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}
function validText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value) && wellFormed(value);
}
function normalizedFreeText(value: unknown, max: number): string | undefined {
  if (typeof value !== "string" || !wellFormed(value)) return undefined;
  const normalized = value.replace(/[\t\r\n ]+/gu, " ").trim();
  return normalized.length > 0 && normalized.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(normalized)
    ? normalized : undefined;
}
function validTenant(value: unknown): value is string { return validText(value, 256); }
function validScopeKey(value: unknown): value is string { return value === N1_SCOPE || (typeof value === "string" && value.startsWith("tenant:") && validTenant(value.slice(7))); }
function inertArray(value: readonly NeedSignal[]): NeedSignal[] {
  try {
    if (!Array.isArray(value) || value.length > MAX_SIGNALS_PER_CYCLE) return [];
    const descriptors = Object.getOwnPropertyDescriptors(value); const out: NeedSignal[] = [];
    for (let i = 0; i < value.length; i++) { const d = descriptors[String(i)]; if (d === undefined || !("value" in d)) return []; out.push(d.value as NeedSignal); }
    return out;
  } catch { return []; }
}
function dataRecord(value: unknown): Record<string, unknown> | undefined {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value); const out: Record<string, unknown> = {};
    for (const [key, d] of Object.entries(descriptors)) { if (!("value" in d)) return undefined; out[key] = d.value; }
    return out;
  } catch { return undefined; }
}
function optionalBoolean(v: unknown): v is boolean | undefined { return v === undefined || typeof v === "boolean"; }
function optionalRate(v: unknown): v is number | undefined { return v === undefined || (typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1); }
function optionalCount(v: unknown): v is number | undefined { return v === undefined || (Number.isSafeInteger(v) && (v as number) >= 0); }
function inertSignal(value: unknown): NeedSignal | undefined {
  const v = dataRecord(value);
  const goal = normalizedFreeText(v?.goal, 4096); const subject = normalizedFreeText(v?.subject, 512);
  if (v === undefined || !validText(v.id, 512) || goal === undefined || subject === undefined ||
    !(v.scopeId === undefined || validTenant(v.scopeId)) || !optionalBoolean(v.currentKnowledgeMissing) ||
    !optionalBoolean(v.projectEvidenceMissing) || !optionalBoolean(v.repeatedSuccessfulProcedure) ||
    !optionalCount(v.measuredFailureCount) || !optionalRate(v.evaluationCoverage) || !optionalBoolean(v.gradientFreeTried) ||
    !optionalRate(v.residualFailureRate) || !optionalCount(v.verifiedExampleCount) ||
    !optionalBoolean(v.verifiableRewardAvailable) || !optionalBoolean(v.narrowStableTask)) return undefined;
  return { id: v.id, goal, subject, ...(v.scopeId === undefined ? {} : { scopeId: v.scopeId }),
    ...(v.currentKnowledgeMissing === undefined ? {} : { currentKnowledgeMissing: v.currentKnowledgeMissing }),
    ...(v.projectEvidenceMissing === undefined ? {} : { projectEvidenceMissing: v.projectEvidenceMissing }),
    ...(v.repeatedSuccessfulProcedure === undefined ? {} : { repeatedSuccessfulProcedure: v.repeatedSuccessfulProcedure }),
    ...(v.measuredFailureCount === undefined ? {} : { measuredFailureCount: v.measuredFailureCount as number }),
    ...(v.evaluationCoverage === undefined ? {} : { evaluationCoverage: v.evaluationCoverage as number }),
    ...(v.gradientFreeTried === undefined ? {} : { gradientFreeTried: v.gradientFreeTried }),
    ...(v.residualFailureRate === undefined ? {} : { residualFailureRate: v.residualFailureRate as number }),
    ...(v.verifiedExampleCount === undefined ? {} : { verifiedExampleCount: v.verifiedExampleCount as number }),
    ...(v.verifiableRewardAvailable === undefined ? {} : { verifiableRewardAvailable: v.verifiableRewardAvailable }),
    ...(v.narrowStableTask === undefined ? {} : { narrowStableTask: v.narrowStableTask }) };
}
function inertOutcome(value: unknown, bindings: WeakMap<object, ScopeGrant>): { solveId: string; taskShape: string; testsPassed: boolean; scope: string } | undefined {
  const v = dataRecord(value);
  if (v === undefined || !validText(v.solveId, 512) || !validText(v.taskShape, 512) || typeof v.testsPassed !== "boolean") return undefined;
  if (v.scopeId === undefined && v.scopeToken === undefined) return { solveId: v.solveId, taskShape: v.taskShape, testsPassed: v.testsPassed, scope: N1_SCOPE };
  if (!validTenant(v.scopeId) || v.scopeToken === null || typeof v.scopeToken !== "object") return undefined;
  const grant = bindings.get(v.scopeToken);
  if (grant === undefined || !grant.authorization.authorize(grant.principal, "change.solve").allow) return undefined;
  return grant.scope === tenantScope(v.scopeId)
    ? { solveId: v.solveId, taskShape: v.taskShape, testsPassed: v.testsPassed, scope: grant.scope } : undefined;
}
function canonicalProposal(value: unknown): NeedProposal | undefined {
  const v = dataRecord(value);
  if (v === undefined || !validText(v.id, 4096) || !validText(v.signalId, 1024) || !validText(v.subject, 512) ||
    !validText(v.goal, 4096) || !validText(v.reason, 4096) || !(v.scopeId === undefined || validTenant(v.scopeId)) ||
    !["research", "rag", "skill", "evaluation-data", "training"].includes(String(v.kind))) return undefined;
  const kind = v.kind as NeedKind; const scope = v.scopeId === undefined ? N1_SCOPE : tenantScope(v.scopeId);
  if (v.id !== proposalId(scope, kind, v.subject) || v.priority !== PRIORITY[kind] || v.requiresOptIn !== (kind === "training")) return undefined;
  return { id: v.id, signalId: v.signalId, kind, subject: v.subject,
    ...(v.scopeId === undefined ? {} : { scopeId: v.scopeId }), goal: v.goal, reason: v.reason,
    priority: PRIORITY[kind], requiresOptIn: kind === "training" };
}
function canonicalProposalArray(value: unknown): NeedProposal[] {
  if (!Array.isArray(value) || value.length > MAX_SIGNALS_PER_CYCLE) return [];
  const out: NeedProposal[] = [];
  for (const item of value) { const proposal = canonicalProposal(item); if (proposal !== undefined) out.push(proposal); }
  return out;
}
function canonicalIdArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_SIGNALS_PER_CYCLE * 5) return [];
  const out: string[] = [];
  for (const item of value) if (validText(item, 4096)) out.push(item);
  return out;
}
function evictionReceipt(ids: readonly string[]): { readonly count: number; readonly idDigest: string } | undefined {
  if (ids.length === 0) return undefined;
  const idDigest = createHash("sha256").update([...ids].sort().join("\u0000"), "utf8").digest("hex");
  return { count: ids.length, idDigest };
}
