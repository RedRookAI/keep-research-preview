import type { Spine } from "../spine/spine.js";
import { randomUUID } from "node:crypto";
import { concurrencyGovernor, type ConcurrencyPolicy } from "../autonomy/project_loop.js";
import type { StagedEvent } from "../spine/event.js";
import { isProjectId, type ProjectId } from "./project_id.js";

export type ProjectJobIntentState = "queued" | "running" | "stopped" | "reconciliation-required" | "completed" | "failed";
export interface ProjectJobIntent {
  readonly id: string;
  readonly projectId: ProjectId;
  readonly workspaceKey: string;
  readonly weight: number;
  readonly label: string;
  readonly ownerId: string;
  readonly leaseUntil: number;
  readonly state: ProjectJobIntentState;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly reason?: string;
  readonly commandDigest?: string;
  readonly exclusiveResource?: string;
  /** Derived from a durable request, not evidence that the backend has stopped. */
  readonly cancellationRequested?: true;
  /** Unresolved owned local port calls; expiry is not evidence that they stopped. */
  readonly activeActivityIds?: readonly string[];
}
export type ProjectJobActivityTracker = <T>(label: string, run: () => Promise<T>) => Promise<T>;
export interface ProjectJobActivity {
  readonly id: string; readonly jobId: string; readonly ownerId: string; readonly label: string;
  readonly startedAt: number; readonly state: "running" | "settled"; readonly settledAt?: number;
}
export interface ProjectJobJournal {
  load(): readonly ProjectJobIntent[];
  append(intent: ProjectJobIntent): void;
  /** Renew every live job owned by one runtime with one durable event. */
  renew(ownerId: string, intentIds: readonly string[], updatedAt: number, leaseUntil: number): void;
  /** Atomic durable reservation. Omission refuses idempotent dispatch; no volatile fallback. */
  reserveSubmission?(submission: ProjectJobSubmission): Promise<{ readonly created: boolean; readonly submission: ProjectJobSubmission }>;
  requestCancellation?(jobId: string): Promise<boolean>;
  activities?(jobId: string): readonly ProjectJobActivity[];
  beginActivity?(activity: ProjectJobActivity): Promise<void>;
  settleActivity?(activityId: string, ownerId: string, settledAt: number): Promise<void>;
  /** Atomically reserve shared capacity and callback ownership before dispatch. */
  tryDispatch?(jobId: string, ownerId: string, policy: ConcurrencyPolicy, now: number, leaseUntil: number): Promise<ProjectJobActivity | undefined>;
  reclaimQueued?(jobId: string, commandDigest: string, ownerId: string, now: number, leaseUntil: number): Promise<ProjectJobIntent | undefined>;
}

/** Digests are derived by a trusted ingress from authenticated caller scope and exact request.
 * No raw request, credentials, or caller key is retained in the public job history. */
export interface ProjectJobSubmission { readonly keyDigest: string; readonly requestDigest: string; readonly jobId: string; }
export class ProjectSubmissionConflictError extends Error { override readonly name = "ProjectSubmissionConflictError"; }
const SUBMISSION_EVENT = "project.job.submission";
function decodeSubmission(value: Record<string, unknown>): ProjectJobSubmission {
  const { keyDigest, requestDigest, jobId } = value;
  if (Object.keys(value).sort().join(",") !== "event,jobId,keyDigest,requestDigest"
    || typeof keyDigest !== "string" || !/^[0-9a-f]{64}$/u.test(keyDigest)
    || typeof requestDigest !== "string" || !/^[0-9a-f]{64}$/u.test(requestDigest)
    || typeof jobId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(jobId)) throw new Error("invalid project submission reservation");
  return { keyDigest, requestDigest, jobId };
}

const EVENT = "project.job.intent";
const HEARTBEAT_EVENT = "project.job.heartbeat";
const CANCEL_EVENT = "project.job.cancel-requested";
const ACTIVITY_EVENT = "project.job.activity";
const DISPATCH_EVENT = "project.job.dispatch";
const RECLAIM_EVENT = "project.job.reclaimed";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function decodeActivity(value: Record<string, unknown>): ProjectJobActivity {
  const { id, jobId, ownerId, label, startedAt, state, settledAt } = value;
  const keys = state === "running" ? "event,id,jobId,label,ownerId,startedAt,state" : "event,id,jobId,label,ownerId,settledAt,startedAt,state";
  if (Object.keys(value).sort().join(",") !== keys || typeof id !== "string" || !UUID.test(id)
    || typeof jobId !== "string" || !UUID.test(jobId) || typeof ownerId !== "string" || ownerId.length < 1 || Buffer.byteLength(ownerId) > 256
    || typeof label !== "string" || !/^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$/u.test(label)
    || !Number.isSafeInteger(startedAt) || (startedAt as number) < 0 || (state !== "running" && state !== "settled")
    || (state === "settled" && (!Number.isSafeInteger(settledAt) || (settledAt as number) < (startedAt as number)))) throw new Error("invalid project activity");
  return { id, jobId, ownerId, label, startedAt: startedAt as number, state, ...(state === "settled" ? { settledAt: settledAt as number } : {}) };
}
const MAX_HEARTBEAT_INTENTS = 4096;
const STATES = new Set<ProjectJobIntentState>(["queued", "running", "stopped", "reconciliation-required", "completed", "failed"]);
const ALLOWED: Readonly<Record<ProjectJobIntentState, ReadonlySet<ProjectJobIntentState>>> = {
  queued: new Set(["queued", "running", "stopped", "failed"]),
  running: new Set(["running", "completed", "failed", "reconciliation-required"]),
  stopped: new Set(),
  "reconciliation-required": new Set(),
  completed: new Set(),
  failed: new Set(),
};

function decode(value: Record<string, unknown>): ProjectJobIntent {
  const { id, projectId, workspaceKey, weight, label, ownerId: rawOwnerId, leaseUntil: rawLeaseUntil, state, createdAt, updatedAt, reason } = value;
  const commandDigest = value["commandDigest"];
  const exclusiveResource = value["exclusiveResource"];
  if (exclusiveResource !== undefined && (typeof exclusiveResource !== "string" || !/^[0-9a-f]{64}$/u.test(exclusiveResource))) throw new Error("invalid project resource identity");
  if (commandDigest !== undefined && (typeof commandDigest !== "string" || !/^[0-9a-f]{64}$/u.test(commandDigest))) throw new Error("invalid project command digest");
  const fields = Object.keys(value).filter((key) => key !== "event" && key !== "commandDigest" && key !== "exclusiveResource").sort().join(",");
  const expected = reason === undefined ? "createdAt,id,label,leaseUntil,ownerId,projectId,state,updatedAt,weight,workspaceKey" : "createdAt,id,label,leaseUntil,ownerId,projectId,reason,state,updatedAt,weight,workspaceKey";
  const legacy = reason === undefined ? "createdAt,id,label,projectId,state,updatedAt,weight,workspaceKey" : "createdAt,id,label,projectId,reason,state,updatedAt,weight,workspaceKey";
  const isLegacy = fields === legacy;
  const ownerId = isLegacy ? "legacy-unleased" : rawOwnerId;
  const leaseUntil = isLegacy ? updatedAt : rawLeaseUntil;
  if ((!isLegacy && fields !== expected) || typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id)
    || typeof projectId !== "string" || !isProjectId(projectId) || workspaceKey !== `project/${projectId}`
    || typeof weight !== "number" || !Number.isFinite(weight) || weight <= 0
    || typeof label !== "string" || label.length < 1 || Buffer.byteLength(label, "utf8") > 1024
    || typeof ownerId !== "string" || ownerId.length < 1 || Buffer.byteLength(ownerId, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(ownerId)
    || typeof state !== "string" || !STATES.has(state as ProjectJobIntentState)
    || !Number.isSafeInteger(createdAt) || (createdAt as number) < 0 || !Number.isSafeInteger(updatedAt) || (updatedAt as number) < (createdAt as number)
    || !Number.isSafeInteger(leaseUntil) || (leaseUntil as number) < (updatedAt as number)
    || (reason !== undefined && (typeof reason !== "string" || Buffer.byteLength(reason, "utf8") > 4096))) throw new Error("invalid project job intent");
  return { id, projectId, workspaceKey, weight, label, ownerId, leaseUntil: leaseUntil as number, state: state as ProjectJobIntentState, createdAt: createdAt as number, updatedAt: updatedAt as number, ...(typeof reason === "string" ? { reason } : {}), ...(typeof commandDigest === "string" ? { commandDigest } : {}), ...(typeof exclusiveResource === "string" ? { exclusiveResource } : {}) };
}

function validateTransition(prior: ProjectJobIntent, intent: ProjectJobIntent): boolean {
  if (intent.projectId !== prior.projectId || intent.workspaceKey !== prior.workspaceKey || intent.weight !== prior.weight || intent.ownerId !== prior.ownerId
    || intent.label !== prior.label || intent.createdAt !== prior.createdAt || intent.commandDigest !== prior.commandDigest || intent.exclusiveResource !== prior.exclusiveResource) throw new Error(`project job ${intent.id} changed immutable identity`);
  if (intent.updatedAt < prior.updatedAt) throw new Error(`project job ${intent.id} moved backward in time`);
  if (intent.leaseUntil < prior.leaseUntil) throw new Error(`project job ${intent.id} shortened its owner lease`);
  if (JSON.stringify(intent) === JSON.stringify(prior)) return false;
  if (intent.state === prior.state && (prior.state === "stopped" || prior.state === "reconciliation-required" || prior.state === "completed" || prior.state === "failed")) return false;
  if (!ALLOWED[prior.state].has(intent.state)) throw new Error(`invalid project job transition ${prior.state} -> ${intent.state}`);
  return true;
}

interface ProjectJobHeartbeat { readonly ownerId: string; readonly intentIds: readonly string[]; readonly updatedAt: number; readonly leaseUntil: number; }
function decodeHeartbeat(value: Record<string, unknown>): ProjectJobHeartbeat {
  const { ownerId, intentIds, updatedAt, leaseUntil } = value;
  if (Object.keys(value).sort().join(",") !== "event,intentIds,leaseUntil,ownerId,updatedAt"
    || typeof ownerId !== "string" || ownerId.length < 1 || Buffer.byteLength(ownerId, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(ownerId)
    || !Array.isArray(intentIds) || intentIds.length < 1 || intentIds.length > MAX_HEARTBEAT_INTENTS
    || intentIds.some((id) => typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id))
    || new Set(intentIds).size !== intentIds.length
    || !Number.isSafeInteger(updatedAt) || (updatedAt as number) < 0
    || !Number.isSafeInteger(leaseUntil) || (leaseUntil as number) < (updatedAt as number)) throw new Error("invalid project job heartbeat");
  return { ownerId, intentIds: [...intentIds] as string[], updatedAt: updatedAt as number, leaseUntil: leaseUntil as number };
}

/** Durable append-only metadata journal. Callback code, arguments, outputs, and secrets are never stored. */
export class SpineProjectJobJournal implements ProjectJobJournal {
  private readonly latest = new Map<string, ProjectJobIntent>();
  private readonly cancellations = new Set<string>();
  private readonly activityRows = new Map<string, ProjectJobActivity>();
  private readonly dispatchPolicies = new Map<string, ConcurrencyPolicy>();
  private foldedEvents = 0;
  private lastFoldedEventId: string | undefined;
  constructor(private readonly spine: Spine) {
    if (!spine.durableStorage()) throw new Error("project job journal requires durable spine storage");
  }
  async reserveSubmission(submission: ProjectJobSubmission): Promise<{ readonly created: boolean; readonly submission: ProjectJobSubmission }> {
    const decoded = decodeSubmission({ event: SUBMISSION_EVENT, ...submission });
    return this.spine.withStableEventView(events => {
      let prior: ProjectJobSubmission | undefined;
      for (const event of events) {
        const value = event.payload as Record<string, unknown>;
        if (event.actor !== "project-runtime" || value["event"] !== SUBMISSION_EVENT) continue;
        // A malformed reservation must not be ignored and then dispatched anew.
        const row = decodeSubmission(value);
        if (row.keyDigest !== decoded.keyDigest) continue;
        if (prior !== undefined && (row.jobId !== prior.jobId || row.requestDigest !== prior.requestDigest)) throw new ProjectSubmissionConflictError("project submission history conflicts; reconciliation required");
        prior = row;
      }
      if (prior !== undefined) {
        if (prior.requestDigest !== decoded.requestDigest) throw new ProjectSubmissionConflictError("idempotency key already belongs to a different request");
        return { created: false, submission: prior };
      }
      this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: SUBMISSION_EVENT, ...decoded } });
      return { created: true, submission: decoded };
    });
  }
  load(): readonly ProjectJobIntent[] {
    return this.fold(this.spine.currentEvents());
  }
  private fold(events: readonly StagedEvent[]): readonly ProjectJobIntent[] {
    // Spine is append-only. Reset defensively if an adapter ever presents a shorter view; under
    // normal operation each durable event is validated and folded exactly once.
    if (events.length < this.foldedEvents || (this.foldedEvents > 0 && events[this.foldedEvents - 1]?.id !== this.lastFoldedEventId)) {
      this.latest.clear(); this.cancellations.clear(); this.activityRows.clear(); this.dispatchPolicies.clear(); this.foldedEvents = 0; this.lastFoldedEventId = undefined;
    }
    for (let index = this.foldedEvents; index < events.length; index++) {
      const event = events[index]!;
      const value = event.payload as Record<string, unknown>;
      if (event.actor !== "project-runtime") continue;
      if (value["event"] === EVENT) {
        try {
          const intent = decode(value); const prior = this.latest.get(intent.id);
          if (prior === undefined) { if (intent.state === "queued") this.latest.set(intent.id, intent); }
          else {
            try { if (validateTransition(prior, intent)) this.latest.set(intent.id, intent); }
            catch (error) { this.latest.set(prior.id, { ...prior, state: "reconciliation-required", updatedAt: Math.max(prior.updatedAt, intent.updatedAt), leaseUntil: Math.max(prior.leaseUntil, intent.leaseUntil), reason: `job journal conflict: ${(error as Error).message}` }); }
          }
        } catch { /* malformed runtime event is isolated from valid jobs */ }
      } else if (value["event"] === RECLAIM_EVENT) {
        const raw = value["intent"];
        if (Object.keys(value).sort().join(",") !== "event,intent,priorOwnerId" || !raw || typeof raw !== "object") throw new Error("invalid queued reclaim");
        const intent = decode(raw as Record<string, unknown>), prior = this.latest.get(intent.id);
        if (prior && JSON.stringify(prior) === JSON.stringify(intent)) continue;
        if (!prior || prior.ownerId !== value["priorOwnerId"] || prior.state !== "queued" || intent.state !== "queued"
          || prior.commandDigest === undefined || prior.leaseUntil > intent.updatedAt || this.cancellations.has(intent.id)
          || this.hasDispatch(intent.id) || !validateTransition({ ...prior, ownerId: intent.ownerId }, intent)) throw new Error("queued reclaim has no never-dispatched authority");
        this.latest.set(intent.id, intent);
      } else if (value["event"] === DISPATCH_EVENT) {
        const { intent: rawIntent, activity: rawActivity, policy } = value;
        if (Object.keys(value).sort().join(",") !== "activity,event,intent,policy" || !rawIntent || typeof rawIntent !== "object" || !rawActivity || typeof rawActivity !== "object" || !policy || typeof policy !== "object") throw new Error("invalid project dispatch");
        const intent = decode({ event: EVENT, ...rawIntent as Record<string, unknown> });
        const activity = decodeActivity({ event: ACTIVITY_EVENT, ...rawActivity as Record<string, unknown> });
        const p = policy as ConcurrencyPolicy;
        if (Object.keys(p).sort().join(",") !== "aggregateCeiling,perProjectShare" || concurrencyGovernor([], { project: intent.projectId, weight: intent.weight }, p).verdict === "denied"
          || activity.jobId !== intent.id || activity.ownerId !== intent.ownerId || activity.label !== "job-callback" || activity.state !== "running" || intent.state !== "running" || activity.startedAt !== intent.updatedAt) throw new Error("invalid project dispatch ownership/policy");
        if (this.activityRows.has(activity.id)) continue; // interrupted seal duplicate, never dispatch again
        const prior = this.latest.get(intent.id);
        if (prior === undefined || prior.state !== "queued" || this.cancellations.has(intent.id) || !validateTransition(prior, intent)) throw new Error("project dispatch is not a queued-to-running claim");
        this.latest.set(intent.id, intent); this.activityRows.set(activity.id, activity); this.dispatchPolicies.set(intent.id, { ...p });
      } else if (value["event"] === ACTIVITY_EVENT) {
        // A malformed/missing ownership record cannot silently free capacity.
        const activity = decodeActivity(value), job = this.latest.get(activity.jobId), prior = this.activityRows.get(activity.id);
        if (job?.ownerId !== activity.ownerId) throw new Error("project activity has no matching job owner");
        if (prior === undefined) {
          if (activity.state !== "running") throw new Error("project activity has no start record");
          this.activityRows.set(activity.id, activity);
        } else {
          if (prior.jobId !== activity.jobId || prior.ownerId !== activity.ownerId || prior.label !== activity.label || prior.startedAt !== activity.startedAt) throw new Error("project activity identity changed");
          if (activity.state === "settled") this.activityRows.set(activity.id, activity);
          // A duplicated start (e.g. an interrupted seal cursor) never reopens a settled call.
        }
      } else if (value["event"] === CANCEL_EVENT) {
        if (Object.keys(value).sort().join(",") === "event,jobId" && typeof value["jobId"] === "string" && this.latest.has(value["jobId"])) this.cancellations.add(value["jobId"]);
      } else if (value["event"] === HEARTBEAT_EVENT) {
        try {
          const heartbeat = decodeHeartbeat(value);
          for (const id of heartbeat.intentIds) {
            const prior = this.latest.get(id);
            if (prior !== undefined && prior.ownerId === heartbeat.ownerId && (prior.state === "queued" || prior.state === "running")
              && heartbeat.updatedAt >= prior.updatedAt && heartbeat.leaseUntil >= prior.leaseUntil) this.latest.set(id, { ...prior, updatedAt: heartbeat.updatedAt, leaseUntil: heartbeat.leaseUntil });
          }
        } catch { /* malformed heartbeat is isolated from valid jobs */ }
      }
    }
    this.foldedEvents = events.length;
    this.lastFoldedEventId = events.at(-1)?.id;
    const active = new Map<string, string[]>();
    for (const activity of this.activityRows.values()) if (activity.state === "running") {
      const ids = active.get(activity.jobId) ?? []; ids.push(activity.id); active.set(activity.jobId, ids);
    }
    return [...this.latest.values()].map((intent) => ({ ...intent,
      ...(this.cancellations.has(intent.id) ? { cancellationRequested: true as const } : {}),
      ...(active.has(intent.id) ? { activeActivityIds: active.get(intent.id)! } : {}),
    }));
  }
  activities(jobId: string): readonly ProjectJobActivity[] {
    this.load(); return [...this.activityRows.values()].filter(activity => activity.jobId === jobId).map(activity => ({ ...activity }));
  }
  private hasDispatch(jobId: string): boolean {
    return this.dispatchPolicies.has(jobId) || [...this.activityRows.values()].some(activity => activity.jobId === jobId);
  }
  async reclaimQueued(jobId: string, commandDigest: string, ownerId: string, now: number, leaseUntil: number): Promise<ProjectJobIntent | undefined> {
    return this.spine.withStableEventView(events => {
      const prior = this.fold(events).find(job => job.id === jobId);
      if (!prior || prior.state !== "queued" || prior.commandDigest !== commandDigest || prior.cancellationRequested || prior.leaseUntil > now || this.hasDispatch(jobId)) return undefined;
      const { cancellationRequested: _cancel, activeActivityIds: _ids, ...record } = prior;
      const intent = decode({ ...record, ownerId, updatedAt: now, leaseUntil });
      validateTransition({ ...prior, ownerId }, intent);
      this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: RECLAIM_EVENT, priorOwnerId: prior.ownerId, intent } });
      return intent;
    });
  }
  async tryDispatch(jobId: string, ownerId: string, policy: ConcurrencyPolicy, now: number, leaseUntil: number): Promise<ProjectJobActivity | undefined> {
    return this.spine.withStableEventView(events => {
      const jobs = this.fold(events), prior = jobs.find(job => job.id === jobId);
      if (prior === undefined || prior.ownerId !== ownerId || prior.state !== "queued" || prior.cancellationRequested || prior.leaseUntil <= now) throw new Error("project dispatch requires a live owned uncancelled queued job");
      const running = jobs.filter(job => (job.activeActivityIds?.length ?? 0) > 0 || job.state === "running");
      if (running.some(job => (prior.exclusiveResource !== undefined || job.exclusiveResource !== undefined)
        && (prior.exclusiveResource === undefined || job.exclusiveResource === undefined || prior.exclusiveResource === job.exclusiveResource))) return undefined;
      for (const job of running) {
        const established = this.dispatchPolicies.get(job.id);
        if (established && (established.aggregateCeiling !== policy.aggregateCeiling || established.perProjectShare !== policy.perProjectShare)) throw new Error("project dispatch policy conflicts with active shared capacity");
      }
      const decision = concurrencyGovernor(running.map(job => ({ project: job.projectId, weight: job.weight })), { project: prior.projectId, weight: prior.weight }, policy);
      if (decision.verdict === "denied") throw new Error(decision.reason);
      if (decision.verdict === "queued") return undefined;
      const { cancellationRequested: _cancel, activeActivityIds: _ids, ...record } = prior;
      const intent = decode({ event: EVENT, ...record, state: "running", updatedAt: now, leaseUntil });
      validateTransition(prior, intent);
      const activity = decodeActivity({ event: ACTIVITY_EVENT, id: randomUUID(), jobId, ownerId, label: "job-callback", state: "running", startedAt: now });
      // One durable append: no crash window between taking capacity and owning the callback.
      this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: DISPATCH_EVENT, intent, activity, policy: { aggregateCeiling: policy.aggregateCeiling, perProjectShare: policy.perProjectShare } } });
      return activity;
    });
  }
  async beginActivity(activity: ProjectJobActivity): Promise<void> {
    const row = decodeActivity({ event: ACTIVITY_EVENT, ...activity });
    if (row.state !== "running") throw new Error("activity must begin running");
    await this.spine.withStableEventView(events => {
      const job = this.fold(events).find(intent => intent.id === row.jobId);
      if (job?.ownerId !== row.ownerId || job.state !== "running" || job.cancellationRequested) throw new Error("activity job is not owned, running and uncancelled");
      if (this.activityRows.has(row.id)) throw new Error("project activity identity was already used");
      if ((job.activeActivityIds?.length ?? 0) >= 256) throw new Error("project activity capacity exhausted");
      this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: ACTIVITY_EVENT, ...row } });
    });
  }
  async settleActivity(activityId: string, ownerId: string, settledAt: number): Promise<void> {
    await this.spine.withStableEventView(events => {
      this.fold(events);
      const prior = this.activityRows.get(activityId);
      if (prior === undefined || prior.ownerId !== ownerId) throw new Error("project activity settlement owner mismatch");
      if (prior.state === "settled") return;
      const row = decodeActivity({ event: ACTIVITY_EVENT, ...prior, state: "settled", settledAt });
      this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: ACTIVITY_EVENT, ...row } });
    });
  }
  async requestCancellation(jobId: string): Promise<boolean> {
    return this.spine.withStableEventView(events => {
      const prior = this.fold(events).find(intent => intent.id === jobId);
      if (prior === undefined) return false;
      if (prior.cancellationRequested || !["queued", "running"].includes(prior.state)) return true;
      this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: CANCEL_EVENT, jobId } });
      return true;
    });
  }
  append(intent: ProjectJobIntent): void {
    // This flag is a projection of cancel-requested events, never supplied authority.
    const { cancellationRequested: _requested, activeActivityIds: _activities, ...record } = intent;
    const decoded = decode({ event: EVENT, ...record });
    const prior = this.load().find((row) => row.id === decoded.id);
    if (prior === undefined) {
      if (decoded.state !== "queued") throw new Error(`project job ${decoded.id} does not begin queued`);
    } else if (!validateTransition(prior, decoded)) return;
    this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: EVENT, ...decoded } });
  }
  renew(ownerId: string, intentIds: readonly string[], updatedAt: number, leaseUntil: number): void {
    if (intentIds.length === 0) return;
    const heartbeat = decodeHeartbeat({ event: HEARTBEAT_EVENT, ownerId, intentIds: [...intentIds].sort(), updatedAt, leaseUntil });
    this.spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: HEARTBEAT_EVENT, ...heartbeat } });
  }
}
