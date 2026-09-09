import { randomUUID } from "node:crypto";
import { concurrencyGovernor, type ConcurrencyPolicy, type RunningEntry } from "../autonomy/project_loop.js";
import type { ProjectId } from "./project_id.js";
import type { ProjectJobIntent, ProjectJobJournal, ProjectJobIntentState, ProjectJobSubmission, ProjectJobActivity, ProjectJobActivityTracker } from "./project_job_journal.js";
import { ProjectSessionManager } from "./project_session_manager.js";
import { commandDocumentName, decodeProjectCommand, encodeProjectCommand, type NativeProjectCommand } from "./project_command.js";
import { GOAL_WORK_DOCUMENT, GOAL_PHASES, captureGoalWorkDefinition, decodeGoalWork, selectGoalWork,
  type GoalWorkDocument, type GoalTaskAcceptance, type GoalWorkPhase } from "./project_goal_work.js";

export interface ProjectJobContext { readonly jobId: string; readonly projectId: ProjectId; readonly workspaceKey: string; readonly signal: AbortSignal; readonly trackActivity: ProjectJobActivityTracker; }
export interface TrackedProjectJob<T> { readonly jobId: string; readonly completion: Promise<T>; }
interface QueuedJob<T> {
  readonly intentId: string; readonly projectId: ProjectId; readonly weight: number;
  readonly run: (context: ProjectJobContext) => Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void; readonly reject: (reason?: unknown) => void;
}
export class ProjectJobReconciliationError extends Error { override readonly name = "ProjectJobReconciliationError"; }
export class ProjectJobCancelledError extends Error { override readonly name = "ProjectJobCancelledError"; }
export class ProjectSubmissionUncertainError extends ProjectJobReconciliationError {
  constructor(readonly jobId: string, options?: ErrorOptions) { super("submission was recorded but has no confirmed job; reconcile without resubmitting under a new key", options); }
}

/** Owns bounded concurrent/background project execution on one host. */
export class ProjectRuntime {
  private readonly running = new Map<symbol, RunningEntry & { readonly intentId: string }>();
  private readonly queued: QueuedJob<unknown>[] = [];
  private readonly intents = new Map<string, ProjectJobIntent>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly activityTasks = new Map<string, { readonly jobId: string; readonly promise: Promise<unknown> }>();
  private readonly ownerId: string;
  private readonly leaseMs: number;
  private readonly heartbeatMs: number;
  private heartbeat: NodeJS.Timeout | undefined;
  private dispatchPaused: boolean;
  private recovering: Promise<void> | undefined;
  private readonly recoveryHolds = new Set<string>();
  constructor(
    readonly manager: ProjectSessionManager,
    private readonly policy: ConcurrencyPolicy,
    private readonly journal?: ProjectJobJournal,
    private readonly config: { readonly maxQueuedJobs?: number; readonly now?: () => number; readonly id?: () => string; readonly ownerId?: string; readonly leaseMs?: number; readonly heartbeatMs?: number;
      readonly paused?: boolean; readonly recoverCommands?: boolean;
      readonly commands?: { readonly binding: string; readonly resource?: string; readonly capabilities?: readonly string[];
        readonly observe?: (projectId: ProjectId, jobId: string, expectedGoal: string, expectedContext: string) => GoalTaskAcceptance | undefined;
        readonly validate: (command: NativeProjectCommand, projectId: ProjectId) => void; readonly execute: (command: NativeProjectCommand, context: ProjectJobContext) => Promise<unknown> };
    } = {},
  ) {
    this.ownerId = config.ownerId ?? randomUUID();
    this.dispatchPaused = config.paused ?? false;
    this.leaseMs = config.leaseMs ?? 30_000;
    if (!Number.isSafeInteger(this.leaseMs) || this.leaseMs < 100) throw new Error("project runtime lease must be at least 100 ms");
    for (const intent of journal?.load() ?? []) {
      if ((intent.state === "completed" || intent.state === "failed") && (intent.activeActivityIds?.length ?? 0) > 0) { this.intents.set(intent.id, intent); continue; }
      if (!["queued", "running", "stopped", "reconciliation-required"].includes(intent.state)) continue;
      if (intent.state === "stopped" || intent.state === "reconciliation-required" || intent.leaseUntil > this.now() || (intent.state === "queued" && intent.commandDigest !== undefined)) { this.intents.set(intent.id, intent); continue; }
      const now = this.now();
      const next: ProjectJobIntent = intent.state === "queued"
        ? { ...intent, state: "stopped", updatedAt: now, leaseUntil: Math.max(intent.leaseUntil, now), reason: "queued callback was interrupted and was not restarted" }
        : { ...intent, state: "reconciliation-required", updatedAt: now, leaseUntil: Math.max(intent.leaseUntil, now), reason: "running callback was interrupted; effect outcome is unknown" };
      journal!.append(next);
      this.intents.set(next.id, next);
    }
    this.heartbeatMs = config.heartbeatMs ?? Math.max(50, Math.floor(this.leaseMs / 3));
    if (!Number.isSafeInteger(this.heartbeatMs) || this.heartbeatMs < 25 || this.heartbeatMs >= this.leaseMs) throw new Error("invalid project runtime heartbeat interval");
    if (config.recoverCommands) this.ensureHeartbeat();
  }

  get commandBinding(): string | undefined { return this.config.commands?.binding; }
  /** Read only the original digest/configuration-bound command; caller must still authorize its use. */
  commandForJob(jobId: string, projectId: ProjectId): NativeProjectCommand {
    const intent = this.job(jobId, new Set([projectId]));
    if (!intent) throw new Error("original project command unavailable");
    return this.readCommand(intent);
  }

  get paused(): boolean { return this.dispatchPaused; }
  pauseDispatch(): void { this.dispatchPaused = true; }
  resumeDispatch(): void { this.dispatchPaused = false; this.drain(); void this.recoverQueuedCommands().catch(() => undefined); }

  async createGoalWork(request: Omit<ProjectJobSubmission, "jobId">, definition: unknown, principal: NativeProjectCommand["principal"], active: boolean): Promise<ProjectId> {
    if (!this.journal?.reserveSubmission || !this.config.commands?.resource || !this.config.commands.observe) throw new Error("native goal execution is not composed");
    const captured = captureGoalWorkDefinition(definition);
    const reservation = await this.journal.reserveSubmission({ ...request, jobId: randomUUID() });
    if (!reservation.created) {
      for (const project of this.manager.list().filter(row => row.tenant === principal.tenant)) {
        const doc = this.manager.session(project.id).resolveDocumentVersioned(GOAL_WORK_DOCUMENT);
        if (doc.value !== undefined && decodeGoalWork(doc.value).creationId === reservation.submission.jobId) return project.id;
      }
      throw new ProjectSubmissionUncertainError(reservation.submission.jobId);
    }
    const parent = this.manager.create({ name: "Keep goal", ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }) });
    const d: GoalWorkDocument = { schema: "keep.goal-work/v1", creationId: reservation.submission.jobId, definition: captured,
      binding: this.config.commands.binding, principal, phase: "development", active, startsUsed: 0, claims: {}, accepted: {} };
    this.validateGoalWork(parent.id, d);
    this.manager.session(parent.id).putDocumentVersioned(GOAL_WORK_DOCUMENT, JSON.stringify(d), 0);
    this.ensureHeartbeat();
    return parent.id;
  }
  private loadGoalWork(projectId: ProjectId): { document: GoalWorkDocument; revision: number } {
    const doc = this.manager.session(projectId).resolveDocumentVersioned(GOAL_WORK_DOCUMENT);
    if (doc.value === undefined) throw new Error("goal work not found");
    return { document: decodeGoalWork(doc.value), revision: doc.revision };
  }
  private validateGoalWork(projectId: ProjectId, d: GoalWorkDocument): void {
    if (!this.config.commands?.resource || d.binding !== this.config.commands.binding) throw new Error("goal runtime configuration changed");
    const command: NativeProjectCommand = { binding: d.binding, principal: d.principal, goal: d.definition.objective };
    encodeProjectCommand(command, d.creationId, projectId);
    this.config.commands.validate(command, projectId);
  }
  goalWork(projectId: ProjectId): { projectId: ProjectId; revision: number; document: GoalWorkDocument; selection: ReturnType<typeof selectGoalWork>; tasks: readonly { id: string; status: string }[] } {
    const { document: d, revision } = this.loadGoalWork(projectId);
    const selection = selectGoalWork(d, new Set(this.config.commands?.capabilities ?? []));
    return { projectId, revision, document: d, selection, tasks: d.definition.tasks.map(task => {
      const claim = d.claims[task.id], job = claim === undefined ? undefined : this.job(claim.jobId);
      return { id: task.id, status: d.accepted[task.id] ? "tested-proposal" : claim ? job?.state === "completed" ? "acceptance-unproven" : job?.state ?? "reconciliation-required" : selection.deferred.includes(task.id) ? "deferred" : selection.held[task.id] ? "held" : "ready" };
    }) };
  }
  setGoalWorkControl(projectId: ProjectId, expectedRevision: number, active: boolean, phase: GoalWorkPhase): void {
    const { document: d, revision } = this.loadGoalWork(projectId);
    if (revision !== expectedRevision || !GOAL_PHASES.includes(phase) || GOAL_PHASES.indexOf(phase) < GOAL_PHASES.indexOf(d.phase) || typeof active !== "boolean") throw new Error("stale or invalid goal control");
    this.validateGoalWork(projectId, d);
    this.manager.session(projectId).putDocumentVersioned(GOAL_WORK_DOCUMENT, JSON.stringify({ ...d, active, phase }), revision);
    this.ensureHeartbeat();
  }
  /** CAS claims precede child creation/dispatch. No missing or failed claim is retried. */
  async advanceGoalWork(projectId: ProjectId): Promise<ReturnType<ProjectRuntime["goalWork"]>> {
    let { document: d, revision } = this.loadGoalWork(projectId);
    this.validateGoalWork(projectId, d);
    const accepted = { ...d.accepted };
    for (const [taskId, claim] of Object.entries(d.claims)) {
      if (accepted[taskId] || claim.projectId === undefined) continue;
      const job = this.job(claim.jobId);
      if (job?.state !== "completed" || (job.activeActivityIds?.length ?? 0) > 0) continue;
      const task = d.definition.tasks.find(t => t.id === taskId)!;
      const evidence = this.config.commands!.observe?.(claim.projectId, claim.jobId, task.goal, d.definition.objective);
      if (evidence !== undefined) accepted[taskId] = evidence;
    }
    if (Object.keys(accepted).length !== Object.keys(d.accepted).length) {
      d = { ...d, accepted }; decodeGoalWork(JSON.stringify(d));
      revision = this.manager.session(projectId).putDocumentVersioned(GOAL_WORK_DOCUMENT, JSON.stringify(d), revision);
    }
    if (this.dispatchPaused || !d.active || Object.values(d.claims).some(c => {
      const job = this.job(c.jobId); return job?.state === "queued" || job?.state === "running" || (job?.activeActivityIds?.length ?? 0) > 0;
    })) return this.goalWork(projectId);
    const selected = selectGoalWork(d, new Set(this.config.commands?.capabilities ?? [])).selected;
    if (!selected) return this.goalWork(projectId);
    const task = d.definition.tasks.find(t => t.id === selected)!, jobId = randomUUID();
    d = { ...d, startsUsed: d.startsUsed + 1, claims: { ...d.claims, [selected]: { jobId } } };
    revision = this.manager.session(projectId).putDocumentVersioned(GOAL_WORK_DOCUMENT, JSON.stringify(d), revision);
    const child = this.manager.create({ name: "Keep goal task", ...(d.principal.tenant === undefined ? {} : { tenant: d.principal.tenant }) });
    d = { ...d, claims: { ...d.claims, [selected]: { jobId, projectId: child.id } } };
    this.manager.session(projectId).putDocumentVersioned(GOAL_WORK_DOCUMENT, JSON.stringify(d), revision);
    const command: NativeProjectCommand = { binding: d.binding, principal: d.principal, goal: task.goal, goalContext: d.definition.objective };
    const tracked = this.enqueueTracked(child.id, 1, async () => undefined, "goal task", jobId, command);
    void tracked.completion.finally(() => {
      if (this.config.recoverCommands) void this.advanceGoalWork(projectId).catch(() => undefined);
    }).catch(() => undefined);
    this.ensureHeartbeat(); return this.goalWork(projectId);
  }
  private async advanceGoals(): Promise<void> {
    if (!this.config.recoverCommands || this.dispatchPaused) return;
    for (const project of this.manager.list()) {
      try {
        const doc = this.manager.session(project.id).resolveDocumentVersioned(GOAL_WORK_DOCUMENT);
        if (doc.value !== undefined && decodeGoalWork(doc.value).active) await this.advanceGoalWork(project.id);
      } catch { /* One held goal cannot block independent authorized goals. */ }
    }
  }

  /** Only native workers opt into automatic recovery; merely observing jobs never executes. */
  recoverQueuedCommands(): Promise<void> {
    if (this.recovering !== undefined) return this.recovering;
    if (!this.config.recoverCommands || this.dispatchPaused || !this.config.commands || !this.journal?.reclaimQueued) return Promise.resolve();
    const recover = async (): Promise<void> => {
      this.refreshJournal();
      for (const intent of [...this.intents.values()]) {
        if (this.dispatchPaused || this.queued.length >= (this.config.maxQueuedJobs ?? 1024)) break;
        if (intent.state !== "queued" || !intent.commandDigest || intent.cancellationRequested || intent.leaseUntil > this.now()
          || this.queued.some(job => job.intentId === intent.id) || [...this.running.values()].some(job => job.intentId === intent.id)) continue;
        try {
          const command = this.readCommand(intent);
          this.config.commands!.validate(command, intent.projectId);
          const now = this.now();
          const claimed = await this.journal!.reclaimQueued!(intent.id, intent.commandDigest, this.ownerId, now, now + this.leaseMs);
          if (!claimed) continue;
          this.intents.set(claimed.id, claimed); this.recoveryHolds.delete(claimed.id);
          // A recovered command has no waiting client; the same durable job is its result.
          this.queued.push({ intentId: claimed.id, projectId: claimed.projectId, weight: claimed.weight,
            run: context => this.executeCommand(claimed, context), resolve: () => undefined, reject: () => undefined });
          this.ensureHeartbeat(); this.drain();
        } catch { this.recoveryHolds.add(intent.id); } // Do not expose command/identity/credential error text.
      }
    };
    this.recovering = recover().finally(() => { this.recovering = undefined; });
    return this.recovering;
  }
  private readCommand(intent: ProjectJobIntent): NativeProjectCommand {
    const session = this.manager.runnableSession(intent.projectId);
    const doc = session.resolveDocumentVersioned(commandDocumentName(intent.id));
    if (doc.revision !== 1 || doc.value === undefined || intent.commandDigest === undefined) throw new Error("project command is missing or changed");
    const command = decodeProjectCommand(doc.value, intent.commandDigest, intent.id, intent.projectId);
    if (command.binding !== this.config.commands?.binding) throw new Error("project command configuration changed");
    return command;
  }
  private executeCommand(intent: ProjectJobIntent, context: ProjectJobContext): Promise<unknown> {
    const command = this.readCommand(intent);
    this.config.commands!.validate(command, intent.projectId);
    context.signal.throwIfAborted();
    return this.config.commands!.execute(command, context);
  }

  submit<T>(projectId: ProjectId, weight: number, run: (context: ProjectJobContext) => Promise<T>, label = "project job"): Promise<T> {
    try { return this.submitTracked(projectId, weight, run, label).completion; }
    catch (error) { return Promise.reject(error); }
  }

  /** Returns the durable identity before awaiting execution. Observation never calls run again. */
  submitTracked<T>(projectId: ProjectId, weight: number, run: (context: ProjectJobContext) => Promise<T>, label = "project job", command?: NativeProjectCommand): TrackedProjectJob<T> {
    return this.enqueueTracked(projectId, weight, run, label, (this.config.id ?? randomUUID)(), command);
  }

  /** Reserve before even creating a project. Only the first claimant prepares/dispatches.
   * A retry gets an observation, never a replayed callback or an invented result. */
  async submitOnce<T>(request: Omit<ProjectJobSubmission, "jobId">, prepare: () => {
    readonly projectId: ProjectId; readonly run: (context: ProjectJobContext) => Promise<T>; readonly command?: NativeProjectCommand;
  }, weight = 1, label = "project job"): Promise<{ readonly jobId: string; readonly projectId: ProjectId; readonly replayed: boolean; readonly completion?: Promise<T> }> {
    if (this.journal?.reserveSubmission === undefined) throw new Error("durable atomic project submission is unavailable");
    const claim = await this.journal.reserveSubmission({ ...request, jobId: (this.config.id ?? randomUUID)() });
    const jobId = claim.submission.jobId;
    if (!claim.created) {
      const prior = this.job(jobId);
      if (prior === undefined) throw new ProjectSubmissionUncertainError(jobId);
      return { jobId, projectId: prior.projectId, replayed: true };
    }
    try {
      const job = prepare();
      const tracked = this.enqueueTracked(job.projectId, weight, job.run, label, jobId, job.command);
      return { ...tracked, projectId: job.projectId, replayed: false };
    } catch (cause) { throw new ProjectSubmissionUncertainError(jobId, { cause }); }
  }

  private enqueueTracked<T>(projectId: ProjectId, weight: number, run: (context: ProjectJobContext) => Promise<T>, label: string, jobId: string, command?: NativeProjectCommand): TrackedProjectJob<T> {
    this.refreshJournal();
    this.manager.runnableSession(projectId);
    if (typeof run !== "function") throw new Error("project job callback is required");
    const decision = concurrencyGovernor(this.runningEntries(), { project: projectId, weight }, this.policy);
    if (decision.verdict === "denied" || weight <= 0) throw new Error(weight <= 0 ? "project job weight must be greater than zero" : decision.reason);
    if ((decision.verdict === "queued" || this.dispatchPaused) && this.queued.length >= (this.config.maxQueuedJobs ?? 1024)) throw new Error("project job queue is full");
    const normalizedLabel = typeof label === "string" ? label.trim() : "";
    if (normalizedLabel.length === 0 || Buffer.byteLength(normalizedLabel, "utf8") > 1024 || /[\u0000-\u001f\u007f]/u.test(normalizedLabel)) throw new Error("invalid project job label");
    const now = this.now();
    const encoded = command === undefined ? undefined : encodeProjectCommand(command, jobId, projectId);
    if (encoded !== undefined) {
      if (!this.config.commands || command!.binding !== this.config.commands.binding) throw new Error("native project commands are unavailable");
      this.config.commands.validate(command!, projectId);
      if (this.manager.session(projectId).putDocumentVersioned(commandDocumentName(jobId), encoded.value, 0) !== 1) throw new Error("project command requires a durable versioned document");
    }
    const intent: ProjectJobIntent = { id: jobId, projectId, workspaceKey: `project/${projectId}`, weight, label: normalizedLabel, ownerId: this.ownerId, leaseUntil: now + this.leaseMs, state: "queued", createdAt: now, updatedAt: now, ...(encoded ? { commandDigest: encoded.digest } : {}), ...(this.config.commands?.resource ? { exclusiveResource: this.config.commands.resource } : {}) };
    if (encoded) run = context => this.executeCommand(intent, context) as Promise<T>;
    this.record(intent);
    this.ensureHeartbeat();
    const completion = decision.verdict === "admitted" && !this.dispatchPaused
      ? this.start({ intentId: intent.id, projectId, weight, run } as QueuedJob<T>)
      : new Promise<T>((resolve, reject) => { this.queued.push({ intentId: intent.id, projectId, weight, run, resolve, reject } as QueuedJob<unknown>); });
    return { jobId: intent.id, completion };
  }

  /** Includes terminal journal records, unlike the active-job listing. Caller supplies its visible projects. */
  job(jobId: string, projectIds?: ReadonlySet<ProjectId>): ProjectJobIntent | undefined {
    this.refreshJournal();
    const intent = this.intents.get(jobId) ?? this.journal?.load().filter(row => row.id === jobId).at(-1);
    return intent !== undefined && (projectIds === undefined || projectIds.has(intent.projectId)) ? { ...intent, ...(this.recoveryHolds.has(jobId) ? { reason: "queued recovery held: command, configuration or current authority requires reconciliation" } : {}) } : undefined;
  }

  activities(jobId: string, projectIds?: ReadonlySet<ProjectId>): readonly ProjectJobActivity[] | undefined {
    return this.job(jobId, projectIds) === undefined ? undefined : this.journal?.activities?.(jobId) ?? [];
  }

  /** Log before signaling; remote owners observe through their existing heartbeat.
   * A requested/running result is not a worker-termination receipt. */
  async cancel(jobId: string, projectIds?: ReadonlySet<ProjectId>): Promise<ProjectJobIntent | undefined> {
    if (this.job(jobId, projectIds) === undefined) return undefined;
    if (this.journal?.requestCancellation === undefined) throw new Error("durable job cancellation is unavailable");
    if (!await this.journal.requestCancellation(jobId)) return undefined;
    this.refreshJournal();
    return this.job(jobId, projectIds);
  }

  archive(projectId: ProjectId): void { this.assertIdle(projectId); this.cancelQueued(projectId, "project was archived before execution"); this.manager.archive(projectId); }
  delete(projectId: ProjectId): void { this.assertIdle(projectId); this.cancelQueued(projectId, "project was deleted before execution"); this.manager.delete(projectId); }
  status(projectIds?: ReadonlySet<ProjectId>): { readonly running: number; readonly queued: number } {
    this.refreshJournal();
    const now = this.now(); const visible = [...this.intents.values()].filter((intent) => projectIds === undefined || projectIds.has(intent.projectId));
    const localRunning = [...this.running.values()].filter((entry) => projectIds === undefined || projectIds.has(entry.project as ProjectId)).length;
    const localRunningIds = new Set([...this.running.values()].map((entry) => entry.intentId));
    const foreignRunning = visible.filter((intent) => !localRunningIds.has(intent.id) && ((intent.activeActivityIds?.length ?? 0) > 0 || (intent.state === "running" && intent.leaseUntil > now))).length;
    const localQueuedIds = new Set(this.queued.filter((job) => projectIds === undefined || projectIds.has(job.projectId)).map((job) => job.intentId));
    const remoteQueued = visible.filter((intent) => !localQueuedIds.has(intent.id) && intent.state === "queued" && (intent.leaseUntil > now || intent.commandDigest !== undefined)).length;
    return { running: localRunning + foreignRunning, queued: localQueuedIds.size + remoteQueued };
  }
  jobs(projectIds?: ReadonlySet<ProjectId>): readonly ProjectJobIntent[] { return [...this.intents.values()].filter((intent) => projectIds === undefined || projectIds.has(intent.projectId)).map((intent) => ({ ...intent })); }

  private now(): number { const value = (this.config.now ?? Date.now)(); if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid project runtime clock"); return value; }
  private runningEntries(): RunningEntry[] {
    const now = this.now();
    const localIntentIds = new Set([...this.running.values()].map((entry) => entry.intentId));
    // Local callbacks remain admission- and lifecycle-visible even when their lease expires or
    // heartbeat persistence fails. A lease describes what sibling processes may infer; it never
    // erases this process's direct knowledge that callback code is still executing.
    return [
      ...this.running.values(),
      ...[...this.intents.values()]
        .filter((intent) => !localIntentIds.has(intent.id) && ((intent.activeActivityIds?.length ?? 0) > 0 || (intent.state === "running" && intent.leaseUntil > now)))
        .map((intent) => ({ project: intent.projectId, weight: intent.weight })),
    ];
  }
  private ensureHeartbeat(): void {
    if (this.journal === undefined || this.heartbeat !== undefined) return;
    this.heartbeat = setInterval(() => {
      try { this.refreshJournal(); this.renewLeases(); this.drain(); void this.recoverQueuedCommands().then(() => this.advanceGoals()).catch(() => undefined); this.stopHeartbeatIfIdle(); }
      catch (error) {
        for (const intent of [...this.intents.values()]) {
          if (intent.ownerId === this.ownerId && intent.state === "running") this.intents.set(intent.id, {
            ...intent, state: "reconciliation-required", reason: `runtime heartbeat failed: ${error instanceof Error ? error.message : "unknown failure"}`,
          });
        }
        if (this.heartbeat !== undefined) { clearInterval(this.heartbeat); this.heartbeat = undefined; }
      }
    }, this.heartbeatMs);
    this.heartbeat.unref();
  }
  private stopHeartbeatIfIdle(): void {
    if (this.heartbeat === undefined) return;
    if (this.running.size > 0 || this.queued.length > 0 || this.activityTasks.size > 0) return;
    if (this.config.recoverCommands) return; // Native workers also own goal discovery/continuation while no callback is live.
    clearInterval(this.heartbeat); this.heartbeat = undefined;
  }
  private refreshJournal(): void {
    if (this.journal === undefined) return;
    const now = this.now();
    const locallyScheduled = new Set([...this.running.values()].map((entry) => entry.intentId));
    for (const job of this.queued) locallyScheduled.add(job.intentId);
    for (const observed of this.journal.load()) {
      const local = this.intents.get(observed.id);
      if (local !== undefined && local.ownerId !== observed.ownerId) {
        const index = this.queued.findIndex(job => job.intentId === observed.id);
        if (index >= 0) this.queued.splice(index, 1)[0]!.reject(new ProjectJobReconciliationError("queued command transferred to another worker; observe the same job"));
        this.intents.set(observed.id, observed);
        continue;
      }
      if (local !== undefined) {
        const { activeActivityIds: _ids, ...current } = local;
        this.intents.set(local.id, { ...current, ...(observed.activeActivityIds ? { activeActivityIds: observed.activeActivityIds } : {}) });
      }
      if (observed.cancellationRequested) {
        if (local !== undefined) this.intents.set(local.id, { ...this.intents.get(local.id)!, cancellationRequested: true });
        this.controllers.get(observed.id)?.abort(new ProjectJobCancelledError("operator requested cancellation"));
        const queuedIndex = this.queued.findIndex(job => job.intentId === observed.id);
        if (queuedIndex >= 0) {
          const queued = this.queued[queuedIndex]!;
          try { this.transition(observed.id, "stopped", "cancelled before callback dispatch"); }
          catch (error) { this.markLocallyUncertain(observed.id, "queued cancellation could not be confirmed durably"); throw error; }
          finally { this.queued.splice(queuedIndex, 1); queued.reject(new ProjectJobCancelledError("cancelled before callback dispatch")); }
          continue;
        }
      }
      if (local !== undefined && locallyScheduled.has(local.id) && (local.state === "queued" || local.state === "running")) {
        continue;
      }
      if ((observed.state === "completed" || observed.state === "failed") && (observed.activeActivityIds?.length ?? 0) === 0) { this.intents.delete(observed.id); continue; }
      // A failed terminal write is stronger local evidence than the older durable
      // running row. Fresh activity observations may update capacity, not erase the hold.
      if (local?.state === "reconciliation-required" && (observed.state === "queued" || observed.state === "running")) continue;
      if ((observed.state === "queued" || observed.state === "running") && observed.leaseUntil <= now) {
        if (observed.state === "queued" && observed.commandDigest !== undefined && !observed.cancellationRequested) { this.intents.set(observed.id, observed); continue; }
        const expired: ProjectJobIntent = observed.state === "queued"
          ? { ...observed, state: "stopped", updatedAt: now, leaseUntil: Math.max(observed.leaseUntil, now), reason: "queued callback was interrupted and was not restarted" }
          : { ...observed, state: "reconciliation-required", updatedAt: now, leaseUntil: Math.max(observed.leaseUntil, now), reason: "running callback was interrupted; effect outcome is unknown" };
        try { this.record(expired); } catch { /* another observer may win the terminal classification */ }
        continue;
      }
      if (local === undefined || observed.updatedAt >= local.updatedAt) this.intents.set(observed.id, observed);
    }
  }
  private renewLeases(): void {
    const now = this.now();
    const locallyScheduled = new Set([...this.running.values()].map((entry) => entry.intentId));
    for (const job of this.queued) locallyScheduled.add(job.intentId);
    const owned = [...this.intents.values()].filter((intent) => locallyScheduled.has(intent.id) && intent.ownerId === this.ownerId && (intent.state === "queued" || intent.state === "running"));
    if (owned.length === 0 || this.journal === undefined) return;
    const leaseUntil = now + this.leaseMs;
    this.journal.renew(this.ownerId, owned.map((intent) => intent.id), now, leaseUntil);
    for (const intent of owned) this.intents.set(intent.id, { ...intent, updatedAt: now, leaseUntil });
  }
  private assertIdle(projectId: ProjectId): void { this.refreshJournal(); if (this.runningEntries().some((entry) => entry.project === projectId)) throw new Error(`project ${projectId} has running work`); }
  private cancelQueued(projectId: ProjectId, reason: string): void {
    const failures: unknown[] = [];
    for (let i = this.queued.length - 1; i >= 0; i--) { const job = this.queued[i]!; if (job.projectId !== projectId) continue;
      const failure = new Error(reason);
      try { this.finish(job.intentId, "failed", reason); }
      catch (error) {
        this.markLocallyUncertain(job.intentId, "queued cancellation was not durable; callback was not executed");
        failures.push(error);
      }
      finally { this.queued.splice(i, 1); job.reject(failure); }
    }
    if (failures.length > 0) throw new AggregateError(failures, "one or more queued job cancellations were not durable");
  }
  private start<T>(job: QueuedJob<T>): Promise<T> {
    if (this.journal?.tryDispatch === undefined) return this.execute(job);
    // Count this local admission-in-progress once so this runtime cannot overfill its
    // own pending claims. Shared authority is decided only under the journal lock.
    const token = Symbol(job.projectId);
    this.running.set(token, { intentId: job.intentId, project: job.projectId, weight: job.weight });
    const now = this.now();
    return this.journal.tryDispatch(job.intentId, this.ownerId, this.policy, now, now + this.leaseMs).then(activity => {
      this.running.delete(token);
      if (activity === undefined) {
        return new Promise<T>((resolve, reject) => {
          if (this.queued.length >= (this.config.maxQueuedJobs ?? 1024)) { this.finish(job.intentId, "failed", "project job queue is full"); reject(new Error("project job queue is full")); return; }
          this.queued.push({ ...job, resolve, reject } as QueuedJob<unknown>);
        });
      }
      const prior = this.intents.get(job.intentId)!;
      this.intents.set(job.intentId, { ...prior, state: "running", updatedAt: activity.startedAt, leaseUntil: now + this.leaseMs });
      return this.execute(job, activity);
    }, error => {
      this.running.delete(token); this.markLocallyUncertain(job.intentId, "dispatch admission was not confirmed; callback was not invoked");
      this.drain(); this.stopHeartbeatIfIdle(); throw error;
    });
  }
  private execute<T>(job: QueuedJob<T>, callbackActivity?: ProjectJobActivity): Promise<T> {
    if (callbackActivity === undefined) { try { this.transition(job.intentId, "running"); } catch (error) { return Promise.reject(error); } }
    const controller = new AbortController(); this.controllers.set(job.intentId, controller);
    if (this.intents.get(job.intentId)?.cancellationRequested) controller.abort(new ProjectJobCancelledError("operator requested cancellation"));
    const token = Symbol(job.projectId); this.running.set(token, { intentId: job.intentId, project: job.projectId, weight: job.weight });
    const result = Promise.resolve().then(async () => {
      try {
        this.refreshJournal(); controller.signal.throwIfAborted();
        return await job.run({ jobId: job.intentId, projectId: job.projectId, workspaceKey: `project/${job.projectId}`, signal: controller.signal,
          trackActivity: (label, run) => this.trackActivity(job.intentId, label, run, controller.signal),
        });
      } finally {
        if (callbackActivity !== undefined) await this.journal!.settleActivity!(callbackActivity.id, this.ownerId, this.now());
      }
    }).then(
      async (value) => {
        if (!controller.signal.aborted) await this.awaitActivities(job.intentId);
        if (controller.signal.aborted) { this.finishCancellation(job.intentId); throw new ProjectJobCancelledError("callback settled after cancellation; reconcile its effects"); }
        try { this.finish(job.intentId, "completed"); return value; } catch (cause) { this.uncertain(job.intentId); throw new ProjectJobReconciliationError("job completed but its terminal record was not durable", { cause }); }
      },
      (error) => {
        if (controller.signal.aborted) { this.finishCancellation(job.intentId); throw error; }
        if ((this.job(job.intentId)?.activeActivityIds?.length ?? 0) > 0) { this.finishCancellation(job.intentId, "callback failed while owned activity remains unresolved"); throw error; }
        try { this.finish(job.intentId, "failed", "callback failed"); } catch (cause) { this.uncertain(job.intentId); throw new ProjectJobReconciliationError("job failed but its terminal record was not durable", { cause }); } throw error;
      },
    );
    void result.finally(() => { this.controllers.delete(job.intentId); this.running.delete(token); this.drain(); this.stopHeartbeatIfIdle(); }).catch(() => undefined);
    return result;
  }
  private finishCancellation(id: string, reason = "callback settled after cancellation; reconcile effects before any retry"): void {
    try { this.transition(id, "reconciliation-required", reason); }
    catch (cause) { this.uncertain(id); throw new ProjectJobReconciliationError("cancelled callback terminal record was not durable", { cause }); }
  }
  private drain(): void {
    this.refreshJournal();
    if (this.dispatchPaused) return;
    for (let i = 0; i < this.queued.length;) {
      const job = this.queued[i]!;
      try { this.manager.runnableSession(job.projectId); } catch (error) { try { this.finish(job.intentId, "failed", "project is no longer runnable"); } finally { this.queued.splice(i, 1); job.reject(error); } continue; }
      const decision = concurrencyGovernor(this.runningEntries(), { project: job.projectId, weight: job.weight }, this.policy);
      if (decision.verdict === "denied") { const failure = new Error(decision.reason); try { this.finish(job.intentId, "failed", "admission policy denied queued job"); } finally { this.queued.splice(i, 1); job.reject(failure); } continue; }
      if (decision.verdict === "queued") { i++; continue; }
      this.queued.splice(i, 1); const result = this.start(job); result.then(job.resolve, job.reject);
    }
  }
  private trackActivity<T>(jobId: string, label: string, run: () => Promise<T>, signal: AbortSignal): Promise<T> {
    if (this.journal?.beginActivity === undefined || this.journal.settleActivity === undefined) return Promise.reject(new Error("durable activity ownership is unavailable"));
    const journal = this.journal;
    const activity: ProjectJobActivity = { id: randomUUID(), jobId, ownerId: this.ownerId, label, state: "running", startedAt: this.now() };
    const promise = (async () => {
      await journal.beginActivity!(activity);
      try { signal.throwIfAborted(); return await run(); }
      finally { await journal.settleActivity!(activity.id, this.ownerId, this.now()); }
    })();
    this.activityTasks.set(activity.id, { jobId, promise });
    void promise.finally(() => {
      this.activityTasks.delete(activity.id); this.drain(); this.stopHeartbeatIfIdle();
    }).catch(() => undefined);
    return promise;
  }
  private async awaitActivities(jobId: string): Promise<void> {
    for (;;) {
      const pending = [...this.activityTasks.values()].filter(activity => activity.jobId === jobId);
      if (pending.length === 0) return;
      await Promise.allSettled(pending.map(activity => activity.promise));
    }
  }
  private record(intent: ProjectJobIntent): void { this.journal?.append(intent); this.intents.set(intent.id, intent); }
  private transition(id: string, state: ProjectJobIntentState, reason?: string): void {
    const prior = this.intents.get(id); if (!prior) throw new Error(`unknown project job ${id}`);
    const now = this.now();
    this.record({ ...prior, state, updatedAt: now, leaseUntil: Math.max(prior.leaseUntil, now + this.leaseMs), ...(reason ? { reason } : {}) });
  }
  private finish(id: string, state: "completed" | "failed", reason?: string): void { this.transition(id, state, reason); this.intents.delete(id); }
  private uncertain(id: string): void {
    const prior = this.intents.get(id); if (!prior) return;
    this.intents.set(id, { ...prior, state: "reconciliation-required", updatedAt: Math.max(prior.updatedAt, this.now()), reason: "terminal persistence failed; effect outcome requires reconciliation" });
  }
  private markLocallyUncertain(id: string, reason: string): void {
    const prior = this.intents.get(id); if (!prior) return;
    this.intents.set(id, { ...prior, state: "reconciliation-required", updatedAt: Math.max(prior.updatedAt, this.now()), reason });
    this.stopHeartbeatIfIdle();
  }
}
