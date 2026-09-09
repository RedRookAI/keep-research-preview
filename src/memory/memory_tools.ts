/**
 * M3 — MANUAL MEMORY TOOLS (shared ops for the CLI + gateway). Thin orchestration over the existing `MemoryStore`:
 * store=ingest, recall=retrieve, update=reweight, forget=retire (supersede-not-delete), correct=one prepared
 * store-owned supersession. Both surfaces call these so they behave identically. `forget` and
 * `correct` NEVER hard-delete: the old lesson is retired (tier→retired, stays present, spine-audited) so provenance
 * survives; `correct`'s new lesson cites the old id for lineage.
 */

import { MemoryStore } from "./store.js";
import { memoryUseExpired, memoryCurrentWithSourcesAt, memoryPrivateUseAllowed, memorySourceClosure, memoryExcerptText, MAX_MEMORY_EXCERPT_BYTES,
  type MemoryCustody, type DerivedMemoryCustody, type ManualMemoryCustody, type SourceOnlyManualMemoryCustody, type RetainedManualMemoryCustody, type MemoryKind, type MemoryScope, type TrustTier, type Origin } from "./model.js";
import type { CapturedMemoryRetentionPolicy } from "./retention.js";
import { eligibleRetainedMemorySources, selectMemorySourceExcerpt } from "./task_context.js";
import { createHash, randomUUID } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import { canonicalize } from "../spine/event.js";
import type { ModelGateway } from "../gateway/gateway.js";
import type { FileMemoryPartition, MemoryAdmissionEvent, MemoryCommitResult, MemoryControlCommand, PersistedMemoryEntry } from "./persistence.js";

export type MemoryProcessing = "source-only" | "configured-provider";
export type DurableMemoryMutation =
  | MemoryControlCommand
  | { readonly action: "consolidate"; readonly sourceIds: readonly string[]; readonly query?: string }
  | { readonly action: "store"; readonly content: string; readonly kind?: MemoryKind; readonly useUntil?: number; readonly processing?: MemoryProcessing; readonly privatePurpose?: string }
  | { readonly action: "correct"; readonly id: string; readonly content: string; readonly processing?: MemoryProcessing; readonly privatePurpose?: string }
  | { readonly action: "update"; readonly id: string; readonly importance: number }
  | { readonly action: "forget"; readonly id: string }
  | { readonly action: "purge"; readonly filter: MemoryFilter }
  | { readonly action: "recall"; readonly query: string; readonly k?: number; readonly processing?: MemoryProcessing };

export type DurableMemoryMutationResult = Exclude<MemoryCommitResult, { disposition: "committed" }>
  | { readonly disposition: "committed"; readonly operationId: string; readonly revision: number; readonly reconciled: boolean; readonly audit: "delivered" | "pending"; readonly result: unknown }
  | { readonly disposition: "committed-withheld"; readonly operationId: string; readonly revision: number; readonly audit: "delivered" | "pending"; readonly reason: "authorization-revoked" }
  | { readonly disposition: "rejected"; readonly operationId: string; readonly reason: "unauthorized" };

function checkedMutation(value: DurableMemoryMutation): DurableMemoryMutation {
  const command = structuredClone(value);
  if (command === null || typeof command !== "object" || Array.isArray(command)) throw new Error("invalid memory command");
  const allowed: Record<string, readonly string[]> = { consolidate: ["action", "sourceIds", "query"], store: ["action", "content", "kind", "useUntil", "processing", "privatePurpose"], correct: ["action", "id", "content", "processing", "privatePurpose"], update: ["action", "id", "importance"], forget: ["action", "id"], purge: ["action", "filter"], recall: ["action", "query", "k", "processing"], erase: ["action", "id"], hold: ["action", "id", "holdId", "active"] };
  const keys = allowed[command.action];
  if (!keys || Object.keys(command).some(key => !keys.includes(key))) throw new Error("invalid memory command fields");
  if ("processing" in command && command.processing !== "source-only" && command.processing !== "configured-provider") throw new Error("invalid memory processing");
  if ("privatePurpose" in command && (command.processing !== "source-only" || typeof command.privatePurpose !== "string" || !/^[a-z][a-z0-9.-]{0,127}$/u.test(command.privatePurpose))) throw new Error("private retention requires an explicit purpose and source-only processing");
  if (command.action === "consolidate" && (!Array.isArray(command.sourceIds) || command.sourceIds.length < 2 || command.sourceIds.length > 8
    || command.sourceIds.some(id => typeof id !== "string" || !id || Buffer.byteLength(id) > 4096 || /[\u0000-\u001f\u007f]/u.test(id))
    || new Set(command.sourceIds).size !== command.sourceIds.length)) throw new Error("two to eight distinct source IDs required");
  if (command.action === "consolidate" && Object.hasOwn(command, "query") && (typeof command.query !== "string"
    || Buffer.byteLength(command.query) > 1024 || !/[\p{L}\p{N}]/u.test(command.query.normalize("NFKC")))) throw new Error("invalid consolidation query");
  if ((command.action === "store" || command.action === "correct") && (typeof command.content !== "string" || command.content.length === 0)) throw new Error("memory content required");
  if ((command.action === "correct" || command.action === "forget" || command.action === "update" || command.action === "erase" || command.action === "hold") && (typeof command.id !== "string" || !command.id)) throw new Error("memory id required");
  if (command.action === "hold" && (typeof command.holdId !== "string" || !command.holdId || typeof command.active !== "boolean")) throw new Error("explicit hold identity/state required");
  if (command.action === "update" && !Number.isFinite(command.importance)) throw new Error("finite memory importance required");
  if (command.action === "store" && command.kind !== undefined && !["fact", "preference", "decision", "procedure"].includes(command.kind)) throw new Error("invalid memory kind");
  if (command.action === "store" && command.useUntil !== undefined && (!Number.isSafeInteger(command.useUntil) || command.useUntil < 0)) throw new Error("invalid memory use deadline");
  if (command.action === "recall" && (typeof command.query !== "string" || (command.k !== undefined && (!Number.isSafeInteger(command.k) || command.k < 1 || command.k > 100)))) throw new Error("invalid bounded memory recall");
  if (command.action === "purge") {
    const f = command.filter;
    if (!f || typeof f !== "object" || Array.isArray(f) || emptyFilter(f) || Object.keys(f).some(key => !["kind", "scope", "tier"].includes(key))
      || (f.kind !== undefined && !["fact", "preference", "decision", "procedure"].includes(f.kind))
      || (f.scope !== undefined && !["user", "project", "global", "agent"].includes(f.scope))
      || (f.tier !== undefined && !["candidate", "probation", "confirmed", "retired"].includes(f.tier))) throw new Error("explicit valid memory filter required");
  }
  if (Buffer.byteLength(canonicalize(command)) > 1024 * 1024) throw new Error("memory command exceeds bound");
  return command;
}

/** Reuses the spine's stable event view; an uncertain append is reconciled by identity, never acknowledged blindly. */
export async function deliverMemoryAdmissions(partition: FileMemoryPartition, spine: Spine): Promise<"delivered" | "pending"> {
  try {
    if (!spine.durableStorage()) return "pending";
    const outbox = partition.admissionEvents();
    await spine.withStableEventView(events => {
      let reused = false;
      for (const event of outbox) {
        const payload = { ...event.payload, memoryEventId: event.id };
        const prior = events.filter(row => row.actor === "memory-outbox" && row.payload["memoryEventId"] === event.id);
        if (prior.some(row => row.type !== "identity.action" || canonicalize(row.payload) !== canonicalize(payload))) throw new Error("conflicting memory audit identity");
        if (prior.length === 0) spine.stage({ type: "identity.action", actor: "memory-outbox", payload });
        else reused = true;
      }
      if (reused) spine.confirmEventDurability();
    });
    return "delivered";
  } catch { return "pending"; }
}

/** Trusted internal command implementation. The composed gateway must supply actual resolved authorization
 * and select the partition before exposure. No default persistence or caller-provided scope is enabled here. */
export async function executeDurableMemoryMutation(context: {
  readonly partition: FileMemoryPartition; readonly spine: Spine; readonly gateway: ModelGateway;
  readonly authorize: () => boolean; readonly clock?: () => number;
  readonly admission?: { readonly actorId: string; readonly actorKind: string; readonly role: string; readonly permission: string };
  /** Actual initialization outbox identity, supplied by the authenticated gateway, never command JSON. */
  readonly consentEventId?: string;
  readonly retentionPolicy?: CapturedMemoryRetentionPolicy;
}, operationId: string, input: DurableMemoryMutation): Promise<DurableMemoryMutationResult> {
  let command: DurableMemoryMutation; let requestDigest: string;
  try {
    if (typeof operationId !== "string" || !operationId || Buffer.byteLength(operationId) > 4096 || /[\u0000-\u001f\u007f]/u.test(operationId)) throw new Error("invalid memory operation id");
    command = checkedMutation(input); requestDigest = createHash("sha256").update(canonicalize(command)).digest("hex");
  } catch { return { disposition: "rejected", operationId, reason: "invalid-request" }; }
  const admitted = (): boolean => { try { return context.authorize() === true; } catch { return false; } };
  const completed = async (revision: number, reconciled: boolean, result: unknown): Promise<DurableMemoryMutationResult> => {
    const audit = await deliverMemoryAdmissions(context.partition, context.spine);
    if (!admitted()) return { disposition: "committed-withheld", operationId, revision, audit, reason: "authorization-revoked" };
    return { disposition: "committed", operationId, revision, reconciled, result, audit };
  };
  if (!admitted()) return { disposition: "rejected", operationId, reason: "unauthorized" };
  if (command.action === "erase" || command.action === "hold") {
    if (context.admission === undefined) return { disposition: "rejected", operationId, reason: "unauthorized" };
    const controlled = context.partition.controlCommand(operationId, command, context.admission);
    if (controlled.disposition !== "committed") return controlled;
    const receipt = context.partition.lookupCommand(operationId, requestDigest);
    if (receipt.disposition !== "committed") return { disposition: "held", operationId, publication: "unknown", reason: "commit-uncertain" };
    return completed(controlled.revision, controlled.reconciled, receipt.command.result);
  }
  const prior = context.partition.lookupCommand(operationId, requestDigest);
  if (prior.disposition === "withheld") return { ...prior, operationId };
  if (prior.disposition === "held") return { disposition: "held", operationId, publication: "unknown", reason: "unavailable" };
  if (prior.disposition === "rejected") return { disposition: "rejected", operationId, reason: "operation-reused" };
  if (prior.disposition === "committed") return completed(prior.revision, true, prior.command.result);
  try {
    const view = context.partition.read(); const events: MemoryAdmissionEvent[] = [];
    const now = context.clock ?? Date.now;
    const sourceActor = context.admission === undefined ? undefined : structuredClone(context.admission);
    const admission = sourceActor ?? {};
    const consentEventId = context.consentEventId;
    if (consentEventId !== undefined && context.admission === undefined) throw new Error("custody source requires admitted actor");
    const previous = command.action === "correct" ? view.entries.find(row => row.lesson.id === command.id)?.lesson : undefined;
    const privatePurpose = command.action === "store" || command.action === "correct" ? command.privatePurpose : undefined;
    if (previous?.custody?.schema === "keep.memory.manual-custody/v3" && privatePurpose === undefined) return { disposition: "rejected", operationId, reason: "invalid-request" };
    if (privatePurpose !== undefined && (!context.retentionPolicy || context.retentionPolicy.authority !== (view.scope.tenantId === undefined ? "owner" : "organization"))) return { disposition: "rejected", operationId, reason: "unauthorized" };
    if (previous?.custody !== undefined && consentEventId === undefined) throw new Error("custody correction requires admitted source");
    const useUntil = command.action === "store" ? command.useUntil ?? null : previous?.custody?.retention.useUntil ?? null;
    // Omission keeps historical behavior, except a NEW v2 predecessor cannot be
    // escalated into embedding by an old client. Digest remains the literal command.
    const sourceOnly = ("processing" in command && command.processing === "source-only")
      || (command.action === "correct" && command.processing === undefined && previous?.custody?.schema === "keep.memory.manual-custody/v2");
    if (sourceOnly && (!sourceActor || !consentEventId)) return { disposition: "rejected", operationId, reason: "unauthorized" };
    if (command.action === "correct" && (sourceOnly || previous?.custody?.schema === "keep.memory.manual-custody/v2")
      && (!previous || previous.custody?.consentEventId !== consentEventId
        || !memoryCurrentWithSourcesAt(previous, now(), new Map(view.entries.map(row => [row.lesson.id, row.lesson]))))) return { disposition: "rejected", operationId, reason: "invalid-request" };
    const baseSourceCustody: SourceOnlyManualMemoryCustody | undefined = sourceOnly && (command.action === "store" || command.action === "correct") ? {
      schema: "keep.memory.manual-custody/v2", scope: structuredClone(view.scope),
      source: { kind: "authenticated-manual-command", operationId, actorId: sourceActor!.actorId, actorKind: sourceActor!.actorKind },
      consentEventId: consentEventId!, purpose: "explicit-manual-memory", assertion: "asserted", uncertainty: "unassessed", authority: "none",
      retention: { useUntil, expiryDisposition: "withhold-pending-erasure", legalHoldAssessment: "unassessed" },
      residency: { storage: "operator-host", region: "unverified", embeddingProcessing: "none" },
      dependencies: { embeddingProvider: null, embeddingModel: null },
      derivatives: { coEncrypted: ["access"], outsideCustody: "caller-provider-backup-copies-untracked" },
      ...(previous === undefined ? {} : { supersedes: previous.id }),
    } : undefined;
    const sourceCustody: RetainedManualMemoryCustody | undefined = baseSourceCustody === undefined ? undefined : privatePurpose === undefined ? baseSourceCustody : {
      ...baseSourceCustody, schema: "keep.memory.manual-custody/v3", privateSource: {
        representation: "keep.memory.private-source/v1", purpose: privatePurpose, policyIdentity: context.retentionPolicy!.identity,
      },
    };
    if ((command.action === "store" && command.useUntil !== undefined && consentEventId === undefined)
      || ((command.action === "store" || command.action === "correct") && useUntil !== null && now() >= useUntil)) return { disposition: "rejected", operationId, reason: "invalid-request" };
    const capture = (payload: Readonly<Record<string, unknown>>): string => {
      const id = `memory-admission:${randomUUID()}`;
      events.push({ id, payload: structuredClone({ ...payload, ...admission, operationId, terminalDisposition: "committed", ownerId: view.scope.ownerId,
        ...(view.scope.tenantId === undefined ? {} : { tenant: view.scope.tenantId }),
        ...(view.scope.projectId === undefined ? {} : { projectId: view.scope.projectId }),
        ...(view.scope.agentId === undefined ? {} : { agentId: view.scope.agentId }),
      }) }); return id;
    };
    const working = MemoryStore.fromPartition(view, { stage: event => {
      if (event.type !== "identity.action" || event.actor !== "memory") throw new Error("unexpected memory audit event");
      const { tenant: _tenant, projectId: _project, agentId: _agent, ownerId: _owner, ...payload } = event.payload;
      return capture(payload);
    } }, context.gateway, context.clock, sourceCustody, context.retentionPolicy);
    let result: unknown;
    let derivedRow: PersistedMemoryEntry | undefined;
    switch (command.action) {
      case "consolidate": {
        const at = now(), byId = new Map(view.entries.map(row => [row.lesson.id, row.lesson]));
        const parents = command.sourceIds.map(id => byId.get(id));
        if (!sourceActor || !consentEventId || !Number.isSafeInteger(at) || at < 0
          || parents.some(parent => !parent || parent.custody?.consentEventId !== consentEventId
            || !memoryCurrentWithSourcesAt(parent, at, byId) || !memoryPrivateUseAllowed(parent, at, byId, context.retentionPolicy))) return { disposition: "rejected", operationId, reason: "invalid-request" };
        let unmatchedSources = 0;
        const sources = parents.map(parent => {
          if (command.query !== undefined) {
            const excerpt = selectMemorySourceExcerpt(parent!, command.query);
            if (!excerpt.matched) unmatchedSources++;
            return { itemId: parent!.id, provenanceEventId: parent!.provenanceEventId, startByte: excerpt.startByte, endByte: excerpt.endByte };
          }
          const bytes = Buffer.from(parent!.content, "utf8");
          let endByte = Math.min(bytes.length, MAX_MEMORY_EXCERPT_BYTES);
          while (endByte > 0 && !Buffer.from(bytes.subarray(0, endByte).toString("utf8"), "utf8").equals(bytes.subarray(0, endByte))) endByte--;
          return { itemId: parent!.id, provenanceEventId: parent!.provenanceEventId, startByte: 0, endByte };
        });
        if (sources.some(s => s.endByte === 0)) return { disposition: "rejected", operationId, reason: "invalid-request" };
        const allSources = parents.flatMap(parent => memorySourceClosure(parent!, byId)!);
        const deadlines = allSources.flatMap(parent => parent.custody?.retention.useUntil == null ? [] : [parent.custody.retention.useUntil]);
        const ends = allSources.flatMap(parent => parent.validTo === undefined ? [] : [parent.validTo]);
        const custody: DerivedMemoryCustody = {
          schema: "keep.memory.derived-custody/v1", scope: structuredClone(view.scope),
          source: { kind: "host-extractive-command", operationId, actorId: sourceActor.actorId, actorKind: sourceActor.actorKind },
          consentEventId, purpose: "source-preserving-memory", assertion: "derived", uncertainty: "unassessed", authority: "none",
          algorithm: "extractive-v1", sources,
          retention: { useUntil: deadlines.length ? Math.min(...deadlines) : null, expiryDisposition: "withhold-pending-erasure", legalHoldAssessment: "unassessed" },
          residency: { storage: "operator-host", region: "unverified", embeddingProcessing: "none" },
          dependencies: { embeddingProvider: null, embeddingModel: null },
          derivatives: { coEncrypted: ["sources", "access"], outsideCustody: "caller-provider-backup-copies-untracked" },
        };
        const id = randomUUID(), provenanceEventId = capture({ event: "memory.view.created", itemId: id, algorithm: custody.algorithm, sourceCount: sources.length });
        derivedRow = { lesson: { id, content: memoryExcerptText(sources, byId), custody, tier: "candidate", origin: "self",
          provenanceEventId, scope: view.scope.kind, kind: parents[0]!.kind, importance: 0, evidence: [], createdTs: at, validFrom: at,
          ...(ends.length ? { validTo: Math.min(...ends) } : {}) }, access: { count: 0, lastAccessedTs: at } };
        result = { id, algorithm: custody.algorithm, sourceCount: sources.length,
          ...(command.query === undefined ? {} : { selection: "lexical-query", unmatchedSources, partial: true }) }; break;
      }
      case "store": result = await memoryStore(working, { content: command.content, ...(command.kind === undefined ? {} : { kind: command.kind }) }); break;
      case "correct": result = await memoryCorrect(working, command.id, command.content); break;
      case "update": result = memoryUpdate(working, command.id, command.importance); break;
      case "forget": result = memoryForget(working, command.id); break;
      case "purge": result = memoryPurge(working, command.filter); break;
      case "recall": {
        const eligible = consentEventId === undefined ? [] : eligibleRetainedMemorySources(view, consentEventId, now(), context.retentionPolicy);
        const embedded = new Set(view.entries.filter(row => row.embedding !== undefined).map(row => row.lesson.id));
        const hits = sourceOnly ? working.recallSources(command.query, command.k ?? 5, consentEventId!)
          : await memoryRecall(working, { query: command.query, ...(command.k === undefined ? {} : { k: command.k }) });
        // Content stays solely under the item key; the receipt retains immutable item references.
        result = { hits: hits.map(({ id, kind, importance }) => ({ id, kind, importance })),
          retrieval: { processing: sourceOnly ? "source-only" : "configured-provider", ranking: sourceOnly ? (command.query.trim() === "" ? "source-id-browse" : "lexical-passage-overlap") : "vector-cosine",
            coverageAtSelection: { eligibleRetainedSources: eligible.length, unrepresentedSources: sourceOnly ? 0 : eligible.filter(lesson => !embedded.has(lesson.id)).length },
            completeMemoryEnumeration: false } }; break;
      }
    }
    if (!admitted()) return { disposition: "rejected", operationId, reason: "unauthorized" };
    if ((command.action === "store" || command.action === "correct") && result && typeof result === "object") {
      const ingestion = events.find(event => ["lesson_ingested", "lesson_corrected"].includes(String(event.payload["event"])))?.payload["ingestion"];
      if (ingestion !== undefined) result = { ...result, ingestion: structuredClone(ingestion) };
    }
    const priorIds = new Set(view.entries.map(row => row.lesson.id));
    const rows = working.partitionEntries().map(row => {
      if (priorIds.has(row.lesson.id) || consentEventId === undefined || ["keep.memory.manual-custody/v2", "keep.memory.manual-custody/v3"].includes(row.lesson.custody?.schema ?? "")) return row;
      const custody: ManualMemoryCustody = {
        schema: "keep.memory.manual-custody/v1", scope: structuredClone(view.scope),
        source: { kind: "authenticated-manual-command", operationId, actorId: sourceActor!.actorId, actorKind: sourceActor!.actorKind },
        consentEventId: previous?.custody?.consentEventId ?? consentEventId, purpose: "explicit-manual-memory",
        assertion: "asserted", uncertainty: "unassessed", authority: "none",
        retention: { useUntil, expiryDisposition: "withhold-pending-erasure", legalHoldAssessment: "unassessed" },
        residency: { storage: "operator-host", region: "unverified", embeddingProcessing: context.gateway.isLocal ? "local" : "external" },
        dependencies: { embeddingProvider: context.gateway.providerName, embeddingModel: null },
        derivatives: { coEncrypted: ["embedding", "access"], outsideCustody: "caller-provider-backup-copies-untracked" },
        ...(previous === undefined ? {} : { supersedes: previous.id }),
      };
      return { ...row, lesson: { ...row.lesson, custody } };
    });
    if (derivedRow !== undefined) rows.push(derivedRow);
    if (rows.some(row => !priorIds.has(row.lesson.id) && (command.action === "consolidate")
      !== (row.lesson.custody?.schema === "keep.memory.derived-custody/v1"))) return { disposition: "rejected", operationId, reason: "invalid-request" };
    // Expiration while preparing a successor must not retire the previously committed item.
    if (rows.some(row => !priorIds.has(row.lesson.id) && memoryUseExpired(row.lesson, now()))) return { disposition: "rejected", operationId, reason: "invalid-request" };
    if (events.length === 0) capture({ event: "memory.command.committed", action: command.action });
    const committed = context.partition.commit(operationId, view.revision, rows, { requestDigest, result, events }, command.action === "consolidate" || sourceOnly ? admitted : undefined);
    if (committed.disposition !== "committed") {
      if (committed.disposition === "conflict" || (committed.disposition === "rejected" && committed.reason === "operation-reused")) {
        const winner = context.partition.lookupCommand(operationId, requestDigest);
        if (winner.disposition === "withheld") return { ...winner, operationId };
        if (winner.disposition === "committed") return completed(winner.revision, true, winner.command.result);
      }
      return committed;
    }
    return completed(committed.revision, committed.reconciled, result);
  } catch { return { disposition: "held", operationId, publication: "not-attempted", reason: "unavailable" }; }
}

export interface StoreArgs {
  readonly content: string;
  readonly kind?: MemoryKind;
  readonly scope?: MemoryScope;
  readonly agentId?: string;
  readonly projectId?: string;
}
export interface RecallArgs {
  readonly query: string;
  readonly k?: number;
  readonly agentId?: string;
  readonly projectId?: string;
}

export async function memoryStore(store: MemoryStore, args: StoreArgs): Promise<{ id: string } | null> {
  const lesson = await store.ingest(args.content, {
    origin: "self", // a manual, human-entered memory
    ...(args.kind !== undefined ? { kind: args.kind } : {}),
    ...(args.scope !== undefined ? { scope: args.scope } : {}),
    ...(args.agentId !== undefined ? { agentId: args.agentId } : {}),
    ...(args.projectId !== undefined ? { projectId: args.projectId } : {}),
  });
  return lesson ? { id: lesson.id } : null;
}

export async function memoryRecall(store: MemoryStore, args: RecallArgs): Promise<{ id: string; content: string; kind: MemoryKind; importance: number }[]> {
  const hits = args.projectId === undefined
    ? await store.retrieve(args.query, args.k ?? 5, "candidate", args.agentId)
    : await store.retrieveForProject(args.query, args.k ?? 5, args.projectId);
  return hits.map((h) => ({ id: h.lesson.id, content: h.lesson.content, kind: h.lesson.kind, importance: h.lesson.importance }));
}

export function memoryUpdate(store: MemoryStore, id: string, importance: number, projectId?: string): boolean {
  return projectId === undefined ? store.reweight(id, importance) : store.reweightForProject(projectId, id, importance);
}

/** Forget = supersede-not-delete: retire the lesson (it stays present + audited so provenance survives). */
export function memoryForget(store: MemoryStore, id: string, projectId?: string): boolean {
  return projectId === undefined ? store.retire(id, "forget (manual)") : store.retireForProject(projectId, id, "forget (manual)");
}

/**
 * Correct = prepare, then supersede atomically in the store. Rejection or failed preparation leaves the old
 * item intact. Returns null for a missing/retired/foreign item, rejected replacement or conflicting change.
 */
export async function memoryCorrect(store: MemoryStore, id: string, newContent: string, projectId?: string): Promise<{ oldId: string; newId: string } | null> {
  return store.correct(id, newContent, projectId);
}


// ─── M4: memory curation (list / review / purge) — composes all()/get()/retire(); purge is bulk-retire, never a wipe ───

export interface MemoryFilter {
  readonly kind?: MemoryKind;
  readonly scope?: MemoryScope;
  readonly tier?: TrustTier;
}

function matches(l: { kind: MemoryKind; scope: MemoryScope; tier: TrustTier }, f: MemoryFilter): boolean {
  return (f.kind === undefined || l.kind === f.kind)
    && (f.scope === undefined || l.scope === f.scope)
    && (f.tier === undefined || l.tier === f.tier);
}

function emptyFilter(f: MemoryFilter): boolean {
  return f.kind === undefined && f.scope === undefined && f.tier === undefined;
}

export interface MemorySummary {
  readonly id: string; readonly kind: MemoryKind; readonly scope: MemoryScope;
  readonly importance: number; readonly tier: TrustTier; readonly origin: Origin; readonly createdTs: number;
}

/** List memories, filtered by kind/scope/tier, importance-ranked, provenance-visible. Excludes retired unless asked. */
export function memoryList(store: MemoryStore, filter: MemoryFilter = {}, includeRetired = false, projectId?: string): MemorySummary[] {
  return (projectId === undefined ? store.all() : store.allForProject(projectId))
    .filter((l) => store.privateUseAllowed(l) && (includeRetired || store.current(l)) && matches(l, filter))
    .sort((a, b) => b.importance - a.importance)
    .map((l) => ({ id: l.id, kind: l.kind, scope: l.scope, importance: l.importance, tier: l.tier, origin: l.origin, createdTs: l.createdTs }));
}

export interface MemoryDetail {
  readonly id: string; readonly content?: string; readonly kind: MemoryKind; readonly scope: MemoryScope;
  readonly tier: TrustTier; readonly origin: Origin; readonly provenanceEventId: string;
  readonly importance: number; readonly evidenceCount: number; readonly createdTs: number; readonly citation?: string;
  readonly custody?: MemoryCustody;
  readonly useStatus?: "retained" | "expired-pending-erasure" | "source-not-current" | "retention-policy";
  readonly validFrom: number; readonly validTo?: number;
}

/** Review one memory with FULL provenance (origin, the spine event it was recorded under, evidence, lineage citation). */
export function memoryReview(store: MemoryStore, id: string, projectId?: string): MemoryDetail | null {
  const l = projectId === undefined ? store.get(id) : store.getForProject(projectId, id);
  if (!l) return null;
  const expired = store.useExpired(l);
  const sourceNotCurrent = l.custody?.schema === "keep.memory.derived-custody/v1" && !store.current(l);
  const policyWithheld = !store.privateUseAllowed(l);
  const withheld = expired || sourceNotCurrent || policyWithheld;
  return {
    id: l.id, ...(withheld ? {} : { content: l.content }), kind: l.kind, scope: l.scope, tier: l.tier, origin: l.origin,
    provenanceEventId: l.provenanceEventId, importance: l.importance, evidenceCount: l.evidence.length,
    createdTs: l.createdTs, validFrom: l.validFrom, ...(l.validTo === undefined ? {} : { validTo: l.validTo }),
    ...(!withheld && l.citation !== undefined ? { citation: l.citation } : {}),
    ...(l.custody === undefined ? {} : { custody: l.custody, useStatus: expired ? "expired-pending-erasure" as const : sourceNotCurrent ? "source-not-current" as const : policyWithheld ? "retention-policy" as const : "retained" as const }),
  };
}

/**
 * Purge = BULK RETIRE (supersede-not-delete) every LIVE memory matching the filter. REQUIRES an explicit non-empty
 * filter — an empty filter is refused (null) so there is no unbounded wipe. Purged memories become retired (still
 * present, spine-audited); nothing is hard-deleted. Returns the retired ids, or null if the filter was empty.
 */
export function memoryPurge(store: MemoryStore, filter: MemoryFilter, projectId?: string): { purged: number; ids: string[] } | null {
  if (emptyFilter(filter)) return null; // no unbounded wipe — an explicit filter is mandatory
  const ids: string[] = [];
  for (const l of projectId === undefined ? store.all() : store.allForProject(projectId)) {
    if (l.tier === "retired" || !matches(l, filter)) continue;
    if ((projectId === undefined ? store.retire(l.id, "purge (bulk-retire, supersede-not-delete)") : store.retireForProject(projectId, l.id, "purge (bulk-retire, supersede-not-delete)"))) ids.push(l.id);
  }
  return { purged: ids.length, ids };
}
