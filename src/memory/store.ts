/**
 * MemoryStore (Phase 1) — the trust-tiered, objective-anchored procedural memory.
 *
 * Ties together: the ingestion gate (sanitize before store), spine-bound provenance
 * (every lesson records its origin event), the two-gate graduation (the moat), and
 * trust-aware retrieval via the model gateway (the ASI06 read-mediator against
 * query-only poisoning like MINJA — untrusted memory can inform, never authorize).
 *
 * Graduation is the whole point: a lesson goes probation -> confirmed ONLY when it
 * passes BOTH gates on verified outcomes. It never graduates by assertion.
 */

import { CryptoShredKeyStore, type SubjectId } from "../keystore/keystore.js";
import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { Spine } from "../spine/spine.js";
import type { ModelGateway, Embedding } from "../gateway/gateway.js";
import { cosineSimilarity } from "../gateway/gateway.js";
import type { Lesson, Origin, MemoryScope, MemoryKind, OutcomeEvidence, TrustTier, RetainedManualMemoryCustody } from "./model.js";
import { selectSourceMemoryRecall } from "./task_context.js";
import { applyForgetting, type ForgetConfig, type RetentionDecision, type AccessInfo } from "./forgetting.js";
import { TemporalKnowledgeGraph, type TkgEdge } from "./temporal_kg.js";
import { outcomeTally, memoryUseExpired, memoryCurrentWithSourcesAt, memoryPrivateUseAllowed } from "./model.js";
import { admitPrivateMemorySource, type CapturedMemoryRetentionPolicy } from "./retention.js";
import { scanIngestion } from "./ingestion.js";
import { MemoryConsensus, type ConsensusLesson } from "./consensus.js";
import { evaluatePromotion, type FunctionalGateConfig, DEFAULT_FUNCTIONAL_CONFIG } from "./gates.js";
import type { MemoryPartitionScope, MemoryPartitionView, PersistedMemoryEntry } from "./persistence.js";

export interface IngestOptions {
  readonly origin: Origin;
  readonly scope?: MemoryScope;
  readonly kind?: MemoryKind;
  readonly importance?: number;
  readonly modelDependency?: string;
  readonly citation?: string;
  /** Required when scope === "agent": the isolation subject. A single-agent (n=1) caller never sets this. */
  readonly agentId?: string;
  /** P-7: the tenant (project) isolation subject for a project-scoped lesson. Absent (n=1) → project-scope stays shared. */
  readonly projectId?: string;
  /** Valid-time start (when the fact begins holding). Defaults to record time (createdTs) — the n=1 path never sets it. */
  readonly validFrom?: number;
  /** Valid-time end (exclusive); undefined = open interval. */
  readonly validTo?: number;
}

export interface RetrievalHit {
  readonly lesson: Lesson;
  readonly similarity: number;
  /** Trust-weighted score used for ranking (confirmed >> probation). */
  readonly score: number;
}

/** Fully prepared, still invisible input to the synchronous publication boundary. */
interface PreparedLesson {
  readonly item: Omit<Lesson, "provenanceEventId">;
  readonly options: IngestOptions;
  readonly embedding?: Embedding;
  readonly findings: readonly string[];
}

const TIER_WEIGHT: Record<TrustTier, number> = {
  confirmed: 1.0,
  probation: 0.4,
  candidate: 0.2,
  retired: 0.0,
};

/** Derive a 0..1 importance from trust tier + corroboration count. Bounded [0,1] + MONOTONE in evidence. Honest: no fabrication. */
export function deriveImportance(tier: TrustTier, evidenceCount: number): number {
  const base = TIER_WEIGHT[tier] * 0.7;                                  // tier floor (confirmed >> candidate)
  const boost = Math.min(0.3, Math.max(0, evidenceCount) * 0.1);         // corroboration lifts salience, capped
  return Math.min(1, base + boost);
}

/** Retrieval rank: semantic similarity, trust-weighted, importance-MODULATED (importance lifts but never zeroes similarity). */
export function lessonRankScore(similarity: number, tierWeight: number, importance: number): number {
  return similarity * tierWeight * (0.5 + 0.5 * importance);
}

export class MemoryStore {
  private partitionScope: MemoryPartitionScope | undefined;
  private sourceCustody: RetainedManualMemoryCustody | undefined;
  private retentionPolicy: CapturedMemoryRetentionPolicy | undefined;
  private readonly lessons = new Map<string, Lesson>();
  /** MEM-MAINTENANCE: access reinforcement — per-lesson last-accessed ts + retrieval count. In-memory, one entry/lesson. */
  private readonly accessLog = new Map<string, { lastAccessedTs: number; count: number }>();
  private readonly embeddings = new Map<string, Embedding>();
  // M2: per-agent retrieval isolation. Agent-scoped lessons are indexed per agent SUBJECT — the same per-subject unit
  // the CryptoShredKeyStore (and the episodic track) uses for isolation + erasure. retrieve() only ever reads the
  // shared space + the querying agent's OWN bucket; another agent's agent-scoped ids are never in the candidate set.
  private readonly agentKeys = new CryptoShredKeyStore();
  private readonly sharedIds = new Set<string>();
  private readonly agentIndex = new Map<SubjectId, Set<string>>();
  private readonly agentOwner = new Map<string, SubjectId>();
  // P-7: tenant (project) isolation — the SAME CryptoShredKeyStore primitive + the M2 partition pattern, one dimension over.
  // A project-scoped lesson ingested under a tenant lives ONLY in that tenant's bucket; another tenant never iterates it.
  private readonly tenantKeys = new CryptoShredKeyStore();
  private readonly tenantIndex = new Map<SubjectId, Set<string>>();
  /** Structural owner metadata for tenant-scoped lessons; used by consensus and audit, never caller filtering. */
  private readonly tenantOwner = new Map<string, SubjectId>();

  constructor(
    private readonly spine: Pick<Spine, "stage">,
    private readonly gateway: ModelGateway,
    private readonly functionalConfig: FunctionalGateConfig = DEFAULT_FUNCTIONAL_CONFIG,
    private readonly clock: () => number = () => Date.now(),
    /**
     * C2: optional dual-memory consensus gate. When present, a lesson may reach the CONFIRMED (retrieval-
     * trusted) tier ONLY if it also reaches independent-origin consensus — a single poisoned write cannot
     * graduate on its own evidence. Absent → the two-gate graduation stands alone (N=1/floor still works).
     */
    private readonly consensus?: MemoryConsensus,
  ) {}

  /** Detached working copy for one already-selected complete partition; not caller authentication. */
  static fromPartition(view: MemoryPartitionView, spine: Pick<Spine, "stage">, gateway: ModelGateway, clock: () => number = Date.now, sourceCustody?: RetainedManualMemoryCustody, retentionPolicy?: CapturedMemoryRetentionPolicy): MemoryStore {
    const store = new MemoryStore(spine, gateway, DEFAULT_FUNCTIONAL_CONFIG, clock);
    store.partitionScope = structuredClone(view.scope);
    store.retentionPolicy = retentionPolicy;
    if (sourceCustody !== undefined) {
      if (!isDeepStrictEqual(sourceCustody.scope, view.scope)) throw new Error("source custody conflicts with selected partition");
      store.sourceCustody = structuredClone(sourceCustody);
    }
    for (const row of view.entries) {
      const entry = structuredClone(row);
      store.lessons.set(entry.lesson.id, entry.lesson);
      if (entry.embedding !== undefined) store.embeddings.set(entry.lesson.id, [...entry.embedding]);
      store.accessLog.set(entry.lesson.id, { ...entry.access });
    }
    return store;
  }

  /** Detached serializable publication input; callers cannot mutate this store through it. */
  partitionEntries(): PersistedMemoryEntry[] {
    if (!this.partitionScope) throw new Error("memory store is not a complete partition working copy");
    return [...this.lessons.values()].map(lesson => {
      const embedding = this.embeddings.get(lesson.id);
      if (!embedding && !["keep.memory.derived-custody/v1", "keep.memory.manual-custody/v2", "keep.memory.manual-custody/v3"].includes(lesson.custody?.schema ?? "")) throw new Error("memory partition derivative is missing");
      return structuredClone({ lesson, ...(embedding === undefined ? {} : { embedding }), access: this.accessLog.get(lesson.id) ?? { count: 0, lastAccessedTs: lesson.createdTs } });
    });
  }

  /**
   * Ingest a candidate lesson. Runs the ingestion gate first (reject copyleft,
   * redact secrets/PII), binds provenance to a spine event, and stores it at the
   * lowest trust tier. Seeded lessons enter on probation with a citation.
   * Returns the stored lesson, or undefined if rejected at ingestion.
   */
  async ingest(content: string, opts: IngestOptions): Promise<Lesson | undefined> {
    const prepared = await this.prepare(content, opts);
    return prepared === undefined ? undefined : this.publish(prepared);
  }

  /** Prepare a replacement without retiring the old item or admitting a partial successor. */
  async correct(id: string, content: string, projectId?: string): Promise<{ oldId: string; newId: string } | null> {
    const old = projectId === undefined ? this.get(id) : this.getForProject(projectId, id);
    if (!old || old.tier === "retired" || this.useExpired(old) || !this.privateUseAllowed(old)) return null;
    const expected = structuredClone(old);
    const tenant = this.tenantOwner.get(id);
    const agent = this.agentOwner.get(id);
    const prepared = await this.prepare(content, {
      origin: "self", kind: old.kind, scope: old.scope, citation: `supersedes:${id}`,
      ...(tenant === undefined ? {} : { projectId: tenant }),
      ...(agent === undefined ? {} : { agentId: agent }),
    });
    if (!prepared) return null;
    // Another operation can change the old item while the provider is preparing its replacement.
    // Compare the complete semantic state, including evidence and validity, before publishing.
    const current = projectId === undefined ? this.get(id) : this.getForProject(projectId, id);
    if (!current || current.tier === "retired" || this.useExpired(current) || !isDeepStrictEqual(current, expected)) return null;
    const fresh = this.publish(prepared, this.lessons.get(current.id)!);
    return { oldId: id, newId: fresh.id };
  }

  private async prepare(content: string, input: IngestOptions): Promise<PreparedLesson | undefined> {
    // Capture scope before awaiting a provider; later caller mutation cannot redirect publication.
    const opts = { ...input };
    if (this.partitionScope) {
      const scope = this.partitionScope;
      if ((opts.scope !== undefined && opts.scope !== scope.kind) || (opts.projectId !== undefined && opts.projectId !== scope.projectId)
        || (opts.agentId !== undefined && opts.agentId !== scope.agentId)) throw new Error("memory operation conflicts with selected partition");
      opts.scope = scope.kind;
      if (scope.projectId !== undefined) opts.projectId = scope.projectId;
      if (scope.agentId !== undefined) opts.agentId = scope.agentId;
    }
    if (opts.scope === "agent" && (opts.agentId === undefined || opts.agentId.length === 0)) {
      throw new Error("agent-scoped lesson requires an agentId");
    }
    const privateCustody = this.sourceCustody?.schema === "keep.memory.manual-custody/v3" ? this.sourceCustody : undefined;
    const privateAt = privateCustody === undefined ? undefined : this.clock();
    const admission = privateCustody === undefined ? undefined : admitPrivateMemorySource(this.retentionPolicy,
      this.partitionScope?.tenantId === undefined ? "owner" : "organization",
      { content, purpose: privateCustody.privateSource.purpose, useUntil: privateCustody.retention.useUntil }, privateAt!);
    const scan = admission === undefined ? scanIngestion(content) : admission.accepted && privateCustody!.privateSource.policyIdentity === this.retentionPolicy?.identity
      ? { decision: "accept" as const, sanitized: admission.content, findings: admission.findings }
      : { decision: "reject" as const, sanitized: "", findings: admission.accepted ? ["policy:private-retention"] : [...admission.findings, "private-source:" + admission.reason] };
    if (scan.decision === "reject") {
      this.spine.stage({
        type: "identity.action",
        actor: "memory",
        payload: { event: "ingest_rejected", findings: scan.findings, ...(opts.projectId === undefined ? {} : { tenant: opts.projectId }) },
      });
      return undefined;
    }
    const vec = this.sourceCustody === undefined ? (await this.gateway.embed([scan.sanitized]))[0] : undefined;
    if (this.sourceCustody === undefined && (!vec || vec.length === 0 || !vec.every(Number.isFinite))) throw new Error("embedding backend returned an invalid memory vector");
    // Seeded (borrowed) lessons start on probation; everything else starts candidate.
    const tier: TrustTier = opts.origin === "seeded" ? "probation" : "candidate";
    const createdTs = privateAt ?? this.clock();
    const item: Omit<Lesson, "provenanceEventId"> = {
      id: randomUUID(),
      ...(this.sourceCustody === undefined ? {} : { custody: structuredClone(this.sourceCustody) }),
      content: scan.sanitized,
      tier,
      origin: opts.origin,
      scope: opts.scope ?? "project",
      kind: opts.kind ?? "procedure",
      importance: opts.importance ?? deriveImportance(tier, 0),
      evidence: [],
      createdTs,
      // Valid-time (story-time) DISTINCT from record time: defaults to createdTs, but a caller can assert a past/future validity.
      validFrom: opts.validFrom ?? createdTs,
      ...(opts.modelDependency !== undefined ? { modelDependency: opts.modelDependency } : {}),
      ...(opts.citation !== undefined ? { citation: opts.citation } : {}),
      ...(opts.validTo !== undefined ? { validTo: opts.validTo } : {}),
    };
    return { item, options: opts, ...(vec === undefined ? {} : { embedding: [...vec] }), findings: scan.findings };
  }

  /**
   * One synchronous publication for the current ephemeral backend. Key preparation and audit
   * failure precede visible item changes; correction has no await between retirement and insertion.
   * This is not a disk transaction: the durable backend must commit this same operation atomically.
   */
  private publish(prepared: PreparedLesson, superseded?: Lesson): Lesson {
    const { item, options: opts } = prepared;
    if (item.scope === "agent") this.agentKeys.ensureKey(opts.agentId!);
    else if (item.scope === "project" && opts.projectId !== undefined) this.tenantKeys.ensureKey(opts.projectId);
    const provenanceEventId = this.spine.stage({
      type: "identity.action", actor: "memory",
      payload: {
        event: superseded === undefined ? "lesson_ingested" : "lesson_corrected",
        lessonId: item.id, origin: item.origin, findings: prepared.findings,
        ...(item.custody?.schema === "keep.memory.manual-custody/v3" || prepared.findings.length ? { ingestion: {
          decision: item.custody?.schema === "keep.memory.manual-custody/v3" ? "accept" : "redact",
          representation: item.custody?.schema === "keep.memory.manual-custody/v3" ? "exact-private-source" : "sanitized-source",
          findings: prepared.findings,
        } } : {}),
        ...(this.partitionScope === undefined ? (opts.projectId === undefined ? {} : { tenant: opts.projectId }) : {
          ownerId: this.partitionScope.ownerId,
          ...(this.partitionScope.tenantId === undefined ? {} : { tenant: this.partitionScope.tenantId }),
          ...(this.partitionScope.projectId === undefined ? {} : { projectId: this.partitionScope.projectId }),
        }),
        ...(opts.agentId === undefined ? {} : { agentId: opts.agentId }),
        ...(superseded === undefined ? {} : { supersedes: superseded.id, validTo: item.validFrom }),
      },
    });
    const lesson: Lesson = { ...item, provenanceEventId };
    if (superseded !== undefined) {
      superseded.tier = "retired";
      superseded.validTo = lesson.validFrom;
    }
    this.lessons.set(lesson.id, lesson);
    // M2: route the id into the shared space or the agent's isolated bucket (structural, not a post-hoc filter).
    if (lesson.scope === "agent") {
      const agentId = opts.agentId!; // checked during preparation, before provider work
      let bucket = this.agentIndex.get(agentId);
      if (!bucket) { bucket = new Set<string>(); this.agentIndex.set(agentId, bucket); }
      bucket.add(lesson.id);
      this.agentOwner.set(lesson.id, agentId);
    } else if (lesson.scope === "project" && opts.projectId !== undefined) {
      // P-7: tenant-isolated project memory. (n=1 project-scope with no projectId falls through to sharedIds — unchanged.)
      let bucket = this.tenantIndex.get(opts.projectId);
      if (!bucket) { bucket = new Set<string>(); this.tenantIndex.set(opts.projectId, bucket); }
      bucket.add(lesson.id);
      this.tenantOwner.set(lesson.id, opts.projectId);
    } else {
      this.sharedIds.add(lesson.id);
    }
    if (prepared.embedding !== undefined) this.embeddings.set(lesson.id, prepared.embedding);
    return this.readView(lesson);
  }

  /**
   * Record a verified build outcome for a lesson (provenance-bound to the spine),
   * then re-evaluate graduation/demotion. This is the objective anchor.
   */
  recordOutcome(lessonId: string, cleanResolved: boolean, context: string): void {
    if (this.partitionScope) throw new Error("durable learning promotion requires independent qualification");
    const lesson = this.lessons.get(lessonId);
    if (!lesson) throw new Error(`no lesson ${lessonId}`);
    const spineEventId = this.spine.stage({
      type: "identity.action",
      actor: "memory",
      payload: { event: "outcome_recorded", lessonId, cleanResolved, context, ...this.tenantPayload(lessonId) },
    });
    const ev: OutcomeEvidence = { spineEventId, cleanResolved, context, ts: this.clock() };
    lesson.evidence.push(ev);
    this.reevaluate(lesson);
  }

  /**
   * Retire a lesson: supersede-not-delete. Sets the tier to `retired` (the lesson stays present, so provenance is
   * retained) and stages a spine event for the audit trail. Idempotent — retiring an already-retired lesson is a
   * no-op (no duplicate event). Returns true iff a live lesson was retired by this call. This is the store's
   * mutation surface for the upkeep apply adapter's supersede/prune.
   */
  /** Manual importance update (M3 `update`): clamp to [0,1] + stage a spine event. Returns true iff the lesson exists. */
  reweight(lessonId: string, importance: number): boolean {
    const lesson = this.lessons.get(lessonId);
    if (!lesson || lesson.tier === "retired") return false;
    const clamped = Math.min(1, Math.max(0, importance));
    this.spine.stage({ type: "identity.action", actor: "memory", payload: { event: "lesson_reweighted", lessonId, importance: clamped, ...this.tenantPayload(lessonId) } });
    lesson.importance = clamped;
    return true;
  }

  retire(lessonId: string, reason: string): boolean {
    const lesson = this.lessons.get(lessonId);
    if (!lesson || lesson.tier === "retired") return false; // idempotent: no-op if absent or already retired
    this.spine.stage({
      type: "identity.action",
      actor: "memory",
      payload: { event: "lesson_retired", lessonId, reason, ...this.tenantPayload(lessonId) },
    });
    lesson.tier = "retired";
    return true;
  }

  /**
   * C2 consensus gate. Absent consensus → always true (floor). Present → each verified outcome is fed as an
   * independent corroboration (keyed by its distinct spine origin event, so flooding from one origin cannot
   * manufacture agreement), and the lesson graduates only if the verdict is "trusted".
   */
  private hasConsensus(lesson: Lesson): boolean {
    if (!this.consensus) return true;
    const cl: ConsensusLesson = { id: lesson.id, content: lesson.content, provenanceEventId: lesson.provenanceEventId, relevanceKey: lesson.scope };
    for (const ev of lesson.evidence) {
      this.consensus.corroborate(lesson.id, { originEventId: ev.spineEventId, agrees: ev.cleanResolved });
    }
    // SSGM veto (store owns this domain check): if an already-CONFIRMED lesson asserts a DIFFERENT value for
    // the same subject key, this candidate is a contradiction — it cannot graduate alongside the confirmed
    // truth (the canonical re-routing poison). Also pass confirmed contents to the consensus's own negation
    // check, so logical negations are caught too.
    if (this.contradictsConfirmedSubject(lesson)) return false;
    const contradictors = this.confirmedContents(lesson);
    return this.consensus.evaluate(cl, contradictors).verdict === "trusted";
  }

  /** True if a confirmed lesson shares this lesson's subject key but asserts a different value. */
  private contradictsConfirmedSubject(lesson: Lesson): boolean {
    const self = parseSubjectValue(lesson.content);
    if (!self) return false;
    for (const other of this.lessons.values()) {
      if (other.id === lesson.id || other.tier !== "confirmed" || !this.sameTenantPartition(lesson.id, other.id)) continue;
      const os = parseSubjectValue(other.content);
      if (os && norm(os.subject) === norm(self.subject) && norm(os.value) !== norm(self.value)) return true;
    }
    return false;
  }

  /** Contents of confirmed lessons (for the consensus layer's own negation-based contradiction check). */
  private confirmedContents(lesson: Lesson): readonly string[] {
    const out: string[] = [];
    for (const other of this.lessons.values()) {
      if (other.id !== lesson.id && other.tier === "confirmed" && this.sameTenantPartition(lesson.id, other.id)) out.push(other.content);
    }
    return out;
  }

  private sameTenantPartition(leftId: string, rightId: string): boolean {
    if (this.partitionScope) return this.lessons.has(leftId) && this.lessons.has(rightId);
    return this.lessons.get(leftId)?.scope === this.lessons.get(rightId)?.scope
      && this.tenantOwner.get(leftId) === this.tenantOwner.get(rightId) && this.agentOwner.get(leftId) === this.agentOwner.get(rightId);
  }
  private tenantPayload(lessonId: string): { readonly tenant?: string } {
    if (this.partitionScope) return this.partitionScope.tenantId === undefined ? {} : { tenant: this.partitionScope.tenantId };
    const tenant = this.tenantOwner.get(lessonId);
    return tenant === undefined ? {} : { tenant };
  }

  /** Promote if both gates pass; demote confirmed lessons on a negative-flip trend. */
  private reevaluate(lesson: Lesson): void {
    if (lesson.tier === "retired") return;

    if (lesson.tier === "candidate" || lesson.tier === "probation") {
      const decision = evaluatePromotion(lesson, this.functionalConfig);
      // Candidates advance to probation once they have any clean evidence.
      if (lesson.tier === "candidate" && lesson.evidence.some((e) => e.cleanResolved)) {
        lesson.tier = "probation";
      }
      if (lesson.tier === "probation" && decision.promotable && this.hasConsensus(lesson)) {
        lesson.tier = "confirmed";
        this.spine.stage({
          type: "identity.action",
          actor: "memory",
          payload: { event: "lesson_graduated", lessonId: lesson.id, ...this.tenantPayload(lesson.id) },
        });
      }
    } else if (lesson.tier === "confirmed") {
      // Negative-flip demotion: if failures now dominate, demote (poison/rot defense).
      const { clean, failed } = outcomeTally(lesson);
      if (failed > clean) {
        lesson.tier = "probation";
        this.spine.stage({
          type: "identity.action",
          actor: "memory",
          payload: { event: "lesson_demoted", lessonId: lesson.id, reason: "negative-flip", ...this.tenantPayload(lesson.id) },
        });
      }
    }
  }

  /**
   * Demote all lessons coupled to a deprecated model back to probation (R18).
   * They must re-earn graduation via outcomes under the new model.
   */
  demoteOnModelSwap(deprecatedModel: string): number {
    let count = 0;
    for (const lesson of this.lessons.values()) {
      if (lesson.modelDependency === deprecatedModel && lesson.tier === "confirmed") {
        lesson.tier = "probation";
        count++;
        this.spine.stage({
          type: "identity.action",
          actor: "memory",
          payload: { event: "lesson_demoted", lessonId: lesson.id, reason: "model-swap", deprecatedModel, ...this.tenantPayload(lesson.id) },
        });
      }
    }
    return count;
  }

  /**
   * Trust-aware retrieval (ASI06 read-mediator). Ranks by similarity * tier-weight,
   * so confirmed lessons dominate and retired lessons are excluded. `minTier`
   * lets callers require confirmed-only for authority-bearing decisions.
   */
  async retrieve(query: string, k: number, minTier: TrustTier = "candidate", agentId?: string, projectId?: string, includeShared = true): Promise<RetrievalHit[]> {
    if (this.partitionScope && ((agentId !== undefined && agentId !== this.partitionScope.agentId) || (projectId !== undefined && projectId !== this.partitionScope.projectId))) return [];
    const [qvec] = await this.gateway.embed([query]);
    if (!qvec) return [];
    const minWeight = TIER_WEIGHT[minTier];
    // M2 STRUCTURAL ISOLATION: the candidate id-set is the shared space + ONLY the querying agent's own bucket.
    // Another agent's agent-scoped ids are never considered — not filtered out, simply absent from the set.
    const candidateIds = new Set<string>(includeShared ? this.sharedIds : []);
    if (this.partitionScope) {
      if ((agentId !== undefined && agentId !== this.partitionScope.agentId) || (projectId !== undefined && projectId !== this.partitionScope.projectId)) return [];
      for (const id of this.lessons.keys()) candidateIds.add(id);
    }
    if (agentId !== undefined && this.agentKeys.hasKey(agentId)) {
      for (const id of this.agentIndex.get(agentId) ?? []) candidateIds.add(id);
    }
    // P-7: add ONLY the querying tenant's project bucket — another tenant's project-scoped ids are never considered.
    if (projectId !== undefined && this.tenantKeys.hasKey(projectId)) {
      for (const id of this.tenantIndex.get(projectId) ?? []) candidateIds.add(id);
    }
    const hits: RetrievalHit[] = [];
    for (const id of candidateIds) {
      const lesson = this.lessons.get(id);
      if (!lesson || lesson.tier === "retired" || (this.partitionScope && !this.current(lesson))) continue;
      const weight = TIER_WEIGHT[lesson.tier];
      if (weight < minWeight) continue;
      const vec = this.embeddings.get(id);
      if (!vec) continue;
      const similarity = cosineSimilarity(qvec, vec);
      hits.push({ lesson, similarity, score: lessonRankScore(similarity, weight, lesson.importance) });
    }
    hits.sort((a, b) => b.score - a.score);
    const top = hits.slice(0, k);
    // ACCESS REINFORCEMENT (hot path, O(k)): a retrieved memory decays-unless-reinforced-by-re-access (dev.to 2026).
    const at = this.clock();
    for (const h of top) {
      const prev = this.accessLog.get(h.lesson.id);
      this.accessLog.set(h.lesson.id, { lastAccessedTs: at, count: (prev?.count ?? 0) + 1 });
    }
    return this.readView(top);
  }

  /** Structural tenant view used by shared product surfaces: no global/default ids enter the candidate set. */
  retrieveForProject(query: string, k: number, projectId: string, minTier: TrustTier = "candidate"): Promise<RetrievalHit[]> {
    return this.retrieve(query, k, minTier, undefined, projectId, false);
  }

  useExpired(lesson: Lesson): boolean { return memoryUseExpired(lesson, this.clock()); }
  /** Explicit durable lexical recall, sharing source eligibility and passage ranking with native context. */
  recallSources(query: string, k: number, consentEventId: string): Lesson[] {
    if (!this.partitionScope) throw new Error("source recall requires an admitted partition");
    const at = this.clock();
    const hits = selectSourceMemoryRecall({ revision: 0, scope: this.partitionScope, entries: this.partitionEntries() }, consentEventId, query, k, at, this.retentionPolicy);
    for (const lesson of hits) this.accessLog.set(lesson.id, { lastAccessedTs: at, count: (this.accessLog.get(lesson.id)?.count ?? 0) + 1 });
    return this.readView(hits);
  }
  privateUseAllowed(lesson: Lesson): boolean { return memoryPrivateUseAllowed(lesson, this.clock(), this.lessons, this.retentionPolicy); }
  current(lesson: Lesson): boolean { return this.privateUseAllowed(lesson) && memoryCurrentWithSourcesAt(lesson, this.clock(), this.lessons); }

  ownsProjectLesson(projectId: string, id: string): boolean { return this.partitionScope ? this.partitionScope.projectId === projectId && this.lessons.has(id) : this.tenantIndex.get(projectId)?.has(id) === true; }
  getForProject(projectId: string, id: string): Lesson | undefined { return this.ownsProjectLesson(projectId, id) ? this.get(id) : undefined; }
  allForProject(projectId: string): Lesson[] {
    if (this.partitionScope) return this.partitionScope.projectId === projectId ? this.all() : [];
    return [...(this.tenantIndex.get(projectId) ?? [])].map((id) => this.lessons.get(id)).filter((lesson): lesson is Lesson => lesson !== undefined);
  }
  reweightForProject(projectId: string, id: string, importance: number): boolean { return this.ownsProjectLesson(projectId, id) && this.reweight(id, importance); }
  retireForProject(projectId: string, id: string, reason: string): boolean { return this.ownsProjectLesson(projectId, id) && this.retire(id, reason); }
  closeValidIntervalForProject(projectId: string, id: string, validTo: number): boolean { return this.ownsProjectLesson(projectId, id) && this.closeValidInterval(id, validTo); }

  /** The recorded access signal for a lesson (for the forgetting policy). Undefined = never retrieved. */
  accessOf(id: string): AccessInfo | undefined {
    return this.readView(this.accessLog.get(id));
  }

  /**
   * MEM-MAINTENANCE (background/explicit, NOT the hot path): run deliberate forgetting over the store using the recorded
   * access signal. Returns the EXPLAINABLE decisions. Retire-not-delete + the MEM-DECAY guardrails hold (a high-value or
   * recently-accessed memory is never retired). Operator/cadence-driven — never a hidden cron.
   */
  runMaintenance(cfg: Omit<ForgetConfig, "now"> & { readonly now?: number }): RetentionDecision[] {
    return applyForgetting(this, (id) => this.accessOf(id), { ...cfg, now: cfg.now ?? this.clock() });
  }

  /**
   * TKG-RECALL: structured graph recall — the current (or as-of-`worldTime`) typed relations of an entity, composed over
   * the TemporalKnowledgeGraph view (relationsOf/edgesAt). This COMPLEMENTS semantic `retrieve` (vector: "what is like
   * this?"); graph-recall answers "what is connected to this / what do I currently know about X?" (mem0/AgentMarketCap
   * 2026). HONEST: returns only DECLARED/STRUCTURED edges (deterministic, no LLM extraction) and inherits the as-of/
   * dilution caveat; invalidated edges are excluded from the current slice but remain visible in an as-of query of the
   * past. Read-only — never mutates.
   */
  recallEntity(subject: string, worldTime?: number): TkgEdge[] {
    return new TemporalKnowledgeGraph(this, this.clock).relationsOf(subject, worldTime ?? this.clock());
  }

  /**
   * VALID-AT (bitemporal valid-time query): every lesson whose valid interval [validFrom, validTo) contains `worldTime`.
   * This is world-history — independent of record-time tier — so a retired-via-correction fact still answers for the
   * window it held. Half-open interval: at exactly validTo the fact no longer holds (the successor does).
   */
  validAt(worldTime: number): Lesson[] {
    const out: Lesson[] = [];
    for (const l of this.lessons.values()) {
      if (l.validFrom <= worldTime && (l.validTo === undefined || worldTime < l.validTo)) out.push(l);
    }
    return this.readView(out);
  }

  /**
   * Close a lesson's valid interval at `validTo` (a correction retro-edit). Sets the valid-time END while leaving the
   * record (createdTs + the lesson itself) intact — supersede-not-delete. Idempotent-safe; audited to the spine.
   */
  closeValidInterval(id: string, validTo: number): boolean {
    const lesson = this.lessons.get(id);
    if (!lesson) return false;
    this.spine.stage({ type: "identity.action", actor: "memory", payload: { event: "valid_interval_closed", lessonId: id, validTo, ...this.tenantPayload(id) } });
    lesson.validTo = validTo;
    return true;
  }

  get(id: string): Lesson | undefined {
    return this.readView(this.lessons.get(id));
  }

  all(): Lesson[] {
    return this.readView([...this.lessons.values()]);
  }

  private readView<T>(value: T): T {
    if (!this.partitionScope) return value;
    const freeze = (item: unknown): void => {
      if (item !== null && typeof item === "object") { Object.values(item).forEach(freeze); Object.freeze(item); }
    };
    const copy = structuredClone(value); freeze(copy); return copy;
  }

  countByTier(): Record<TrustTier, number> {
    const counts: Record<TrustTier, number> = { candidate: 0, probation: 0, confirmed: 0, retired: 0 };
    for (const l of this.lessons.values()) counts[l.tier]++;
    return counts;
  }
}

/** Parse "subject => value" or "subject: value" from lesson content (C2 subject/value contradiction check). */
function parseSubjectValue(content: string): { subject: string; value: string } | null {
  const m = content.match(/^(.+?)\s*(?:=>|:)\s*(.+)$/);
  return m ? { subject: m[1]!.trim(), value: m[2]!.trim() } : null;
}
function norm(s: string): string { return s.toLowerCase().replace(/\s+/g, " ").trim(); }
