/**
 * Memory model (Phase 1) — procedural lessons with objective-anchored trust tiers.
 *
 * Keep's moat: procedural lessons (coding patterns, review conventions, tool-use
 * habits) that graduate from probation to confirmed ONLY via verified build
 * outcomes — never by assertion. Aligned with OWASP ASI06 (2026): every memory
 * carries provenance (spine-bound), origin, and a trust tier; retrieval is
 * trust-aware; graduation is objective.
 *
 * Trust tiers (the lifecycle the field says most tools lack):
 *   candidate  — just observed/ingested, untrusted, cannot authorize actions
 *   probation  — under evaluation; can inform, still cannot authorize
 *   confirmed  — passed BOTH gates via verified outcomes; trusted
 *   retired    — superseded, decayed, or demoted; excluded from retrieval
 */

import { privateRetentionAllowed, type CapturedMemoryRetentionPolicy, type PrivateSourceRetention } from "./retention.js";

export type TrustTier = "candidate" | "probation" | "confirmed" | "retired";

/** Where a lesson came from (ASI06 provenance: separate stated facts from inferences). */
export type Origin =
  | "self" // distilled from Keep's own observed build outcomes
  | "external" // imported (cross-project transfer, team library)
  | "seeded"; // research starter corpus (borrowed, unverified)

/** A single verified-outcome data point supporting (or against) a lesson. */
export interface OutcomeEvidence {
  /** The spine event id this outcome was recorded under (provenance binding). */
  readonly spineEventId: string;
  /** Did applying/holding this lesson correspond to a clean-resolved build? */
  readonly cleanResolved: boolean;
  /** Distinct context (project/repo) this was observed in — for cross-context proof. */
  readonly context: string;
  readonly ts: number;
}

export interface Lesson {
  readonly id: string;
  /** Immutable admission facts. Absent on legacy/ephemeral rows; never inferred on read. */
  readonly custody?: MemoryCustody;
  /** The procedural content (a convention, a check, an avoid-this rule). */
  content: string;
  tier: TrustTier;
  readonly origin: Origin;
  /** Admission event identity: spine id for ephemeral writes; atomic memory-outbox id for durable writes,
   * linked from the spine's memoryEventId when delivered. An undelivered outbox is audit-pending, not rollback. */
  readonly provenanceEventId: string;
  /**
   * If this lesson is coupled to a specific model's behavioral quirks, the model
   * id/version it was learned against (R18). Model-coupled lessons demote on a
   * model swap; codebase-fact lessons do not.
   */
  modelDependency?: string;
  /** For seeded lessons: the research citation, so borrowed priors are auditable. */
  citation?: string;
  /** The scope this lesson lives in (user / project / global). */
  readonly scope: MemoryScope;
  /** Semantic taxonomy (fact / preference / decision / procedure). */
  readonly kind: MemoryKind;
  /** Salience 0..1 — explicit or DERIVED from tier + corroboration (never fabricated); ranks retrieval. */
  importance: number;
  /** Accumulated verified-outcome evidence. */
  readonly evidence: OutcomeEvidence[];
  /** Record time (transaction-time axis): when this lesson was WRITTEN. Never mutated — supersede-not-delete preserves it. */
  readonly createdTs: number;
  /** Valid-time (story-time axis) START: when the fact begins HOLDING in the world. Distinct from createdTs. */
  readonly validFrom: number;
  /** Valid-time END (exclusive); undefined = open interval / still holds. Closed by a correction retro-edit, never re-opened. */
  validTo?: number;
}

export type MemoryScope = "user" | "project" | "global" | "agent";

/** Facts about custody, not a claim that the remembered assertion is true or legally qualified. */
export interface ManualMemoryCustody {
  readonly schema: "keep.memory.manual-custody/v1";
  readonly scope: { readonly ownerId: string; readonly kind: MemoryScope; readonly tenantId?: string; readonly projectId?: string; readonly agentId?: string };
  readonly source: { readonly kind: "authenticated-manual-command"; readonly operationId: string; readonly actorId: string; readonly actorKind: string };
  readonly consentEventId: string;
  readonly purpose: "explicit-manual-memory";
  readonly assertion: "asserted";
  readonly uncertainty: "unassessed";
  readonly authority: "none";
  /** A use deadline, NOT proof that expired bytes have been erased. Null means until revoked. */
  readonly retention: { readonly useUntil: number | null; readonly expiryDisposition: "withhold-pending-erasure"; readonly legalHoldAssessment: "unassessed" };
  readonly residency: { readonly storage: "operator-host"; readonly region: "unverified"; readonly embeddingProcessing: "local" | "external" };
  readonly dependencies: { readonly embeddingProvider: string; readonly embeddingModel: null };
  readonly derivatives: { readonly coEncrypted: readonly ["embedding", "access"]; readonly outsideCustody: "caller-provider-backup-copies-untracked" };
  readonly supersedes?: string;
}

/** Retained manual source without an embedding; not a promise about later consented model use. */
export interface SourceOnlyManualMemoryCustody extends Omit<ManualMemoryCustody, "schema" | "residency" | "dependencies" | "derivatives"> {
  readonly schema: "keep.memory.manual-custody/v2";
  readonly residency: { readonly storage: "operator-host"; readonly region: "unverified"; readonly embeddingProcessing: "none" };
  readonly dependencies: { readonly embeddingProvider: null; readonly embeddingModel: null };
  readonly derivatives: { readonly coEncrypted: readonly ["access"]; readonly outsideCustody: "caller-provider-backup-copies-untracked" };
}

/** Exact private source under explicit host retention policy; no embedding at admission. */
export interface PrivateSourceMemoryCustody extends Omit<SourceOnlyManualMemoryCustody, "schema"> {
  readonly schema: "keep.memory.manual-custody/v3";
  readonly privateSource: Omit<PrivateSourceRetention, "useUntil">;
}
export type RetainedManualMemoryCustody = SourceOnlyManualMemoryCustody | PrivateSourceMemoryCustody;

export function memoryUseExpired(lesson: Lesson, now: number): boolean {
  const until = lesson.custody?.retention.useUntil;
  return until !== undefined && until !== null && now >= until;
}

/** A navigation view of retained sources, never another independent assertion. */
export interface DerivedMemoryCustody {
  readonly schema: "keep.memory.derived-custody/v1";
  readonly scope: ManualMemoryCustody["scope"];
  readonly source: { readonly kind: "host-extractive-command"; readonly operationId: string; readonly actorId: string; readonly actorKind: string };
  readonly consentEventId: string;
  readonly purpose: "source-preserving-memory";
  readonly assertion: "derived";
  readonly uncertainty: "unassessed";
  readonly authority: "none";
  readonly algorithm: "extractive-v1";
  readonly sources: readonly MemoryExcerptSource[];
  readonly retention: ManualMemoryCustody["retention"];
  readonly residency: { readonly storage: "operator-host"; readonly region: "unverified"; readonly embeddingProcessing: "none" };
  readonly dependencies: { readonly embeddingProvider: null; readonly embeddingModel: null };
  readonly derivatives: { readonly coEncrypted: readonly ["sources", "access"]; readonly outsideCustody: "caller-provider-backup-copies-untracked" };
  readonly supersedes?: never;
}
export type MemoryCustody = ManualMemoryCustody | RetainedManualMemoryCustody | DerivedMemoryCustody;
export interface MemoryExcerptSource {
  readonly itemId: string;
  readonly provenanceEventId: string;
  readonly startByte: number;
  readonly endByte: number;
}
export const MAX_MEMORY_VIEW_SOURCES = 8, MAX_MEMORY_EXCERPT_BYTES = 512;
const MAX_MEMORY_SOURCE_CLOSURE = 128, MAX_MEMORY_SOURCE_DEPTH = 16;

/** Byte-exact excerpts from stored text; no second sanitizer or model transformation. */
export function memoryExcerptText(sources: readonly MemoryExcerptSource[], byId: ReadonlyMap<string, Lesson>): string {
  if (sources.length < 2 || sources.length > MAX_MEMORY_VIEW_SOURCES || new Set(sources.map(s => s.itemId)).size !== sources.length) throw new Error("invalid memory sources");
  return sources.map(source => {
    const parent = byId.get(source.itemId);
    if (!parent || parent.provenanceEventId !== source.provenanceEventId) throw new Error("missing memory source");
    const bytes = Buffer.from(parent.content, "utf8");
    if (!Number.isSafeInteger(source.startByte) || !Number.isSafeInteger(source.endByte)
      || source.startByte < 0 || source.endByte <= source.startByte || source.endByte > bytes.length
      || source.endByte - source.startByte > MAX_MEMORY_EXCERPT_BYTES) throw new Error("invalid memory span");
    const part = bytes.subarray(source.startByte, source.endByte);
    const text = part.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(part)) throw new Error("memory span splits UTF-8");
    return text;
  }).join("\n\n");
}

/** Structural source closure only. Retired history must remain loadable for control operations. */
export function memorySourceClosure(lesson: Lesson, byId: ReadonlyMap<string, Lesson>): readonly Lesson[] | undefined {
  const result = new Map<string, Lesson>(), active = new Set<string>();
  const visit = (item: Lesson, depth: number): boolean => {
    if (depth > MAX_MEMORY_SOURCE_DEPTH || active.has(item.id)) return false;
    if (result.has(item.id)) return true;
    if (result.size >= MAX_MEMORY_SOURCE_CLOSURE) return false;
    result.set(item.id, item); active.add(item.id);
    const custody = item.custody;
    if (custody?.schema === "keep.memory.derived-custody/v1") {
      if (custody.algorithm !== "extractive-v1") return false;
      try { if (memoryExcerptText(custody.sources, byId) !== item.content) return false; } catch { return false; }
      for (const source of custody.sources) {
        const parent = byId.get(source.itemId), pc = parent?.custody;
        if (!parent || !pc || pc.consentEventId !== custody.consentEventId
          || (["ownerId", "kind", "tenantId", "projectId", "agentId"] as const).some(key => pc.scope[key] !== custody.scope[key])
          || !visit(parent, depth + 1)) return false;
      }
    }
    active.delete(item.id); return true;
  };
  return visit(lesson, 0) ? [...result.values()] : undefined;
}

/** Shared read mediator: derived data is current only while every supporting source is current. */
export function memoryPrivateUseAllowed(lesson: Lesson, now: number, byId: ReadonlyMap<string, Lesson>, policy?: CapturedMemoryRetentionPolicy): boolean {
  const closure = memorySourceClosure(lesson, byId);
  return closure !== undefined && closure.every(item => {
    const c = item.custody;
    return c?.schema !== "keep.memory.manual-custody/v3" || privateRetentionAllowed(policy,
      c.scope.tenantId === undefined ? "owner" : "organization", c.privateSource.purpose, item.createdTs, c.retention.useUntil, now);
  });
}

export function memoryCurrentWithSourcesAt(lesson: Lesson, now: number, byId: ReadonlyMap<string, Lesson>): boolean {
  const closure = memorySourceClosure(lesson, byId);
  return Number.isFinite(now) && closure !== undefined && closure.every(item => memoryCurrentAt(item, now));
}

/** Current-use eligibility, never authorization. Administrative inspection is a separate operation. */
export function memoryCurrentAt(lesson: Lesson, now: number): boolean {
  return lesson.tier !== "retired" && !memoryUseExpired(lesson, now)
    && lesson.validFrom <= now && (lesson.validTo === undefined || now < lesson.validTo);
}

/** Semantic taxonomy: what KIND of memory this is. Existing procedural lessons default to "procedure". */
export type MemoryKind = "fact" | "preference" | "decision" | "procedure";

/** Count of distinct contexts in which this lesson was clean-resolved. */
export function distinctCleanContexts(lesson: Lesson): number {
  const ctx = new Set<string>();
  for (const e of lesson.evidence) {
    if (e.cleanResolved) ctx.add(e.context);
  }
  return ctx.size;
}

/** Count of clean vs. failed outcomes (for demotion / negative-flip detection). */
export function outcomeTally(lesson: Lesson): { clean: number; failed: number } {
  let clean = 0;
  let failed = 0;
  for (const e of lesson.evidence) {
    if (e.cleanResolved) clean++;
    else failed++;
  }
  return { clean, failed };
}
