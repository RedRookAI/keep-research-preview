/**
 * Portable skill catalog and content-bound managed lifecycle.
 *
 * installSkill checks package integrity and a caller-supplied gate before catalog
 * storage. Catalog presence alone does not grant managed retrieval eligibility.
 * Managed admission binds lifecycle state to a content hash; composition also
 * checks canary state before retrieval. Supplied gates, outcomes and stores remain
 * trusted dependencies with different evidence levels. A hash detects differing
 * content; it does not authenticate the declared publisher or prove task utility.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { DistilledSkill, SkillAuthority } from "../loop/skill_distiller.js";
import { verifySkillProgram, type SkillPrograms } from "../loop/skill_program.js";
import { reuseSignal, type OutcomeSignal } from "../loop/self_improvement_bus.js";

export interface SkillPackage {
  readonly skill: DistilledSkill;
  /** sha256 over the canonical skill; integrity identity, not publisher authentication. */
  readonly contentHash: string;
  /** Declared publisher (not authenticated by the content hash). */
  readonly origin: string;
  readonly publishedAt: number;
}

/** The gate verdict — production wraps `SkillValidator` (and `SkillCanary` for rollout) behind this. */
export interface GateVerdict {
  readonly ok: boolean;
  readonly verdict: string;
  readonly reason?: string;
  /** Exact final candidate checked by a refining gate; omitted means unchanged input. */
  readonly checkedSkill?: DistilledSkill;
}

export interface RegistryStore {
  put(pkg: SkillPackage): void;
  get(id: string): SkillPackage | undefined;
  list(): readonly SkillPackage[];
  /** Optional synchronous atomic publication of a fully prepared catalog. */
  replaceAll?(packages: readonly SkillPackage[]): void;
}

export interface InstallDeps {
  readonly store: RegistryStore;
  /** Trusted catalog gate. Its verdict must name the checks actually performed; managed eligibility is separate. */
  readonly gate: (skill: DistilledSkill) => Promise<GateVerdict>;
}

export type InstallResult =
  | { readonly ok: true; readonly pkg: SkillPackage; readonly assessment: { readonly verdict: string; readonly inputContentHash: string; readonly contentHash: string } }
  | { readonly ok: false; readonly reason: "tampered" | "rejected-unsafe" | "held-legacy-retired"; readonly detail: string };

/** Deterministic canonical JSON (recursively key-sorted) so the content hash is stable across machines. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

function hashValue(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

export function hashSkill(skill: DistilledSkill): string {
  return createHash("sha256").update(canonical(skill)).digest("hex");
}

/** Package a skill for sharing: content-hashed + origin-attributed. */
export function publishSkill(skill: DistilledSkill, origin: string, now: number = Date.now()): SkillPackage {
  return { skill, contentHash: hashSkill(skill), origin, publishedAt: now };
}

/**
 * Check package integrity and the configured gate before catalog storage. A
 * refining gate supplies its final candidate; the returned assessment identifies
 * submitted and accepted content separately. This is not publisher authentication.
 */
export async function installSkill(pkg: SkillPackage, deps: InstallDeps): Promise<InstallResult> {
  const prepared = await prepareSkillInstall(pkg, deps);
  if (prepared.ok) deps.store.put(prepared.pkg);
  return prepared;
}

/** Resolve the checked bytes without catalog mutation, also used by whole-bundle preflight. */
async function prepareSkillInstall(pkg: SkillPackage, deps: InstallDeps): Promise<InstallResult> {
  if (!isPackage(pkg)) return { ok: false, reason: "tampered", detail: "package schema is invalid" };
  const input = immutableCopy(pkg);
  if (hashSkill(input.skill) !== input.contentHash) {
    return { ok: false, reason: "tampered", detail: "content hash does not match the packaged skill" };
  }
  const verdict = await deps.gate(input.skill);
  if (!verdict.ok) {
    return { ok: false, reason: "rejected-unsafe", detail: verdict.reason ?? verdict.verdict };
  }
  const checked = immutableCopy(verdict.checkedSkill === undefined ? input.skill : verdict.checkedSkill);
  if (!isSkill(checked) || checked.id !== input.skill.id) {
    return { ok: false, reason: "rejected-unsafe", detail: "checked candidate must have a valid schema and preserve the requested skill id" };
  }
  const accepted = Object.freeze({ ...input, skill: checked, contentHash: hashSkill(checked) });
  return { ok: true, pkg: accepted, assessment: Object.freeze({ verdict: verdict.verdict, inputContentHash: input.contentHash, contentHash: accepted.contentHash }) };
}

/** Detach gate/caller-owned references before asynchronous checking and retention. */
function immutableCopy<T>(value: T): T {
  const copy = structuredClone(value);
  const seen = new WeakSet<object>();
  function freeze(item: unknown): void {
    if (item === null || typeof item !== "object" || seen.has(item)) return;
    seen.add(item);
    for (const child of Object.values(item)) freeze(child);
    Object.freeze(item);
  }
  freeze(copy);
  return copy;
}

/** Immutable candidate identity for trusted comparison/retention consumers. */
export function snapshotSkill(skill: DistilledSkill): DistilledSkill { return immutableCopy(skill); }

export function listRegistry(store: RegistryStore): readonly SkillPackage[] {
  return store.list();
}

/** The n=1 / local default store. An HTTP-backed store implementing `RegistryStore` is a thin adapter for org/community. */
export class InMemoryRegistryStore implements RegistryStore {
  private byId = new Map<string, SkillPackage>();
  put(pkg: SkillPackage): void { this.byId.set(pkg.skill.id, pkg); }
  get(id: string): SkillPackage | undefined { return this.byId.get(id); }
  list(): readonly SkillPackage[] { return [...this.byId.values()]; }
  replaceAll(packages: readonly SkillPackage[]): void { this.byId = new Map(packages.map(pkg => [pkg.skill.id, pkg])); }
}

export type RetirementReason = "harmful" | "unused" | "redundant";

export interface SkillLifecycleRecord {
  readonly skillId: string;
  readonly uses: number;
  readonly reward: number;
  readonly lastUsedAt: number;
  readonly retired?: { readonly reason: RetirementReason; readonly at: number; readonly replacementId?: string };
}

export interface SkillBundle {
  readonly format: "keep.skill-registry/v1";
  readonly packages: readonly SkillPackage[];
  readonly bundleHash: string;
}

export interface ManagedRegistryConfig extends InstallDeps {
  /** A never-used skill is retired after this age. Defaults to 90 days. */
  readonly unusedAfterMs?: number;
  /** Import denial-of-service bound. Defaults to 1000 packages. */
  readonly maxImportPackages?: number;
  readonly persistence?: SkillRegistryPersistence;
  /** Maximum authority this receiver grants imported skills. Defaults to all known local authorities for API compatibility. */
  readonly allowedImportAuthorities?: readonly SkillAuthority[];
  /** Host implementations available to imported typed contracts. Missing entrypoints fail closed. */
  readonly programs?: SkillPrograms;
  /** Declare only when the injected gate itself verifies typed programs; avoids repeating deterministic examples. */
  readonly gateVerifiesPrograms?: boolean;
  /** Called only after admission is fully installed (and, for bundles, every package passed preflight). */
  readonly onAdmit?: (skill: DistilledSkill) => void;
}

export interface PersistedSkillLifecycle { readonly skillId: string; readonly admittedHash?: string | null; readonly uses: number; readonly reward: number; readonly lastUsedAt: number; readonly retired?: { readonly reason: RetirementReason; readonly at: number; readonly replacementId?: string }; }
export interface SkillRegistrySnapshot { readonly schemaVersion: 1 | 2; readonly packages: readonly SkillPackage[]; readonly lifecycle: readonly PersistedSkillLifecycle[]; }
/** Synchronous trusted port. A successful save must make the snapshot available to
 * load; an ordinary thrown error may have occurred after commit and fences the
 * managed writer until reconstruction. The default file writer can identify its
 * own pre-commit failures with SkillRegistryWriteError. */
export interface SkillRegistryPersistence { load(): SkillRegistrySnapshot | undefined; save(snapshot: SkillRegistrySnapshot): void; }

/** Default file writer failed before its rename commit; staged bytes may remain. */
export class SkillRegistryWriteError extends Error {
  constructor(cause: unknown) {
    super(`skill registry commit did not occur: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    this.name = "SkillRegistryWriteError";
  }
}

/** Single-writer local rename persistence; no power-loss/fsync or multi-process
 * guarantee. Corruption fails closed instead of silently resetting history. */
export class FileSkillRegistryPersistence implements SkillRegistryPersistence {
  constructor(private readonly path: string) {}
  load(): SkillRegistrySnapshot | undefined {
    let raw: string;
    try { raw = readFileSync(this.path, "utf8"); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
    const value = JSON.parse(raw) as SkillRegistrySnapshot;
    if ((value?.schemaVersion !== 1 && value?.schemaVersion !== 2) || !Array.isArray(value.packages) || !Array.isArray(value.lifecycle)) throw new Error("invalid persisted skill registry");
    return value;
  }
  save(snapshot: SkillRegistrySnapshot): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.tmp`;
      writeFileSync(temporary, JSON.stringify(snapshot), { encoding: "utf8", mode: 0o600 });
      renameSync(temporary, this.path);
    } catch (cause) { throw new SkillRegistryWriteError(cause); }
  }
}

export type ImportResult =
  | { readonly ok: true; readonly installed: number; readonly merged: number }
  | { readonly ok: false; readonly reason: "invalid-bundle" | "tampered-bundle" | "import-too-large" | "rejected-package" | "held-legacy-retired"; readonly detail: string };

/**
 * Product lifecycle around the registry. Rewards use supplied solve outcomes.
 * Harmful reuse and inactivity retire the current version without deleting its
 * package. Checked replacement starts a new version-specific record; this store
 * is not an archive of all prior versions. Equivalent envelopes/programs merge
 * provenance. Exchange is bounded and uses the configured admission gate.
 */
export class ManagedSkillRegistry {
  private records = new Map<string, { admittedHash: string | null; uses: number; reward: number; lastUsedAt: number; retired?: { reason: RetirementReason; at: number; replacementId?: string } }>();
  private draft = false;
  private committing = false;
  private reconstructionRequired = false;
  private readonly unusedAfterMs: number;
  private readonly maxImportPackages: number;
  private readonly allowedImportAuthorities: ReadonlySet<SkillAuthority>;

  constructor(private readonly config: ManagedRegistryConfig) {
    this.unusedAfterMs = config.unusedAfterMs ?? 90 * 24 * 60 * 60 * 1000;
    this.maxImportPackages = config.maxImportPackages ?? 1000;
    this.allowedImportAuthorities = new Set(config.allowedImportAuthorities ?? ["workspace:read", "workspace:write", "sandbox:execute"]);
    const restored = config.persistence?.load();
    if (restored) {
      if ((restored.schemaVersion !== 1 && restored.schemaVersion !== 2) || !Array.isArray(restored.packages) || !Array.isArray(restored.lifecycle)) throw new Error("invalid persisted skill registry");
      const packageIds = new Set<string>();
      for (const pkg of restored.packages) {
        if (!isPackage(pkg) || packageIds.has(pkg.skill.id) || hashSkill(pkg.skill) !== pkg.contentHash) {
          throw new Error("invalid persisted skill package");
        }
        packageIds.add(pkg.skill.id);
      }
      const lifecycleIds = new Set<string>();
      for (const record of restored.lifecycle) {
        if (!isLifecycle(record) || lifecycleIds.has(record.skillId) || !packageIds.has(record.skillId)) throw new Error("invalid persisted skill lifecycle");
        if (restored.schemaVersion === 2 && record.admittedHash !== null && (typeof record.admittedHash !== "string" || !/^[a-f0-9]{64}$/.test(record.admittedHash))) throw new Error("invalid persisted skill admission binding");
        lifecycleIds.add(record.skillId);
      }
      // Catalog-only entries have no admission record. Preview v1 could also attach
      // another version's lifecycle to replaced content; its binding cannot be inferred.
      for (const pkg of restored.packages) config.store.put(pkg);
      for (const record of restored.lifecycle) {
        this.records.set(record.skillId, { admittedHash: restored.schemaVersion === 2 ? record.admittedHash! : null, uses: record.uses, reward: record.reward, lastUsedAt: record.lastUsedAt, ...(record.retired ? { retired: { ...record.retired } } : {}) });
      }
    }
  }

  async add(pkg: SkillPackage): Promise<InstallResult & { readonly mergedInto?: string }> {
    this.ensureMutable();
    if (!isPackage(pkg)) return { ok: false, reason: "tampered", detail: "package schema is invalid" };
    const observed = this.subjectToken(pkg.skill.id);
    const prepared = await this.preparePackage(pkg);
    if (!prepared.ok) return prepared;
    if (this.subjectToken(prepared.pkg.skill.id) !== observed) return { ok: false, reason: "rejected-unsafe", detail: "skill admission state changed during validation; retry against current state" };
    const result = this.commit(draft => {
      draft.config.store.put(prepared.pkg);
      return { ...prepared, ...draft.finishInstalled(prepared.pkg) };
    });
    this.activateInstalled(result.pkg, result.mergedInto);
    return result;
  }

  /** Record a locally validated candidate synchronously after the caller's execution gate; this grants no activation. */
  trackValidated(skill: DistilledSkill, origin: string, now: number = Date.now()): { readonly pkg: SkillPackage; readonly active: boolean; readonly mergedInto?: string } {
    if (!this.draft) return this.commit(draft => draft.trackValidated(skill, origin, now));
    skill = immutableCopy(skill);
    const existing = this.config.store.get(skill.id);
    if (existing && this.records.has(skill.id)) {
      const lifecycle = this.records.get(skill.id)!;
      // Unknown-content retirement cannot be cleared by a new description or a
      // trusted retention caller. The returned package remains the stored record,
      // not a claim that the supplied candidate was retained.
      if (lifecycle.retired && (lifecycle.admittedHash === null || hashSkill(existing.skill) === hashSkill(skill))) return { pkg: existing, active: false };
      // The caller checked this candidate, not the previous content under its ID.
      const pkg = publishSkill(skill, origin, now);
      this.config.store.put(pkg);
      if (lifecycle.admittedHash !== pkg.contentHash) this.records.set(skill.id, { admittedHash: pkg.contentHash, uses: 0, reward: 0, lastUsedAt: now });
      this.persist(); return { pkg, active: true };
    }
    const pkg = publishSkill(skill, origin, now);
    this.config.store.put(pkg);
    const result = this.finishInstalled(pkg);
    this.persist();
    if (result.mergedInto) return { pkg: this.config.store.get(result.mergedInto)!, active: false, mergedInto: result.mergedInto };
    return { pkg, active: true };
  }

  private async preparePackage(pkg: SkillPackage): Promise<InstallResult> {
    if (!isPackage(pkg)) return { ok: false, reason: "tampered", detail: "package schema is invalid" };
    const previous = this.records.get(pkg.skill.id);
    if (previous?.retired && previous.admittedHash === null) return {
      ok: false, reason: "held-legacy-retired",
      detail: "legacy retirement has no content binding; this id cannot be reactivated by admission",
    };
    const input = immutableCopy(pkg);
    const policyFailure = this.exchangePolicyFailure(input);
    if (policyFailure) return { ok: false, reason: "rejected-unsafe", detail: policyFailure };
    const prepared = await prepareSkillInstall(input, this.config);
    if (!prepared.ok) return prepared;
    // Refinement does not enlarge the receiver's permission grant or bypass its
    // typed-program requirements, even when the original passed those checks.
    const revisedFailure = prepared.pkg.contentHash !== input.contentHash ? this.exchangePolicyFailure(prepared.pkg) : undefined;
    return revisedFailure ? { ok: false, reason: "rejected-unsafe", detail: revisedFailure } : prepared;
  }

  private finishInstalled(pkg: SkillPackage): { readonly mergedInto?: string } {
    const previous = this.records.get(pkg.skill.id);
    if (previous?.admittedHash !== pkg.contentHash) this.records.set(pkg.skill.id, { admittedHash: pkg.contentHash, uses: 0, reward: 0, lastUsedAt: pkg.publishedAt });
    const equivalent = this.config.store.list().find((other) =>
      other.skill.id !== pkg.skill.id && this.isEligible(other.skill) && skillBehaviorHash(other.skill) === skillBehaviorHash(pkg.skill));
    if (!equivalent) return {};

    const mergedSkill: DistilledSkill = {
      ...equivalent.skill,
      provenance: [...new Set([...equivalent.skill.provenance, ...pkg.skill.provenance])],
      confidence: equivalent.skill.confidence === "corroborated" || pkg.skill.confidence === "corroborated" ||
        new Set([...equivalent.skill.provenance, ...pkg.skill.provenance]).size > 1 ? "corroborated" : "low",
    };
    const merged = publishSkill(mergedSkill, equivalent.origin, Math.max(equivalent.publishedAt, pkg.publishedAt));
    this.config.store.put(merged);
    this.records.get(equivalent.skill.id)!.admittedHash = merged.contentHash;
    this.retire(pkg.skill.id, "redundant", pkg.publishedAt, equivalent.skill.id);
    return { mergedInto: equivalent.skill.id };
  }

  recordOutcome(signal: OutcomeSignal): void {
    if (!this.draft) { this.commit(draft => draft.recordOutcome(signal)); return; }
    const active = new Set(signal.activeArtifacts ?? []);
    let changed = false;
    for (const skillId of active) {
      const rec = this.records.get(skillId);
      const pkg = this.config.store.get(skillId);
      if (!rec || !pkg || !this.isEligible(pkg.skill)) continue;
      const delta = reuseSignal(signal).reward;
      rec.uses++;
      rec.reward += delta;
      rec.lastUsedAt = signal.timestamp;
      if (!signal.testsPassed || signal.mergeVerdict === "rejected" || rec.reward < 0) this.retire(skillId, "harmful", signal.timestamp);
      changed = true;
    }
    if (changed) this.persist();
  }

  retireUnused(now: number): readonly string[] {
    if (!this.draft) return this.commit(draft => draft.retireUnused(now));
    const retired: string[] = [];
    for (const [id, rec] of this.records) {
      const pkg = this.config.store.get(id);
      if (pkg && this.isEligible(pkg.skill) && rec.uses === 0 && now - rec.lastUsedAt >= this.unusedAfterMs) {
        this.retire(id, "unused", now);
        retired.push(id);
      }
    }
    if (retired.length > 0) this.persist();
    return retired;
  }

  lifecycle(skillId: string): SkillLifecycleRecord | undefined {
    const rec = this.records.get(skillId);
    if (!rec) return undefined;
    const { admittedHash: _binding, ...history } = rec;
    return { skillId, ...history, ...(rec.retired ? { retired: { ...rec.retired } } : {}) };
  }

  /** Current content eligibility, not a claim about the truth of a supplied gate's evidence. */
  admissionStatus(skillId: string): "missing" | "catalog-only" | "legacy-unverified" | "content-changed" | "retired" | "admitted" | "reconstruction-required" {
    if (this.reconstructionRequired) return "reconstruction-required";
    const pkg = this.config.store.get(skillId), record = this.records.get(skillId);
    if (!pkg) return "missing";
    if (!record) return "catalog-only";
    if (record.retired && record.admittedHash === null) return "retired";
    if (record.admittedHash === null) return "legacy-unverified";
    if (record.admittedHash !== pkg.contentHash || hashSkill(pkg.skill) !== pkg.contentHash) return "content-changed";
    return record.retired ? "retired" : "admitted";
  }

  isEligible(skill: DistilledSkill): boolean {
    return !this.reconstructionRequired && this.admissionStatus(skill.id) === "admitted" && this.records.get(skill.id)!.admittedHash === hashSkill(skill);
  }

  /** Content/admission/retirement precondition; counters alone do not alter it. */
  subjectToken(skillId: string): string {
    const pkg = this.config.store.get(skillId), record = this.records.get(skillId);
    return JSON.stringify([pkg ? hashSkill(pkg.skill) : null, record?.admittedHash ?? null, record?.retired ?? null, this.reconstructionRequired]);
  }

  /** A measured bad candidate may withdraw only the exact currently admitted content. */
  withdrawExact(skill: DistilledSkill, now = Date.now()): boolean {
    if (!this.isEligible(skill)) return false;
    try {
      return this.commit(draft => { draft.retire(skill.id, "harmful", now); return true; });
    } catch (error) {
      // Known harmful evidence must not remain live after failed durable withdrawal.
      this.reconstructionRequired = true;
      throw error;
    }
  }

  activePackages(): readonly SkillPackage[] {
    return this.config.store.list().filter((pkg) => this.isEligible(pkg.skill));
  }

  exportBundle(): string {
    const packages = this.activePackages();
    for (const pkg of packages) {
      if (!isPackage(pkg) || hashSkill(pkg.skill) !== pkg.contentHash) throw new Error(`refusing to export invalid skill package ${pkg.skill?.id ?? "<unknown>"}`);
    }
    const bundle: SkillBundle = { format: "keep.skill-registry/v1", packages, bundleHash: hashValue(packages) };
    return canonical(bundle);
  }

  async importBundle(serialized: string): Promise<ImportResult> {
    this.ensureMutable();
    let value: unknown;
    try { value = JSON.parse(serialized); } catch { return { ok: false, reason: "invalid-bundle", detail: "bundle is not valid JSON" }; }
    if (!isBundle(value)) return { ok: false, reason: "invalid-bundle", detail: "bundle schema or skill format is invalid" };
    if (value.packages.length > this.maxImportPackages) return { ok: false, reason: "import-too-large", detail: `bundle exceeds ${this.maxImportPackages} packages` };
    if (hashValue(value.packages) !== value.bundleHash) return { ok: false, reason: "tampered-bundle", detail: "bundle digest does not match its packages" };
    const observed = value.packages.map(pkg => this.subjectToken(pkg.skill.id));
    // Preflight the complete bundle before mutating the store. This makes a rejected later package unable to
    // leave an attacker-chosen prefix installed; only this checked set reaches the mutation loop below.
    const prepared: SkillPackage[] = [];
    for (const pkg of value.packages) {
      if (hashSkill(pkg.skill) !== pkg.contentHash) return { ok: false, reason: "rejected-package", detail: `${pkg.skill.id}: content hash does not match the packaged skill` };
      const checked = await this.preparePackage(pkg);
      if (!checked.ok) return { ok: false, reason: checked.reason === "held-legacy-retired" ? checked.reason : "rejected-package", detail: `${pkg.skill.id}: ${checked.detail}` };
      prepared.push(checked.pkg);
    }
    if (prepared.some((pkg, i) => this.subjectToken(pkg.skill.id) !== observed[i])) return { ok: false, reason: "rejected-package", detail: "skill admission state changed during bundle validation; retry against current state" };
    const admitted = this.commit(draft => prepared.map(pkg => {
      draft.config.store.put(pkg);
      return { pkg, ...draft.finishInstalled(pkg) };
    }));
    for (const item of admitted) this.activateInstalled(item.pkg, item.mergedInto);
    return { ok: true, installed: admitted.length, merged: admitted.filter(item => item.mergedInto !== undefined).length };
  }

  private persist(): void {
    if (!this.draft) throw new Error("registry mutation must use the commit boundary");
  }

  private snapshot(): SkillRegistrySnapshot {
    return { schemaVersion: 2, packages: this.config.store.list(), lifecycle: [...this.records].map(([skillId, record]) => ({ skillId, ...record })) };
  }

  private ensureMutable(): void {
    if (this.committing) throw new Error("reentrant skill registry mutation refused");
    if (this.reconstructionRequired) throw new Error("skill registry requires reconstruction after an uncertain or failed withdrawal commit");
  }

  private commit<T>(change: (draft: ManagedSkillRegistry) => T): T {
    this.ensureMutable();
    this.committing = true;
    try {
      const before = immutableCopy(this.snapshot());
      const { onAdmit: _notice, persistence: _persistence, ...config } = this.config;
      const draft = new ManagedSkillRegistry({ ...config, store: new InMemoryRegistryStore(),
        persistence: { load: () => before, save: () => { throw new Error("draft may not save"); } } });
      draft.draft = true;
      const result = change(draft);
      const after = immutableCopy(draft.snapshot());
      if (canonical(before) !== canonical(after)) {
        try { this.config.persistence?.save(after); }
        catch (error) { if (!(error instanceof SkillRegistryWriteError)) this.reconstructionRequired = true; throw error; }
        try {
          if (this.config.store.replaceAll) this.config.store.replaceAll(after.packages);
          else for (const pkg of after.packages) this.config.store.put(pkg);
          this.records = draft.records;
        } catch (error) { this.reconstructionRequired = true; throw error; }
      }
      return result;
    } finally { this.committing = false; }
  }

  private exchangePolicyFailure(pkg: SkillPackage): string | undefined {
    const excess = pkg.skill.requiredAuthority.find((authority) => !this.allowedImportAuthorities.has(authority));
    if (excess) return `required authority is not granted by receiver: ${excess}`;
    if (this.config.gateVerifiesPrograms) return undefined;
    const program = verifySkillProgram(pkg.skill, this.config.programs ?? {});
    return program.ok ? undefined : `typed program verification failed: ${program.detail}`;
  }

  private activateInstalled(pkg: SkillPackage, mergedInto?: string): void {
    const active = mergedInto ? this.config.store.get(mergedInto) : pkg;
    if (active && this.isEligible(active.skill)) this.config.onAdmit?.(active.skill);
  }

  private retire(id: string, reason: RetirementReason, at: number, replacementId?: string): void {
    const rec = this.records.get(id);
    if (!rec || rec.retired) return;
    rec.retired = replacementId === undefined ? { reason, at } : { reason, at, replacementId };
  }

}

function skillBehaviorHash(skill: DistilledSkill): string {
  return hashValue({ relevanceKey: skill.relevanceKey, envelope: skill.envelope, requiredAuthority: [...skill.requiredAuthority].sort(), program: skill.program ?? null });
}

function isBundle(value: unknown): value is SkillBundle {
  if (!isRecord(value) || value.format !== "keep.skill-registry/v1" || typeof value.bundleHash !== "string" || !Array.isArray(value.packages)) return false;
  return value.packages.every((pkg) => isRecord(pkg) && typeof pkg.contentHash === "string" && typeof pkg.origin === "string" &&
    typeof pkg.publishedAt === "number" && Number.isFinite(pkg.publishedAt) && isSkill(pkg.skill));
}

function isPackage(value: unknown): value is SkillPackage {
  return isRecord(value) && typeof value.contentHash === "string" && typeof value.origin === "string" &&
    typeof value.publishedAt === "number" && Number.isFinite(value.publishedAt) && isSkill(value.skill);
}

function isLifecycle(value: unknown): value is PersistedSkillLifecycle {
  if (!isRecord(value) || typeof value.skillId !== "string" || !Number.isInteger(value.uses) || (value.uses as number) < 0 ||
    typeof value.reward !== "number" || !Number.isFinite(value.reward) || typeof value.lastUsedAt !== "number" || !Number.isFinite(value.lastUsedAt)) return false;
  if (value.retired === undefined) return true;
  if (!isRecord(value.retired) || !["harmful", "unused", "redundant"].includes(value.retired.reason as string) ||
    typeof value.retired.at !== "number" || !Number.isFinite(value.retired.at)) return false;
  return value.retired.replacementId === undefined || typeof value.retired.replacementId === "string";
}

function isSkill(value: unknown): value is DistilledSkill {
  if (!isRecord(value) || value.format !== "keep.skill/v1" || typeof value.id !== "string" || typeof value.name !== "string" ||
    typeof value.description !== "string" || typeof value.relevanceKey !== "string" || !Array.isArray(value.requiredAuthority) ||
    !value.requiredAuthority.every((a) => a === "workspace:read" || a === "workspace:write" || a === "sandbox:execute") ||
    !Array.isArray(value.provenance) || !value.provenance.every((p) => typeof p === "string") ||
    (value.confidence !== "low" && value.confidence !== "corroborated") || !isRecord(value.envelope) ||
    (value.program !== undefined && !isProgram(value.program))) return false;
  const e = value.envelope;
  return Array.isArray(e.preconditions) && e.preconditions.every((x) => typeof x === "string") &&
    Array.isArray(e.postconditions) && e.postconditions.every((x) => typeof x === "string") &&
    Array.isArray(e.declaredEffects) && e.declaredEffects.every((x) => typeof x === "string") && Array.isArray(e.steps) &&
    e.steps.every((s) => isRecord(s) && typeof s.action === "string" && typeof s.targetPattern === "string") &&
    (e.parameters === undefined || (Array.isArray(e.parameters) && e.parameters.every((parameter) => isRecord(parameter) &&
      (parameter.name === "file" || parameter.name === "symbol" || parameter.name === "arg") && parameter.type === "string" && parameter.required === true) &&
      new Set(e.parameters.map((parameter) => (parameter as { name: string }).name)).size === e.parameters.length));
}

function isProgram(value: unknown): boolean {
  if (!isRecord(value) || typeof value.entrypoint !== "string" || !isRecord(value.inputs) || !Array.isArray(value.cases)) return false;
  if (!Object.values(value.inputs).every((type) => type === "string" || type === "number" || type === "boolean")) return false;
  return value.cases.every((item) => isRecord(item) && typeof item.name === "string" && isRecord(item.input) && "expected" in item);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
