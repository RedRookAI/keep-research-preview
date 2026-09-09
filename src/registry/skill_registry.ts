/**
 * P8 — KEEPHUB SKILL REGISTRY (publish + pull skills, safety-gated).
 *
 * Keep learns skills from its own trajectories (distiller → validator → canary). This lets a skill be PUBLISHED to a
 * portable, content-hashed, attributed package and PULLED into another Keep — closing the ecosystem/distribution gap
 * WITHOUT inheriting the memory/skill-poisoning weakness that dogs the incumbents. The cardinal rule: a pulled skill
 * is NOT trusted because it was published — it must pass the SAME safety gate (`SkillValidator`/`SkillCanary`) a
 * locally-learned skill passes before it can be used. Provenance (content hash + origin) makes tampering detectable
 * and poisoning attributable.
 *
 * This is a pure core: `publishSkill` / `installSkill` / `listRegistry` over a pluggable `RegistryStore`. The safety
 * gate is INJECTED (`InstallDeps.gate`) so the registry composes the real validator/canary without re-implementing
 * them; an HTTP-backed store + a production gate that chains validator→canary are thin adapters over this.
 *
 * Four hard properties (each disproof-backed):
 *   - COMPOSED: reuses the `DistilledSkill` shape + the injected validator/canary gate; no new skill model.
 *   - SAFETY-GATED: a pulled skill runs the gate before admission; a failing (unsafe) skill is rejected.
 *   - ATTRIBUTABLE: each package is content-hashed and carries its origin; a tampered skill fails the hash check.
 *   - BOTH-TRACKS: an in-memory/local store for n=1; an HTTP-backed store is a thin adapter for org/community.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { DistilledSkill, SkillAuthority } from "../loop/skill_distiller.js";
import { verifySkillProgram, type SkillPrograms } from "../loop/skill_program.js";
import { reuseSignal, type OutcomeSignal } from "../loop/self_improvement_bus.js";

export interface SkillPackage {
  readonly skill: DistilledSkill;
  /** sha256 over the canonical skill — provenance + tamper detection. */
  readonly contentHash: string;
  /** Who published it (an operator id, a workspace, a community handle) — attribution / anti-poisoning. */
  readonly origin: string;
  readonly publishedAt: number;
}

/** The gate verdict — production wraps `SkillValidator` (and `SkillCanary` for rollout) behind this. */
export interface GateVerdict {
  readonly ok: boolean;
  readonly verdict: string;
  readonly reason?: string;
}

export interface RegistryStore {
  put(pkg: SkillPackage): void;
  get(id: string): SkillPackage | undefined;
  list(): readonly SkillPackage[];
}

export interface InstallDeps {
  readonly store: RegistryStore;
  /** The safety gate — MUST wrap the real validator/canary. A pulled skill passes this before it is admitted. */
  readonly gate: (skill: DistilledSkill) => Promise<GateVerdict>;
}

export type InstallResult =
  | { readonly ok: true; readonly pkg: SkillPackage }
  | { readonly ok: false; readonly reason: "tampered" | "rejected-unsafe"; readonly detail: string };

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
 * Pull a skill into this Keep. ATTRIBUTABLE: the package must hash to its declared contentHash (a tampered skill is
 * refused). SAFETY-GATED: the skill then runs the injected validator/canary gate; only a passing skill is admitted.
 */
export async function installSkill(pkg: SkillPackage, deps: InstallDeps): Promise<InstallResult> {
  if (hashSkill(pkg.skill) !== pkg.contentHash) {
    return { ok: false, reason: "tampered", detail: "content hash does not match the packaged skill" };
  }
  const verdict = await deps.gate(pkg.skill);
  if (!verdict.ok) {
    return { ok: false, reason: "rejected-unsafe", detail: verdict.reason ?? verdict.verdict };
  }
  deps.store.put(pkg);
  return { ok: true, pkg };
}

export function listRegistry(store: RegistryStore): readonly SkillPackage[] {
  return store.list();
}

/** The n=1 / local default store. An HTTP-backed store implementing `RegistryStore` is a thin adapter for org/community. */
export class InMemoryRegistryStore implements RegistryStore {
  private readonly byId = new Map<string, SkillPackage>();
  put(pkg: SkillPackage): void { this.byId.set(pkg.skill.id, pkg); }
  get(id: string): SkillPackage | undefined { return this.byId.get(id); }
  list(): readonly SkillPackage[] { return [...this.byId.values()]; }
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

export interface PersistedSkillLifecycle { readonly skillId: string; readonly uses: number; readonly reward: number; readonly lastUsedAt: number; readonly retired?: { readonly reason: RetirementReason; readonly at: number; readonly replacementId?: string }; }
export interface SkillRegistrySnapshot { readonly schemaVersion: 1; readonly packages: readonly SkillPackage[]; readonly lifecycle: readonly PersistedSkillLifecycle[]; }
export interface SkillRegistryPersistence { load(): SkillRegistrySnapshot | undefined; save(snapshot: SkillRegistrySnapshot): void; }

/** Atomic local persistence for the n=1 registry; corruption fails closed instead of silently resetting history. */
export class FileSkillRegistryPersistence implements SkillRegistryPersistence {
  constructor(private readonly path: string) {}
  load(): SkillRegistrySnapshot | undefined {
    let raw: string;
    try { raw = readFileSync(this.path, "utf8"); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
    const value = JSON.parse(raw) as SkillRegistrySnapshot;
    if (value?.schemaVersion !== 1 || !Array.isArray(value.packages) || !Array.isArray(value.lifecycle)) throw new Error("invalid persisted skill registry");
    return value;
  }
  save(snapshot: SkillRegistrySnapshot): void {
    mkdirSync(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.tmp`;
    writeFileSync(temporary, JSON.stringify(snapshot), { encoding: "utf8", mode: 0o600 });
    renameSync(temporary, this.path);
  }
}

export type ImportResult =
  | { readonly ok: true; readonly installed: number; readonly merged: number }
  | { readonly ok: false; readonly reason: "invalid-bundle" | "tampered-bundle" | "import-too-large" | "rejected-package"; readonly detail: string };

/**
 * Product lifecycle around the registry. Rewards come only from execution-grounded solve outcomes. Harmful
 * reuse retires immediately; inactivity retires explicitly (never silently deletes); equivalent envelopes
 * merge while retaining the union of their provenance. Exchange is bounded and every imported package still
 * traverses the ordinary content-hash and validator/canary gate.
 */
export class ManagedSkillRegistry {
  private readonly records = new Map<string, { uses: number; reward: number; lastUsedAt: number; retired?: { reason: RetirementReason; at: number; replacementId?: string } }>();
  private readonly unusedAfterMs: number;
  private readonly maxImportPackages: number;
  private readonly allowedImportAuthorities: ReadonlySet<SkillAuthority>;

  constructor(private readonly config: ManagedRegistryConfig) {
    this.unusedAfterMs = config.unusedAfterMs ?? 90 * 24 * 60 * 60 * 1000;
    this.maxImportPackages = config.maxImportPackages ?? 1000;
    this.allowedImportAuthorities = new Set(config.allowedImportAuthorities ?? ["workspace:read", "workspace:write", "sandbox:execute"]);
    const restored = config.persistence?.load();
    if (restored) {
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
        lifecycleIds.add(record.skillId);
      }
      if (lifecycleIds.size !== packageIds.size) throw new Error("persisted skill registry is missing lifecycle state");
      for (const pkg of restored.packages) config.store.put(pkg);
      for (const record of restored.lifecycle) {
        this.records.set(record.skillId, { uses: record.uses, reward: record.reward, lastUsedAt: record.lastUsedAt, ...(record.retired ? { retired: { ...record.retired } } : {}) });
      }
    }
  }

  async add(pkg: SkillPackage): Promise<InstallResult & { readonly mergedInto?: string }> {
    const result = await this.addPackage(pkg, true);
    if (result.ok) {
      this.persist();
      this.activateInstalled(result.pkg, result.mergedInto);
    }
    return result;
  }

  /** Record a locally validated candidate synchronously after the caller's execution gate; this grants no activation. */
  trackValidated(skill: DistilledSkill, origin: string, now: number = Date.now()): { readonly pkg: SkillPackage; readonly active: boolean; readonly mergedInto?: string } {
    const existing = this.config.store.get(skill.id);
    if (existing && this.records.has(skill.id)) {
      const lifecycle = this.records.get(skill.id)!;
      if (lifecycle.retired && hashSkill(existing.skill) === hashSkill(skill)) return { pkg: existing, active: false };
      const mergedSkill = { ...existing.skill, provenance: [...new Set([...existing.skill.provenance, ...skill.provenance])], confidence: existing.skill.confidence === "corroborated" || skill.confidence === "corroborated" || new Set([...existing.skill.provenance, ...skill.provenance]).size > 1 ? "corroborated" as const : "low" as const };
      const pkg = publishSkill(mergedSkill, existing.origin, Math.max(existing.publishedAt, now));
      this.config.store.put(pkg);
      if (lifecycle.retired) this.records.set(skill.id, { uses: 0, reward: 0, lastUsedAt: now });
      this.persist(); return { pkg, active: true };
    }
    const pkg = publishSkill(skill, origin, now);
    this.config.store.put(pkg);
    const result = this.finishInstalled(pkg);
    this.persist();
    if (result.mergedInto) return { pkg: this.config.store.get(result.mergedInto)!, active: false, mergedInto: result.mergedInto };
    return { pkg, active: true };
  }

  private async addPackage(pkg: SkillPackage, runGate: boolean): Promise<InstallResult & { readonly mergedInto?: string }> {
    if (runGate) {
      if (!isPackage(pkg)) return { ok: false, reason: "tampered", detail: "package schema is invalid" };
      const policyFailure = this.exchangePolicyFailure(pkg);
      if (policyFailure) return { ok: false, reason: "rejected-unsafe", detail: policyFailure };
    }
    const installed = runGate ? await installSkill(pkg, this.config) : this.installPreflighted(pkg);
    if (!installed.ok) return installed;
    return { ...installed, ...this.finishInstalled(pkg) };
  }

  private finishInstalled(pkg: SkillPackage): { readonly mergedInto?: string } {
    this.records.set(pkg.skill.id, { uses: 0, reward: 0, lastUsedAt: pkg.publishedAt });
    const equivalent = this.config.store.list().find((other) =>
      other.skill.id !== pkg.skill.id && !this.records.get(other.skill.id)?.retired && skillBehaviorHash(other.skill) === skillBehaviorHash(pkg.skill));
    if (!equivalent) return {};

    const mergedSkill: DistilledSkill = {
      ...equivalent.skill,
      provenance: [...new Set([...equivalent.skill.provenance, ...pkg.skill.provenance])],
      confidence: equivalent.skill.confidence === "corroborated" || pkg.skill.confidence === "corroborated" ||
        new Set([...equivalent.skill.provenance, ...pkg.skill.provenance]).size > 1 ? "corroborated" : "low",
    };
    this.config.store.put(publishSkill(mergedSkill, equivalent.origin, Math.max(equivalent.publishedAt, pkg.publishedAt)));
    this.retire(pkg.skill.id, "redundant", pkg.publishedAt, equivalent.skill.id);
    return { mergedInto: equivalent.skill.id };
  }

  recordOutcome(signal: OutcomeSignal): void {
    const active = new Set(signal.activeArtifacts ?? []);
    let changed = false;
    for (const skillId of active) {
      const rec = this.records.get(skillId);
      if (!rec || rec.retired) continue;
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
    const retired: string[] = [];
    for (const [id, rec] of this.records) {
      if (!rec.retired && rec.uses === 0 && now - rec.lastUsedAt >= this.unusedAfterMs) {
        this.retire(id, "unused", now);
        retired.push(id);
      }
    }
    if (retired.length > 0) this.persist();
    return retired;
  }

  lifecycle(skillId: string): SkillLifecycleRecord | undefined {
    const rec = this.records.get(skillId);
    return rec ? { skillId, ...rec } : undefined;
  }

  activePackages(): readonly SkillPackage[] {
    return this.config.store.list().filter((pkg) => !this.records.get(pkg.skill.id)?.retired);
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
    let value: unknown;
    try { value = JSON.parse(serialized); } catch { return { ok: false, reason: "invalid-bundle", detail: "bundle is not valid JSON" }; }
    if (!isBundle(value)) return { ok: false, reason: "invalid-bundle", detail: "bundle schema or skill format is invalid" };
    if (value.packages.length > this.maxImportPackages) return { ok: false, reason: "import-too-large", detail: `bundle exceeds ${this.maxImportPackages} packages` };
    if (hashValue(value.packages) !== value.bundleHash) return { ok: false, reason: "tampered-bundle", detail: "bundle digest does not match its packages" };
    // Preflight the complete bundle before mutating the store. This makes a rejected later package unable to
    // leave an attacker-chosen prefix installed; only this checked set reaches the mutation loop below.
    for (const pkg of value.packages) {
      if (hashSkill(pkg.skill) !== pkg.contentHash) return { ok: false, reason: "rejected-package", detail: `${pkg.skill.id}: content hash does not match the packaged skill` };
      const policyFailure = this.exchangePolicyFailure(pkg);
      if (policyFailure) return { ok: false, reason: "rejected-package", detail: `${pkg.skill.id}: ${policyFailure}` };
      const verdict = await this.config.gate(pkg.skill);
      if (!verdict.ok) return { ok: false, reason: "rejected-package", detail: `${pkg.skill.id}: ${verdict.reason ?? verdict.verdict}` };
    }
    let installed = 0;
    let merged = 0;
    const admitted: { pkg: SkillPackage; mergedInto?: string }[] = [];
    for (const pkg of value.packages) {
      const result = await this.addPackage(pkg, false);
      if (!result.ok) return { ok: false, reason: "rejected-package", detail: `${pkg.skill.id}: ${result.detail}` };
      installed++;
      if (result.mergedInto) merged++;
      admitted.push({ pkg: result.pkg, ...(result.mergedInto ? { mergedInto: result.mergedInto } : {}) });
    }
    this.persist();
    for (const item of admitted) this.activateInstalled(item.pkg, item.mergedInto);
    return { ok: true, installed, merged };
  }

  private persist(): void {
    this.config.persistence?.save({ schemaVersion: 1, packages: this.config.store.list(), lifecycle: [...this.records].map(([skillId, record]) => ({ skillId, ...record })) });
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
    if (active) this.config.onAdmit?.(active.skill);
  }

  private retire(id: string, reason: RetirementReason, at: number, replacementId?: string): void {
    const rec = this.records.get(id);
    if (!rec || rec.retired) return;
    rec.retired = replacementId === undefined ? { reason, at } : { reason, at, replacementId };
  }

  private installPreflighted(pkg: SkillPackage): InstallResult {
    this.config.store.put(pkg);
    return { ok: true, pkg };
  }
}

function skillBehaviorHash(skill: DistilledSkill): string {
  return hashValue({ relevanceKey: skill.relevanceKey, envelope: skill.envelope, requiredAuthority: [...skill.requiredAuthority].sort() });
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
