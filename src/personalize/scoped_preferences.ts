/**
 * CRYPTOGRAPHIC preference isolation — binds the preference spine through the project's ProjectNamespace so
 * preferences are isolated by the SAME per-tenant-key boundary as session history / memory / ingest, closing the
 * theme-2 ∩ theme-4 seam.
 *
 * The gap this closes: the personalization envelope isolates preferences by a LOGICAL CP-net string scope
 * (`pref:<dim>@project:alpha`) matched in code — weaker than the cryptographic ProjectNamespace (per-project keys
 * + `key()` namespacing + crypto-shred) that everything else in Keep uses. A forged/mismatched string scope
 * could in principle read another project's preference. Here every preference is (a) written under a NAMESPACED
 * key `ns.key("pref:...")` that binds it to one ProjectId, and (b) encrypted under that project's own key
 * (AES-256-GCM — authenticated, so a wrong-key decrypt throws). So project B's namespace can neither address nor
 * decrypt project A's preferences, and crypto-shredding A (destroying its key) makes A's preferences
 * permanently inaccessible (GDPR-grade clean-delete). Deterministic, below the model — "relying on LLMs for
 * access control is an architectural anti-pattern" (Truto 2026).
 *
 * BUILT + proven in-env: the namespacing binding + the default-deny filter + `assertScopedRead`. It REUSES the
 * envelope's `resolveDimension` (CP-net scope) + `applyWithinPolicy` (clamp) and the registry's ProjectNamespace
 * — it does not reimplement isolation or rebuild the envelope. The persistent per-project store is the SEAM.
 */

import type { RevisionStore, Version } from "../frontdoor/revision_store.js";
import type { ProjectNamespace } from "../session/project_registry.js";
import { CrossProjectAccessError } from "../session/project_registry.js";
import { isProjectId, type ProjectId } from "../session/project_id.js";
import type { Ciphertext } from "../keystore/keystore.js";
import type { AutonomyLevel } from "../frontdoor/autonomy_profile.js";
import {
  resolveDimension,
  applyWithinPolicy,
  type PreferenceDimension,
  type PolicyBounds,
  type PersonalizeContext,
  type EffectiveProfile,
  type PromptFormat,
  type Verbosity,
} from "./personalize.js";

const NS_SEP = "::";

/**
 * STRUCTURAL owner extraction (red-team hardening). A namespaced key is `<ProjectId>::<logical>`. The owner is
 * the FIELD before the first separator, and it must be a VALID ProjectId — not a substring prefix match. This
 * replaces the ad-hoc `startsWith`/`indexOf`/`includes` string handling so the isolation boundary is a field
 * comparison (immune to prefix confusion) and every unowned/malformed key fails CLOSED. Returns undefined for a
 * key with no separator or a non-ProjectId owner field (⇒ owned by no project).
 */
export function ownerOf(itemKey: string): ProjectId | undefined {
  const i = itemKey.indexOf(NS_SEP);
  if (i < 0) return undefined; // no namespace field ⇒ not project-owned
  const proj = itemKey.slice(0, i);
  return isProjectId(proj) ? proj : undefined; // owner field must be a valid ProjectId
}

/** The logical key (the part after the first separator), or undefined if the key isn't namespaced. */
export function logicalOf(itemKey: string): string | undefined {
  const i = itemKey.indexOf(NS_SEP);
  return i < 0 ? undefined : itemKey.slice(i + NS_SEP.length);
}

function logicalPrefKey(dim: PreferenceDimension, scope: string | undefined): string {
  return `pref:${dim}${scope !== undefined ? "@" + scope : ""}`;
}

/**
 * Write a preference bound to a project: the itemKey is namespaced via `ns.key(...)` (binds it to this
 * ProjectId) and the value is ENCRYPTED under the project's own key. Supersedes any current version at that key.
 */
export function putScopedPreference(
  store: RevisionStore,
  ns: ProjectNamespace,
  dim: PreferenceDimension,
  value: string,
  scope?: string,
): void {
  const key = ns.key(logicalPrefKey(dim, scope)); // projId::pref:dim[@scope] — cryptographic namespacing
  const content = JSON.stringify(ns.encrypt(value)); // encrypted under the per-project key
  if (store.current(key) !== undefined) store.revise(key, content);
  else store.create(key, "preference", content);
}

/**
 * The DEFAULT-DENY isolation filter: the current preference Versions that belong to THIS project's namespace.
 * A version written under another project's namespace does not start with this project's prefix and is excluded
 * — a cross-project read returns nothing by construction, not by discipline.
 */
export function scopedVersions(store: RevisionStore, ns: ProjectNamespace): Version[] {
  return store.allCurrent("preference").filter((v) => {
    if (ownerOf(v.itemKey) !== ns.projectId) return false; // structural field equality — not a prefix match
    const logical = logicalOf(v.itemKey);
    return logical !== undefined && logical.startsWith("pref:");
  });
}

/**
 * Defensive assertion: throw `CrossProjectAccessError` if `itemKey` is not owned by `ns`'s project. The isolation
 * is already structural (scopedVersions excludes foreign keys); this makes an explicit cross attempt fail loudly.
 */
export function assertScopedRead(ns: ProjectNamespace, itemKey: string): void {
  const owner = ownerOf(itemKey); // structural + validated; undefined for a malformed/unowned key
  if (owner !== ns.projectId) {
    // fail CLOSED with the right error type — a malformed or foreign key never silently passes.
    throw new CrossProjectAccessError(ns.projectId, owner ?? ns.projectId);
  }
}

/** Decrypt a stored preference value under the project key; undefined if it can't be decrypted (foreign key,
 *  tampered, or crypto-shredded ⇒ clean-delete). */
function decryptSafe(ns: ProjectNamespace, content: string): string | undefined {
  try {
    return ns.decrypt(JSON.parse(content) as Ciphertext);
  } catch {
    return undefined; // shredded / foreign / tampered ⇒ inaccessible
  }
}

interface ScopedParsed {
  readonly dimension: PreferenceDimension;
  readonly scope?: string | undefined;
  readonly value: string;
}

function parseLogical(logical: string, value: string): ScopedParsed | undefined {
  if (!logical.startsWith("pref:")) return undefined;
  const body = logical.slice(5);
  const [dimRaw, scope] = body.split("@", 2) as [string, string | undefined];
  if (!isDimension(dimRaw)) return undefined;
  return { dimension: dimRaw, scope, value };
}
function isDimension(s: string): s is PreferenceDimension {
  return s === "promptFormat" || s === "verbosity" || s === "minReliability" || s === "autonomy" || s === "modelTier";
}

/**
 * Resolve the effective profile for a PROJECT: reads only this project's namespaced preferences, decrypts them
 * under the project key, then reuses the envelope's `resolveDimension` (CP-net scope-match + validation) and
 * `applyWithinPolicy` (the clamp). Within-project behaviour is identical to the envelope; the only change is that
 * the isolation boundary is now cryptographic.
 */
export function resolveScopedProfile(
  store: RevisionStore,
  ns: ProjectNamespace,
  ctx: PersonalizeContext,
  bounds: PolicyBounds,
): EffectiveProfile {
  const prefs: ScopedParsed[] = [];
  for (const v of scopedVersions(store, ns)) {
    const logical = logicalOf(v.itemKey); // structural: the part after the projId:: field
    if (logical === undefined) continue;
    const value = decryptSafe(ns, v.content);
    if (value === undefined) continue; // undecryptable (shredded/foreign) ⇒ excluded
    const parsed = parseLogical(logical, value);
    if (parsed !== undefined) prefs.push(parsed);
  }
  const raw = {
    promptFormat: resolveDimension(prefs, "promptFormat", ctx) as PromptFormat | undefined,
    verbosity: resolveDimension(prefs, "verbosity", ctx) as Verbosity | undefined,
    minReliability: resolveDimension(prefs, "minReliability", ctx) as number | undefined,
    autonomy: resolveDimension(prefs, "autonomy", ctx) as AutonomyLevel | undefined,
    modelTier: resolveDimension(prefs, "modelTier", ctx) as number | undefined,
  };
  return applyWithinPolicy(raw, bounds);
}
