/**
 * Effect DECLARATION model (Mechanical-Enforcement Increment 4 — Closed-World Effect Inventory).
 *
 * The dual of Increment 3's ingress inventory: where that fixed the INBOUND surface (no entrypoint exists unless
 * declared), this fixes the OUTBOUND surface — every security-relevant observation/mutation belongs to exactly one
 * declared effect FAMILY with exactly one declared KIND and exactly one broker OWNER. A `family` groups the effectful
 * host primitives of one concern (filesystem, network, DNS, subprocess, …); the `owner` is the single module allowed
 * to touch that family's raw host API; the `kind` is its consequence class (reused from the capability allowlist:
 * recoverable / external / destructive). The build-time scanner (tools/effect_sweep.mjs) then rejects any use of a
 * family's primitives OUTSIDE its declared owner.
 *
 * SCOPE (honest seams): this fixes the closed INVENTORY + owner assignment + its binding to the Increment-2 policy.
 * EXECUTION mediation (an effect runs only through the broker) is Increment 9; OS-level impossibility of bypass is
 * Increment 10. Identity is DERIVED from content (canonical.ts), never stored.
 *
 * Grounding: effect systems; capability-safe module discipline (only the owner holds the raw authority); deny-by-default
 * syscall ownership; Saltzer–Schroeder complete mediation.
 */
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";

/** The closed set of effect families (each groups one concern's host primitives). Adding one is a reviewed change. */
export const EFFECT_FAMILIES = [
  "fs", "net", "dns", "tls", "dgram", "subprocess", "worker", "module-load",
  "env", "clock", "random", "hostinfo", "persistence", "audit-out",
] as const;
export type EffectFamily = typeof EFFECT_FAMILIES[number];
export const isEffectFamily = (x: unknown): x is EffectFamily => typeof x === "string" && (EFFECT_FAMILIES as readonly string[]).includes(x);

/**
 * An effect family bound to its single broker OWNER. NOTE: the consequence KIND (recoverable/external/destructive) is
 * a property of the specific EFFECT (its policy `effectType`, derived + declared in Increment 2), NOT of the family —
 * one family (e.g. `fs`) legitimately spans kinds (`fs.read` recoverable, `fs.delete` destructive). This declaration
 * fixes only the OWNERSHIP: which single module holds this family's raw host authority.
 */
export interface EffectDecl {
  readonly family: EffectFamily;
  /** Repo-relative POSIX path of the SINGLE module that owns this family's raw host authority. */
  readonly owner: string;
}

export class EffectError extends Error { constructor(m: string) { super(`effect decl: ${m}`); this.name = "EffectError"; } }

// An owner path: repo-relative posix, non-empty, NFC, no backslashes / drive letters / absolute / traversal.
const OWNER_RE = /^(?!.*\.\.)[a-zA-Z0-9._-]+(\/[a-zA-Z0-9._-]+)*\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;

/** Validate a declaration against its closed schema. Throws EffectError. */
export function validateEffectDecl(d: unknown): EffectDecl {
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw new EffectError("declaration must be an object");
  const o = d as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!["family", "owner"].includes(k)) throw new EffectError(`unknown field "${k}"`);
  if (!isEffectFamily(o.family)) throw new EffectError(`unknown effect family "${String(o.family)}"`);
  if (typeof o.owner !== "string" || !isWellFormedText(o.owner) || o.owner.normalize("NFC") !== o.owner || !OWNER_RE.test(o.owner)) {
    throw new EffectError(`owner "${String(o.owner)}" must be a repo-relative posix source path (no absolute/backslash/traversal)`);
  }
  return { family: o.family, owner: o.owner };
}

/** Canonical value of a declaration — explicit field mapping. */
export function effectDeclToCanonical(d: EffectDecl): CanonicalValue {
  const v = validateEffectDecl(d);
  return { family: v.family, owner: v.owner };
}

/** Content-derived id of a declaration (domain-separated). */
export function effectDeclId(d: EffectDecl): string { return eirDigest("keep.effect.decl.v1", effectDeclToCanonical(d)); }
