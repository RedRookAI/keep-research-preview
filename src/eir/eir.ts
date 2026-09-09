/**
 * Enforcement IR — closed node model + content-derived identity (Mechanical-Enforcement Increment 1).
 *
 * ONE deterministic, non-ambiguous representation for the foundational security objects: a PRINCIPAL, an EFFECT,
 * a GUARD, and an OBLIGATION binding them. Two structurally-equal nodes get the SAME id; any semantic change gets a
 * DIFFERENT id. Identity is DERIVED from the canonical encoding of the node's content (never a stored field, never
 * source text) — so an obligation cannot lie about its own id, and a later increment cannot silently retarget one.
 *
 * SCOPE (Increment 1, honest): this fixes the VALUE MODEL + IDENTITY + STRICT VALIDATION. It deliberately DEFERS —
 * the full decision lattice / predicate semantics to Increment 6 (Total Decision Kernel); permit scope + delegation
 * to Increment 7 (Object-Capability Permits); actual-object resolution to Increment 11 (Resolver-Bound Guards);
 * policy production to Increment 2 (Total Policy Compiler). A guard's `predicate` and an effect's `resourceSelector`
 * are canonical STRINGS here — placeholders those increments replace with structured, evaluable forms. Nothing here
 * claims to EVALUATE a policy; it claims only that every object has one canonical form + id, checkably.
 *
 * Grounding: tagged (discriminated) unions; content-addressed identity; RFC 8949 deterministic CBOR (canonical.ts).
 */
import { encodeCanonical, decodeCanonical, isCanonical, eirDigest, canonicalEqual, type CanonicalValue } from "./canonical.js";

export const EIR_VERSION = 1 as const;

/** Effect consequence classes — aligned with the capability-port effect classes the codebase already uses. */
export type EffectClass = "recoverable" | "external" | "destructive" | "unknown";
const EFFECT_CLASSES: readonly EffectClass[] = ["recoverable", "external", "destructive", "unknown"];

export interface Principal { readonly kind: "principal"; readonly name: string; readonly labels: readonly string[]; }
export interface Effect { readonly kind: "effect"; readonly effectType: string; readonly resourceSelector: string; readonly cls: EffectClass; }
export interface Guard { readonly kind: "guard"; readonly predicate: string; }
/** An obligation references its guard + effect BY THEIR DERIVED IDs (content addresses), not by embedding them. */
export interface Obligation {
  readonly kind: "obligation";
  readonly subjects: readonly string[];     // principal names admitted
  readonly entryPoints: readonly string[];  // ingress ids this obligation covers
  readonly effectId: string;                // = effectId(effect)
  readonly guardId: string;                 // = guardId(guard)
}
export type EirNode = Principal | Effect | Guard | Obligation;

class EirError extends Error { constructor(m: string) { super(`EIR: ${m}`); this.name = "EirError"; } }

const isNfcString = (x: unknown): x is string => typeof x === "string" && x.normalize("NFC") === x;
const isNfcStringArray = (x: unknown): x is readonly string[] => Array.isArray(x) && x.every(isNfcString);
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * VALIDATE a node against its closed schema — reject unknown fields, wrong types, non-NFC strings, bad ids. A node
 * that does not validate has no canonical form and no id (fail-closed). Returns the node narrowed, or throws.
 */
export function validateNode(node: unknown): EirNode {
  if (node === null || typeof node !== "object") throw new EirError("node must be an object");
  const n = node as Record<string, unknown>;
  const only = (allowed: readonly string[]) => {
    for (const k of Object.keys(n)) if (!allowed.includes(k)) throw new EirError(`unknown field "${k}" for ${String(n.kind)}`);
  };
  switch (n.kind) {
    case "principal":
      only(["kind", "name", "labels"]);
      if (!isNfcString(n.name)) throw new EirError("principal.name must be NFC text");
      if (!isNfcStringArray(n.labels)) throw new EirError("principal.labels must be NFC text[]");
      return { kind: "principal", name: n.name, labels: [...n.labels] };
    case "effect":
      only(["kind", "effectType", "resourceSelector", "cls"]);
      if (!isNfcString(n.effectType)) throw new EirError("effect.effectType must be NFC text");
      if (!isNfcString(n.resourceSelector)) throw new EirError("effect.resourceSelector must be NFC text");
      if (typeof n.cls !== "string" || !EFFECT_CLASSES.includes(n.cls as EffectClass)) throw new EirError("effect.cls must be a known EffectClass");
      return { kind: "effect", effectType: n.effectType, resourceSelector: n.resourceSelector, cls: n.cls as EffectClass };
    case "guard":
      only(["kind", "predicate"]);
      if (!isNfcString(n.predicate)) throw new EirError("guard.predicate must be NFC text");
      return { kind: "guard", predicate: n.predicate };
    case "obligation":
      only(["kind", "subjects", "entryPoints", "effectId", "guardId"]);
      if (!isNfcStringArray(n.subjects)) throw new EirError("obligation.subjects must be NFC text[]");
      if (!isNfcStringArray(n.entryPoints)) throw new EirError("obligation.entryPoints must be NFC text[]");
      if (typeof n.effectId !== "string" || !HEX64.test(n.effectId)) throw new EirError("obligation.effectId must be a 64-hex effect id");
      if (typeof n.guardId !== "string" || !HEX64.test(n.guardId)) throw new EirError("obligation.guardId must be a 64-hex guard id");
      return { kind: "obligation", subjects: [...n.subjects], entryPoints: [...n.entryPoints], effectId: n.effectId, guardId: n.guardId };
    default:
      throw new EirError(`unknown node kind "${String(n.kind)}"`);
  }
}

/**
 * Canonical value of a node — an explicit, field-by-field mapping (so an unknown field can never leak into identity).
 * Sets (subjects/entryPoints/labels) are DEDUPLICATED + SORTED so identity is order- and multiplicity-independent for
 * genuinely set-semantic fields, while arrays with sequence meaning would be left ordered (none here yet). The `kind`
 * is the discriminant + doubles as the ID domain separator.
 */
export function toCanonical(node: EirNode): CanonicalValue {
  const n = validateNode(node);
  const set = (xs: readonly string[]): readonly string[] => [...new Set(xs)].sort();
  switch (n.kind) {
    case "principal": return { kind: "principal", name: n.name, labels: set(n.labels) };
    case "effect": return { kind: "effect", effectType: n.effectType, resourceSelector: n.resourceSelector, cls: n.cls };
    case "guard": return { kind: "guard", predicate: n.predicate };
    case "obligation": return { kind: "obligation", subjects: set(n.subjects), entryPoints: set(n.entryPoints), effectId: n.effectId, guardId: n.guardId };
  }
}

/** The content-derived id of a node: SHA-256 domain-separated by the node kind over its canonical encoding. */
export function eirId(node: EirNode): string { return eirDigest(node.kind, toCanonical(node)); }
export const principalId = (p: Principal): string => eirId(p);
export const effectId = (e: Effect): string => eirId(e);
export const guardId = (g: Guard): string => eirId(g);
export const obligationId = (o: Obligation): string => eirId(o);

/** Two nodes are the SAME iff their canonical encodings are byte-identical (equivalently, equal ids). */
export function nodeEqual(a: EirNode, b: EirNode): boolean { return canonicalEqual(toCanonical(a), toCanonical(b)); }

/** Serialize a validated node to canonical bytes; parse rejects any non-canonical / schema-invalid input (fail-closed). */
export function encodeNode(node: EirNode): Uint8Array { return encodeCanonical(toCanonical(node)); }
export function decodeNode(bytes: Uint8Array): EirNode {
  if (!isCanonical(bytes)) throw new EirError("node bytes are not canonical");
  return validateNode(decodeCanonical(bytes) as unknown);
}
