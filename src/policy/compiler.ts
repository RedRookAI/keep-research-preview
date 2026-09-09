/**
 * TOTAL POLICY COMPILER (Mechanical-Enforcement Increment 2).
 *
 * The frontier property (one sentence): every accepted policy becomes a COMPLETE, SIGNED, self-verifying EIR bundle
 * in which absence / ambiguity / analysis-uncertainty / version-skew / every error state is represented as DENY —
 * or compilation FAILS. There is no third outcome and no silent fall-through to permit.
 *
 * Totality contract. `compilePolicy(source, signers, threshold)` returns a `SignedBundle` ONLY if the whole pipeline
 * — strict parse, schema closure, id/set integrity, capability classification, reference closure, guard-DAG cycle +
 * normalization, shadow/redundancy/conflict analysis, effect-coverage closure, deterministic bundle assembly,
 * signing, AND a self-verification against the signers' own trust policy — all succeed. Any failure throws
 * `CompileError`. For every declared effect the compiler emits exactly one DECISION ROOT with an explicit
 * `DefaultDeny` leaf, so the compiled decision function is TOTAL by construction (deny-by-default is a materialized
 * artifact, never implicit absence).
 *
 * Scope boundary (honest). Guards are PROPOSITIONAL over OPAQUE atoms (guard_dag.ts). Predicate/atom THEORY — what an
 * atom means, typed operators, interval/label solvers — and runtime EVALUATION are Increment 6 (Total Decision
 * Kernel); actual-object binding is Increment 11. This compiler decides everything decidable at the structural layer
 * and fails closed on anything it cannot decide there (e.g. a guard over more atoms than the propositional bound).
 *
 * Composition (no duplication). Identity + canonical bytes: eir/canonical.ts + eir/eir.ts. Effect classes: the fixed
 * capability allowlist resolveCapabilityEffect (reference/reference_registry.ts). Signing primitive: the Signer port
 * + stubSign (bom/bom_signing.ts) — asymmetric signing is the documented seam; the reference impl is keyed-hash.
 *
 * Grounding: Cedar verified authorization semantics (always Allow/Deny; errors deny) extended to compiler-produced
 * structural coverage; XACML deny-overrides combining; RFC 8259 / RFC 7493 strict JSON; RFC 8949 deterministic CBOR;
 * reproducible-build determinism; SLSA-style signed provenance with domain separation.
 */
import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import { effectId as eirEffectId, principalId as eirPrincipalId, EIR_VERSION, type Effect, type Principal } from "../eir/eir.js";
import { resolveCapabilityEffect, type CapabilityEffect } from "../reference/reference_registry.js";
import {
  normalize, guardKey, atomsOf, toCanonical as guardCanonical, contradiction, implies, equivalent,
  parseCanonical as parseGuard, GuardError, GUARD_DOMAIN, TRUE, type GuardExpr, type NormGuard,
} from "./guard_dag.js";
import { parsePolicyJson, type JsonValue } from "./json.js";
import { stubSign, type Signature, type Signer, type TrustPolicy } from "../bom/bom_signing.js";

export const COMPILER = { name: "keep.policy.compiler", version: "2.0.0" } as const;
export const ALGORITHM = "deny-overrides" as const;
export type CombiningAlgorithm = typeof ALGORITHM;

/** Extract an error message without letting an adversarial thrown value (Proxy with a throwing getter) escape. */
function safeMsg(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; } }

export class CompileError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(`policy compile [${code}]: ${message}`); this.name = "CompileError"; this.code = code; }
}

// ── Compiled bundle shape (all content-addressed; all lists sorted -> deterministic) ──

export interface CompiledPrincipal { readonly id: string; readonly name: string; readonly labels: readonly string[]; }
export interface CompiledEffect { readonly id: string; readonly effectType: string; readonly resourceSelector: string; readonly cls: CapabilityEffect; }
export interface CompiledGuard { readonly id: string; readonly expr: CanonicalValue; readonly atoms: readonly string[]; }
export interface CompiledRule { readonly id: string; readonly decision: "permit" | "deny"; readonly subjects: readonly string[]; readonly entryPoints: readonly string[]; readonly effectId: string; readonly guardId: string; }
export interface RuleRef { readonly ruleId: string; readonly subjects: readonly string[]; readonly entryPoints: readonly string[]; readonly guardId: string; }
export interface DecisionRoot {
  readonly effectId: string;
  readonly cls: CapabilityEffect;
  readonly algorithm: CombiningAlgorithm;
  readonly denies: readonly RuleRef[];
  readonly permits: readonly RuleRef[];
  readonly fallback: { readonly decision: "deny"; readonly reason: "no-applicable-permit" };
}
export interface SourceMapEntry { readonly id: string; readonly kind: string; readonly sourceId: string; }
export interface BundlePayload {
  readonly bundleVersion: 1;
  readonly eirVersion: number;
  readonly policyVersion: number;
  readonly compiler: { readonly name: string; readonly version: string };
  readonly algorithm: CombiningAlgorithm;
  readonly capabilityBindingDigest: string;
  /**
   * NAME-INDEPENDENT identity of the NORMALIZED POLICY: author-chosen rule/effect/guard ids + the source map are
   * excluded, effects/guards are content-addressed, and each effect's deny/permit regions are deduplicated sorted
   * SETS of {subjects, entryPoints, guardId}. Two policies that differ ONLY in author names share this digest; any
   * change to the normalized rule set breaks it.
   *
   * HONEST BOUND (not an overclaim): this is canonical on the normalized RULE SET, NOT on full decision-function
   * EQUIVALENCE. Two policies with the same decision function but different rule DECOMPOSITIONS can still differ —
   * e.g. one permit over {alice,bob} vs two permits over {alice} and {bob}, or a guard expressed two propositionally-
   * equivalent-but-differently-atomised ways. Deciding true policy equivalence is the theory-aware problem (SMT /
   * region algebra over interpreted atoms) that belongs to Increment 6 (Total Decision Kernel); it is deliberately
   * NOT attempted here. Use semanticDigest for name-independent dedup, not as a proof of behavioural equivalence.
   */
  readonly semanticDigest: string;
  readonly principals: readonly CompiledPrincipal[];
  readonly effects: readonly CompiledEffect[];
  readonly guards: readonly CompiledGuard[];
  readonly rules: readonly CompiledRule[];
  readonly decisionRoots: readonly DecisionRoot[];
  readonly sourceMap: readonly SourceMapEntry[];
  readonly checks: readonly string[];
}
export interface SignedBundle {
  readonly payload: BundlePayload;
  readonly payloadDigest: string;
  readonly signatures: readonly Signature[];
}

/** A signer + the material a verifier needs to trust it. verifyKey === privateKey for the keyed-hash reference impl. */
export interface CompilerSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }

/** On success, `bundle` is an OWNED, immutable snapshot verified end-to-end — callers that then read the bundle (e.g.
 * to derive ingress coverage) MUST use THIS, not the caller-supplied object (which may be getter/Proxy-backed). */
export type BundleVerdict = { readonly valid: true; readonly signerCount: number; readonly bundle: SignedBundle } | { readonly valid: false; readonly reason: string };

/** Deep-clone into OWNED plain data, reading every property EXACTLY ONCE (getters/Proxies are read once as data; an
 * accessor property is rejected). This is the capture that makes verify TOCTOU-safe. */
function deepOwn(v: unknown, depth = 0): unknown {
  if (depth > 200) throw new Error("value nested too deep");
  if (v === null) return null;
  const t = typeof v;
  if (t === "string" || t === "bigint" || t === "boolean" || t === "number") return v;
  if (v instanceof Uint8Array) return v.slice();
  if (Array.isArray(v)) return v.map((x) => deepOwn(x, depth + 1));
  if (t === "object") {
    const o = v as Record<string, unknown>;
    if (Object.getOwnPropertySymbols(o).length) throw new Error("symbol keys not allowed in a signed bundle");
    const out: Record<string, unknown> = {};
    for (const k of Object.getOwnPropertyNames(o)) {
      const d = Object.getOwnPropertyDescriptor(o, k)!;
      if (d.get || d.set) throw new Error("accessor property not allowed in a signed bundle");
      out[k] = deepOwn(d.value, depth + 1);
    }
    return out;
  }
  throw new Error(`unsupported value of type ${t} in a signed bundle`);
}
/** Capture a caller's signed bundle into an owned, read-once snapshot (all own keys preserved so an extra wrapper
 * field is caught by the envelope check, not silently dropped). Exported so downstream binders (the ingress manifest)
 * can derive coverage from the SAME owned snapshot they verify, never re-reading a caller-controlled object. */
export function captureBundle(signed: unknown): SignedBundle {
  if (signed === null || typeof signed !== "object" || Array.isArray(signed)) throw new Error("bundle must be an object");
  return deepOwn(signed) as SignedBundle;
}

/** Recompute a bundle's payload digest from its OWN payload content (never the claimed `payloadDigest` field). A
 * downstream binder must use THIS, not the claimed field, so a forged (payload, claimed-digest) pair cannot bind. */
export function bundlePayloadDigest(bundle: SignedBundle): string {
  return payloadDigestOf(captureBundle(bundle).payload);
}

// ── Domain-separated digests (never a bare reusable SHA-256) ──
const payloadDigestOf = (p: BundlePayload): string => eirDigest("keep.policy.bundle.payload/v1", payloadCanonical(p));
const signPreimageOf = (payloadDigest: string, policyVersion: number): string =>
  eirDigest("keep.policy.signature-preimage/v1", { payloadDigest, policyVersion: BigInt(policyVersion), algorithm: ALGORITHM });

/** Deduplicate + canonically sort a rule-ref set for the semantic view (author rule ids are intentionally dropped). */
function semRefs(refs: readonly RuleRef[]): CanonicalValue {
  const m = new Map<string, CanonicalValue>();
  for (const r of refs) {
    const v: CanonicalValue = { subjects: [...r.subjects].sort(), entryPoints: [...r.entryPoints].sort(), guardId: r.guardId };
    m.set(JSON.stringify([[...r.subjects].sort(), [...r.entryPoints].sort(), r.guardId]), v);
  }
  return [...m.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map((e) => e[1]);
}
/** The name-independent decision function: effect identities + per-effect deny/permit REGIONS + guard content. */
function semanticCanonicalOf(p: Pick<BundlePayload, "algorithm" | "effects" | "guards" | "decisionRoots">): CanonicalValue {
  return {
    algorithm: p.algorithm,
    effects: [...p.effects].map((e) => ({ id: e.id, cls: e.cls })).sort((a, b) => (a.id < b.id ? -1 : 1)),
    guards: [...p.guards].map((g) => ({ id: g.id, expr: g.expr })).sort((a, b) => (a.id < b.id ? -1 : 1)),
    decisionRoots: [...p.decisionRoots]
      .map((r) => ({ effectId: r.effectId, cls: r.cls, denies: semRefs(r.denies), permits: semRefs(r.permits), fallback: { decision: r.fallback.decision, reason: r.fallback.reason } }))
      .sort((a, b) => (a.effectId < b.effectId ? -1 : 1)),
  };
}
const semanticDigestOf = (p: Pick<BundlePayload, "algorithm" | "effects" | "guards" | "decisionRoots">): string =>
  eirDigest("keep.policy.semantics/v1", semanticCanonicalOf(p));

/** Digest binding which capability-table classification the bundle compiled against (one {effectType,cls} per effect). */
const capabilityBindingDigestOf = (effects: readonly { readonly effectType: string; readonly cls: CapabilityEffect }[]): string =>
  eirDigest("keep.policy.capability-binding/v1",
    effects.map((c) => ({ effectType: c.effectType, cls: c.cls })).sort((a, b) => (a.effectType < b.effectType ? -1 : a.effectType > b.effectType ? 1 : 0)));

const PAYLOAD_KEYS = ["bundleVersion", "eirVersion", "policyVersion", "compiler", "algorithm", "capabilityBindingDigest", "semanticDigest", "principals", "effects", "guards", "rules", "decisionRoots", "sourceMap", "checks"].sort();
/** The fixed manifest of checks every compiled bundle asserts — re-checked verbatim at load (fabrication-proof). */
const CHECKS = ["schema", "version", "set-integrity", "capability", "reference", "cycle", "dead-guard", "shadow", "conflict", "redundant", "coverage", "determinism", "semantic-digest", "structural", "self-verify"] as const;
const HEX64 = /^[0-9a-f]{64}$/;
/**
 * Re-derive the bundle's STRUCTURAL invariants from the payload alone (load-time revalidation; never trust claimed
 * values). Returns null if sound, else a reason. Checks: exactly the known top-level keys (no unsigned extra field),
 * reference closure (rule.effectId/guardId resolve; every decision-root ruleRef.ruleId is a real rule; one root per
 * effect), well-formed content ids, the fixed algorithm + explicit default-deny leaf, and that the claimed
 * semanticDigest actually matches the payload's decision function.
 */
const exactKeys = (o: unknown, allowed: readonly string[]): boolean =>
  o !== null && typeof o === "object" && !Array.isArray(o) && (() => { const k = Object.keys(o).sort(); const a = [...allowed].sort(); return k.length === a.length && k.every((x, i) => x === a[i]); })();
// Require BOTH to be real arrays — else a string "ab" would satisfy length/index equality against ["a","b"] and slip
// a non-array (with different downstream .includes semantics) past a signature-preserving swap.
const arrEq = (a: unknown, b: unknown): boolean => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);
/** True iff `xs` is STRICTLY increasing by `key` — i.e. canonically sorted AND duplicate-free in one check. */
const strictlyIncreasing = <T>(xs: readonly T[], key: (x: T) => string): boolean => xs.every((x, i) => i === 0 || key(xs[i - 1]!) < key(x));

function structuralProblem(p: BundlePayload): string | null {
  const keys = Object.keys(p).sort();
  if (keys.length !== PAYLOAD_KEYS.length || keys.some((k, i) => k !== PAYLOAD_KEYS[i])) return "payload has unexpected or missing top-level fields";
  // Fail closed on version skew: a threshold-signed bundle from an unsupported/future version must not pass current
  // verification (cross-version semantic confusion). Only exact supported versions are honoured.
  if (p.bundleVersion !== 1) return `unsupported bundleVersion ${p.bundleVersion}`;
  if (p.eirVersion !== EIR_VERSION) return `unsupported eirVersion ${p.eirVersion}`;
  if (p.policyVersion !== 1) return `unsupported policyVersion ${p.policyVersion}`;
  if (p.compiler.name !== COMPILER.name || p.compiler.version !== COMPILER.version) return "unsupported compiler identity";
  if (p.algorithm !== ALGORITHM) return `algorithm must be "${ALGORITHM}"`;
  if (!exactKeys(p.compiler, ["name", "version"])) return "compiler block has unexpected fields";
  const principalIds = new Set<string>();
  const principalNames = new Set<string>();
  const principalNameById = new Map<string, string>();
  for (const pr of p.principals) {
    if (!exactKeys(pr, ["id", "name", "labels"])) return "principal has unexpected fields";
    if (typeof pr.name !== "string" || pr.name.length === 0 || pr.name.normalize("NFC") !== pr.name) return "principal name must be non-empty NFC text";
    if (pr.name === "*") return `a principal may not be named "*" (reserved wildcard)`;
    if (principalNames.has(pr.name)) return `duplicate principal name "${pr.name}" (name-based rule references would be ambiguous)`;
    principalNames.add(pr.name);
    if (!Array.isArray(pr.labels)) return "principal labels must be an array";
    const seenL = new Set<string>();
    for (const l of pr.labels) {
      if (typeof l !== "string" || l.length === 0 || l.normalize("NFC") !== l) return "principal label must be non-empty NFC text";
      if (seenL.has(l)) return "principal has a duplicate label";
      seenL.add(l);
    }
    if (pr.labels.some((l, i) => i > 0 && l < pr.labels[i - 1]!)) return "principal labels are not canonically sorted";
    if (!HEX64.test(pr.id)) return `principal id not a content hash: ${pr.id}`;
    if (eirPrincipalId({ kind: "principal", name: pr.name, labels: pr.labels }) !== pr.id) return `principal id is not the hash of its content: ${pr.id}`;
    if (principalIds.has(pr.id)) return "duplicate principal id in payload";
    principalIds.add(pr.id);
    principalNameById.set(pr.id, pr.name);
  }
  for (const sm of p.sourceMap) if (!exactKeys(sm, ["id", "kind", "sourceId"])) return "source-map entry has unexpected fields";

  // Content-address INTEGRITY: recompute every effect + guard id from its own content (never trust the claimed id),
  // and re-derive each effect's consequence class from the fixed capability table. A falsely content-addressed or
  // reclassified node is rejected. This also rejects extra nested fields on effects/guards (fixed key sets).
  const effectIds = new Set<string>();
  const effectClsById = new Map<string, CapabilityEffect>();
  for (const e of p.effects) {
    if (!exactKeys(e, ["id", "effectType", "resourceSelector", "cls"])) return "effect has unexpected fields";
    if (typeof e.effectType !== "string" || e.effectType.length === 0 || e.effectType.normalize("NFC") !== e.effectType) return "effect.effectType must be non-empty NFC text";
    if (typeof e.resourceSelector !== "string" || e.resourceSelector.length === 0 || e.resourceSelector.normalize("NFC") !== e.resourceSelector) return "effect.resourceSelector must be non-empty NFC text";
    if (!HEX64.test(e.id)) return `effect id not a content hash: ${e.id}`;
    const res = resolveCapabilityEffect(e.effectType);
    if (!res.known || res.effect === "unknown" || res.effect !== e.cls) return `effect "${e.id}" class does not match the capability table`;
    if (eirEffectId({ kind: "effect", effectType: e.effectType, resourceSelector: e.resourceSelector, cls: e.cls }) !== e.id) return `effect id is not the hash of its content: ${e.id}`;
    if (effectIds.has(e.id)) return "duplicate effect id in payload";
    effectIds.add(e.id);
    effectClsById.set(e.id, e.cls);
  }
  const guardIds = new Set<string>();
  for (const g of p.guards) {
    if (!exactKeys(g, ["id", "expr", "atoms"])) return "guard has unexpected fields";
    if (!HEX64.test(g.id)) return `guard id not a content hash: ${g.id}`;
    if (eirDigest(GUARD_DOMAIN, g.expr) !== g.id) return `guard id is not the hash of its expr: ${g.id}`;
    // expr must be a well-formed guard AST in CANONICAL normal form, and the atoms field must match it exactly —
    // a signed bundle cannot carry a malformed/denormalised expr or a misleading atom set behind a correct id.
    let norm: NormGuard;
    try { norm = parseGuard(g.expr); } catch { return `guard "${g.id}" expr is not a valid guard AST`; }
    if (guardKey(normalize(normToExpr(norm))) !== g.id) return `guard "${g.id}" expr is not in canonical normal form`;
    if (!arrEq(atomsOf(norm), g.atoms)) return `guard "${g.id}" atoms do not match its expr (must be the sorted, deduped atom set)`;
    if (guardIds.has(g.id)) return "duplicate guard id in payload";
    guardIds.add(g.id);
  }
  // Re-enforce rule applicability schema + reference closure at LOAD: a signed payload that compilePolicy could never
  // have emitted (empty/duplicated/non-NFC/unsorted/wildcard-mixed sets, or an undeclared principal) must fail closed.
  const validSet = (xs: readonly string[], where: string, names: ReadonlySet<string> | null): string | null => {
    if (!Array.isArray(xs) || xs.length === 0) return `${where} must be a non-empty array`;
    const seen = new Set<string>();
    for (const s of xs) {
      if (typeof s !== "string" || s.length === 0 || s.normalize("NFC") !== s) return `${where} has an empty/non-NFC member`;
      if (seen.has(s)) return `${where} has a duplicate member`;
      seen.add(s);
      if (names && s !== "*" && !names.has(s)) return `${where} references undeclared principal "${s}"`;
    }
    if (xs.includes("*") && xs.length > 1) return `${where} mixes "*" with specific members`;
    if (xs.some((s, i) => i > 0 && s < xs[i - 1]!)) return `${where} is not canonically sorted`;
    return null;
  };
  const ruleById = new Map<string, CompiledRule>();
  for (const r of p.rules) {
    if (!exactKeys(r, ["id", "decision", "subjects", "entryPoints", "effectId", "guardId"])) return "rule has unexpected fields";
    if (typeof r.id !== "string" || r.id.length === 0 || r.id.normalize("NFC") !== r.id) return "rule id must be non-empty NFC text";
    if (ruleById.has(r.id)) return `duplicate rule id "${r.id}"`;
    if (!effectIds.has(r.effectId)) return `rule "${r.id}" references effect not in table`;
    if (!guardIds.has(r.guardId)) return `rule "${r.id}" references guard not in table`;
    if (r.decision !== "permit" && r.decision !== "deny") return `rule "${r.id}" has an invalid decision`;
    const sp = validSet(r.subjects, `rule "${r.id}".subjects`, principalNames); if (sp) return sp;
    const ep = validSet(r.entryPoints, `rule "${r.id}".entryPoints`, null); if (ep) return ep;
    ruleById.set(r.id, r);
  }

  if (p.decisionRoots.length !== effectIds.size) return "decision roots do not cover the effects one-to-one";
  const rootEffects = new Set<string>();
  for (const root of p.decisionRoots) {
    if (!exactKeys(root, ["effectId", "cls", "algorithm", "denies", "permits", "fallback"])) return "decision root has unexpected fields";
    if (!effectIds.has(root.effectId)) return "decision root for an unknown effect";
    if (rootEffects.has(root.effectId)) return "duplicate decision root for an effect";
    rootEffects.add(root.effectId);
    if (root.algorithm !== ALGORITHM) return "decision root has the wrong algorithm";
    if (root.cls !== effectClsById.get(root.effectId)) return `decision root cls contradicts its effect's capability class`;
    if (!exactKeys(root.fallback, ["decision", "reason"]) || root.fallback.decision !== "deny" || root.fallback.reason !== "no-applicable-permit") return "decision root lacks an explicit default-deny leaf";
    // Each ref MUST be a faithful projection of a real rule: right decision list, right effect, matching applicability.
    const checkRefs = (refs: readonly RuleRef[], want: "permit" | "deny"): string | null => {
      for (const ref of refs) {
        if (!exactKeys(ref, ["ruleId", "subjects", "entryPoints", "guardId"])) return "decision-root ref has unexpected fields";
        const rule = ruleById.get(ref.ruleId);
        if (rule === undefined) return `decision root references unknown rule "${ref.ruleId}"`;
        if (rule.decision !== want) return `rule "${ref.ruleId}" (${rule.decision}) is placed in the ${want} list`;
        if (rule.effectId !== root.effectId) return `rule "${ref.ruleId}" is under the wrong effect's decision root`;
        if (rule.guardId !== ref.guardId || !arrEq(rule.subjects, ref.subjects) || !arrEq(rule.entryPoints, ref.entryPoints)) return `decision-root ref for "${ref.ruleId}" does not match the rule`;
      }
      if (!strictlyIncreasing(refs, (r) => r.ruleId)) return `decision-root ${want} list is not canonically sorted / has duplicates`;
      return null;
    };
    const d = checkRefs(root.denies, "deny"); if (d) return d;
    const pm = checkRefs(root.permits, "permit"); if (pm) return pm;
    // every rule on this effect must appear in exactly the right list (no dropped/duplicated rule -> no silent permit).
    const listed = new Set([...root.denies, ...root.permits].map((r) => r.ruleId));
    for (const r of p.rules) if (r.effectId === root.effectId && !listed.has(r.id)) return `rule "${r.id}" on this effect is missing from its decision root`;
  }

  // checks manifest must be exactly the compiler's fixed list (no fabricated/omitted "checks ran" claim).
  if (p.checks.length !== CHECKS.length || p.checks.some((c, i) => c !== CHECKS[i])) return "checks manifest does not match the compiler's";

  // sourceMap: no fabricated entries (every id resolves in its kind's table) + complete provenance for the 1:1 kinds
  // (principals/effects/rules). Guards are excluded from coverage — TRUE + rule-inlined norms have no author name.
  const tableFor: Record<string, ReadonlySet<string>> = { principal: principalIds, effect: effectIds, guard: guardIds, rule: new Set(ruleById.keys()) };
  const covered: Record<string, Set<string>> = { principal: new Set(), effect: new Set(), rule: new Set() };
  for (const sm of p.sourceMap) {
    const t = tableFor[sm.kind];
    if (t === undefined) return `source-map entry has unknown kind "${sm.kind}"`;
    if (!t.has(sm.id)) return `source-map entry references an unknown ${sm.kind} id`;
    if (typeof sm.sourceId !== "string" || sm.sourceId.length === 0 || sm.sourceId.normalize("NFC") !== sm.sourceId) return "source-map sourceId must be non-empty NFC";
    // Re-derive the provenance where it is derivable: a principal's source name IS its declared name; a rule's source
    // id IS the rule id. (effect/guard source ids are author handles, not recomputable — only their resolution above.)
    if (sm.kind === "principal" && sm.sourceId !== principalNameById.get(sm.id)) return "source-map principal name does not match the principal";
    if (sm.kind === "rule" && sm.sourceId !== sm.id) return "source-map rule sourceId must equal the rule id";
    // principals/effects/rules are 1:1 with their provenance — a second entry for the same id is fabricated. (Guards
    // may legitimately have several source names aliasing one normalized id, so they are not in `covered`.)
    if (sm.kind in covered) {
      if (covered[sm.kind]!.has(sm.id)) return `duplicate source-map provenance for ${sm.kind} "${sm.id}"`;
      covered[sm.kind]!.add(sm.id);
    }
  }
  if (covered.principal!.size !== principalIds.size) return "source map does not cover all principals";
  if (covered.effect!.size !== effectIds.size) return "source map does not cover all effects";
  if (covered.rule!.size !== ruleById.size) return "source map does not cover all rules";

  // Canonical ORDERING of every list (deterministic bundle identity): a re-signed permutation compilePolicy could
  // never emit must fail closed. Strictly-increasing keys also re-assert duplicate-freedom.
  if (!strictlyIncreasing(p.principals, (x) => x.id)) return "principals are not canonically sorted";
  if (!strictlyIncreasing(p.effects, (x) => x.id)) return "effects are not canonically sorted";
  if (!strictlyIncreasing(p.guards, (x) => x.id)) return "guards are not canonically sorted";
  if (!strictlyIncreasing(p.rules, (x) => x.id)) return "rules are not canonically sorted";
  if (!strictlyIncreasing(p.decisionRoots, (x) => x.effectId)) return "decision roots are not canonically sorted";
  // source map orders by (kind, sourceId) — the exact tuple comparator the compiler uses (strict => duplicate-free).
  if (!p.sourceMap.every((x, i) => { if (i === 0) return true; const pv = p.sourceMap[i - 1]!; return pv.kind < x.kind || (pv.kind === x.kind && pv.sourceId < x.sourceId); })) return "source map is not canonically sorted";

  if (capabilityBindingDigestOf(p.effects) !== p.capabilityBindingDigest) return "capabilityBindingDigest does not match the payload's effect classifications";
  if (semanticDigestOf(p) !== p.semanticDigest) return "semanticDigest does not match the payload's normalized policy";
  return null;
}

// ── strict field helpers over the parsed JSON tree (bigint numbers, plain objects) ──
const isPlainObj = (x: unknown): x is Record<string, JsonValue> => x !== null && typeof x === "object" && !Array.isArray(x);
const isNfc = (x: unknown): x is string => typeof x === "string" && x.normalize("NFC") === x && (x as string).length > 0;
function only(obj: Record<string, JsonValue>, allowed: readonly string[], where: string): void {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) throw new CompileError("schema", `unknown field "${k}" in ${where}`);
}
function req<T>(v: T | undefined, code: string, msg: string): T { if (v === undefined) throw new CompileError(code, msg); return v; }
function asArray(x: JsonValue | undefined, where: string): readonly JsonValue[] {
  if (!Array.isArray(x)) throw new CompileError("schema", `${where} must be an array`);
  return x;
}
function asNfc(x: JsonValue | undefined, where: string): string {
  if (!isNfc(x)) throw new CompileError("schema", `${where} must be non-empty NFC text`);
  return x;
}
function asStringSet(x: JsonValue | undefined, where: string): readonly string[] {
  const arr = asArray(x, where);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const e of arr) {
    const s = asNfc(e, `${where} element`);
    if (seen.has(s)) throw new CompileError("set-integrity", `${where} has duplicate member "${s}" (sets must be duplicate-free)`);
    seen.add(s);
    out.push(s);
  }
  return [...out].sort();
}

/**
 * Compile a policy (string or bytes or already-parsed JsonValue) into a signed, self-verified bundle. Throws
 * CompileError on any defect. `signers` must be non-empty and `threshold` in [1, signers.length]; the produced bundle
 * is signed by every signer and self-verified against {their keyids → verifyKeys, threshold} before it is returned.
 */
export function compilePolicy(source: string | Uint8Array | JsonValue, signers: readonly CompilerSigner[], threshold = signers.length): SignedBundle {
  if (signers.length === 0) throw new CompileError("signing", "at least one signer is required (deny-by-default: an unsigned bundle is never emitted)");
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) throw new CompileError("signing", `threshold must be an integer in [1, ${signers.length}]`);
  const keyids = new Set<string>();
  for (const s of signers) { if (keyids.has(s.keyid)) throw new CompileError("signing", `duplicate signer keyid "${s.keyid}"`); keyids.add(s.keyid); }

  const root = (typeof source === "string" || source instanceof Uint8Array) ? parsePolicyJson(source) : source;
  const payload = compileToPayload(root);

  // sign the domain-separated preimage of the payload digest; assemble; then SELF-VERIFY (fail closed if it doesn't).
  const payloadDigest = payloadDigestOf(payload);
  const preimage = signPreimageOf(payloadDigest, payload.policyVersion);
  // Each declared signer must produce EXACTLY its own, VALID signature — even below threshold. A signer returning a
  // wrong/duplicate keyid or a bad signature is a fault we fail compilation on (not silently tolerate because other
  // signatures already meet the threshold).
  const produced = signers.map((s) => {
    const sig = s.signer.sign(preimage);
    if (sig === null || typeof sig !== "object" || typeof sig.keyid !== "string" || typeof sig.sig !== "string") throw new CompileError("signing", `signer for "${s.keyid}" returned a malformed signature`);
    if (sig.keyid !== s.keyid) throw new CompileError("signing", `signer returned keyid "${sig.keyid}", expected "${s.keyid}"`);
    if (sig.sig !== stubSign(s.verifyKey, s.keyid, preimage).sig) throw new CompileError("signing", `signer for "${s.keyid}" produced an invalid signature`);
    return { keyid: sig.keyid, sig: sig.sig };
  });
  const signatures = produced.sort((a, b) => (a.keyid < b.keyid ? -1 : a.keyid > b.keyid ? 1 : 0));
  const bundle: SignedBundle = { payload, payloadDigest, signatures };
  const trust: TrustPolicy = { trustedKeys: new Map(signers.map((s) => [s.keyid, s.verifyKey] as const)), threshold };
  const v = verifyBundle(bundle, trust);
  if (!v.valid) throw new CompileError("self-verify", `compiler produced a bundle that does not verify: ${v.reason}`);
  return bundle;
}

/**
 * Verify a signed bundle END TO END: recompute the payload digest from the payload (never trust the claimed digest),
 * recompute the signing preimage, and count valid signatures from DISTINCT TRUSTED keys against the threshold. Total
 * and fail-safe — any shortfall is `valid:false`, never an exception.
 */
export function verifyBundle(bundle: SignedBundle, trust: TrustPolicy): BundleVerdict {
  // TOTAL + fail-safe: any malformed input (null/typed-wrong wrapper, signatures, or trust policy) becomes valid:false,
  // never an exception. The whole body is guarded so a caller can trust the verdict unconditionally.
  try {
    // Trust policy shape (deny-by-default): a non-positive/non-integer threshold or a non-Map key set is unusable.
    if (bundle === null || typeof bundle !== "object") return { valid: false, reason: "bundle must be an object" };
    const rawKeys = trust?.trustedKeys; if (!(rawKeys instanceof Map)) return { valid: false, reason: "trust.trustedKeys must be a Map" };
    const trustedKeys = new Map(rawKeys); const threshold = trust.threshold; // capture map ONCE before clone (TOCTOU-safe)
    if (!Number.isInteger(threshold) || threshold < 1) return { valid: false, reason: "invalid-threshold (must be an integer >= 1)" };
    // Capture the caller's bundle into an OWNED, read-once snapshot FIRST (getter/Proxy-backed inputs are read once),
    // then verify + return that snapshot — so no downstream reader can observe a different view than was verified.
    let b: SignedBundle;
    try { b = captureBundle(bundle); } catch (e) { return { valid: false, reason: safeMsg(e) }; }
    // Envelope schema: exactly {payload, payloadDigest, signatures}; signatures a canonically-sorted, duplicate-free
    // list of {keyid, sig} strings. Extra wrapper fields / non-canonical or malformed signature lists fail closed.
    if (!exactKeys(b, ["payload", "payloadDigest", "signatures"])) return { valid: false, reason: "malformed bundle envelope" };
    if (typeof b.payloadDigest !== "string") return { valid: false, reason: "payloadDigest must be a string" };
    if (!Array.isArray(b.signatures) || b.signatures.length === 0) return { valid: false, reason: "signatures must be a non-empty array" };
    for (const s of b.signatures) if (!exactKeys(s, ["keyid", "sig"]) || typeof s.keyid !== "string" || typeof s.sig !== "string") return { valid: false, reason: "malformed signature entry" };
    if (!strictlyIncreasing(b.signatures, (s) => s.keyid)) return { valid: false, reason: "signatures not canonically sorted / duplicate keyid" };

    // Load-time STRUCTURAL revalidation: a valid signature over a malformed/extended payload must still not verify.
    const structural = structuralProblem(b.payload);
    if (structural !== null) return { valid: false, reason: `structural: ${structural}` };
    const recomputed = payloadDigestOf(b.payload);
    if (recomputed !== b.payloadDigest) return { valid: false, reason: "payload digest mismatch (tampered payload or claimed digest)" };
    const preimage = signPreimageOf(recomputed, b.payload.policyVersion);
    let valid = 0;
    const seen = new Set<string>();
    for (const s of b.signatures) {
      const key = trustedKeys.get(s.keyid);
      if (key === undefined || seen.has(s.keyid)) continue;
      const expected = stubSign(key, s.keyid, preimage).sig;
      if (s.sig === expected) { seen.add(s.keyid); valid++; }
    }
    if (valid < threshold) return { valid: false, reason: `threshold-not-met:${valid}<${threshold}` };
    return { valid: true, signerCount: valid, bundle: b };
  } catch (e) {
    return { valid: false, reason: `verify error: ${safeMsg(e)}` };
  }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
// The pipeline: parse tree -> validated payload. Pure + deterministic. Each stage fails closed on its defect class.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

function compileToPayload(root: JsonValue): BundlePayload {
  // [1] schema/version closure
  if (!isPlainObj(root)) throw new CompileError("schema", "policy root must be an object");
  only(root, ["version", "combiningAlgorithm", "principals", "effects", "guards", "rules"], "policy");
  const policyVersion = root.version;
  if (typeof policyVersion !== "bigint" || policyVersion !== 1n) throw new CompileError("version", "policy version must be 1");
  if (root.combiningAlgorithm !== ALGORITHM) throw new CompileError("schema", `combiningAlgorithm must be "${ALGORITHM}" (the only total, safe algorithm in v1)`);

  // [2] principals: id/set integrity + EIR identity
  const principals: CompiledPrincipal[] = [];
  const principalNames = new Set<string>();
  for (const raw of asArray(root.principals, "principals")) {
    if (!isPlainObj(raw)) throw new CompileError("schema", "principal must be an object");
    only(raw, ["name", "labels"], "principal");
    const name = asNfc(raw.name, "principal.name");
    if (name === "*") throw new CompileError("schema", `a principal may not be named "*" (reserved for the any-principal wildcard)`);
    if (principalNames.has(name)) throw new CompileError("set-integrity", `duplicate principal name "${name}"`);
    principalNames.add(name);
    const labels = raw.labels === undefined ? [] : asStringSet(raw.labels, "principal.labels");
    const node: Principal = { kind: "principal", name, labels };
    principals.push({ id: eirPrincipalId(node), name, labels });
  }

  // [3] effects: id/set integrity + capability classification (unknown => error, never a default class)
  const effects: CompiledEffect[] = [];
  const effectBySourceId = new Map<string, CompiledEffect>();
  const effectIdOwner = new Map<string, string>(); // content id -> the (single) source id that owns it
  const capBinding: { effectType: string; cls: CapabilityEffect }[] = [];
  for (const raw of asArray(root.effects, "effects")) {
    if (!isPlainObj(raw)) throw new CompileError("schema", "effect must be an object");
    only(raw, ["id", "effectType", "resourceSelector", "cls"], "effect");
    if ("cls" in raw) throw new CompileError("schema", "effect.cls is DERIVED from the capability table, not declared (a policy may not assert its own consequence class)");
    const sourceId = asNfc(raw.id, "effect.id");
    if (effectBySourceId.has(sourceId)) throw new CompileError("set-integrity", `duplicate effect id "${sourceId}"`);
    const effectType = asNfc(raw.effectType, "effect.effectType");
    const resourceSelector = asNfc(raw.resourceSelector, "effect.resourceSelector");
    const res = resolveCapabilityEffect(effectType);
    if (!res.known || res.effect === "unknown") throw new CompileError("capability", `effect "${sourceId}" has effectType "${effectType}" that does not resolve to a known capability class (unknown => deny-by-default, not compilable)`);
    const cls = res.effect;
    const node: Effect = { kind: "effect", effectType, resourceSelector, cls };
    const compiled: CompiledEffect = { id: eirEffectId(node), effectType, resourceSelector, cls };
    // Two distinct source ids with IDENTICAL identity (same effectType+resourceSelector) are the SAME effect: one
    // decision root would own both, silently dropping the other's rules (a real silent-permit path). Reject it.
    const owner = effectIdOwner.get(compiled.id);
    if (owner !== undefined) throw new CompileError("set-integrity", `effects "${owner}" and "${sourceId}" have identical identity (same effectType "${effectType}" + resourceSelector) — declare the effect once`);
    effectIdOwner.set(compiled.id, sourceId);
    effects.push(compiled);
    effectBySourceId.set(sourceId, compiled);
    capBinding.push({ effectType, cls });
  }

  // [4/5] guards: reference closure over guard refs, cycle detection, propositional normalization.
  const guardSourceIds = new Set<string>();
  const rawGuardById = new Map<string, Record<string, JsonValue>>();
  for (const raw of asArray(root.guards, "guards")) {
    if (!isPlainObj(raw)) throw new CompileError("schema", "guard must be an object");
    const id = asNfc(raw.id, "guard.id");
    if (guardSourceIds.has(id)) throw new CompileError("set-integrity", `duplicate guard id "${id}"`);
    guardSourceIds.add(id);
    rawGuardById.set(id, raw);
  }
  const normByGuardId = new Map<string, NormGuard>();
  const resolveGuard = (id: string, stack: readonly string[]): NormGuard => {
    const cached = normByGuardId.get(id);
    if (cached) return cached;
    if (stack.includes(id)) throw new CompileError("cycle", `guard reference cycle: ${[...stack, id].join(" -> ")}`);
    const raw = rawGuardById.get(id);
    if (raw === undefined) throw new CompileError("reference", `rule/guard references undefined guard "${id}"`);
    only(raw, ["id", "predicate", "not", "allOf", "anyOf"], `guard "${id}"`);
    const forms = ["predicate", "not", "allOf", "anyOf"].filter((k) => k in raw);
    if (forms.length !== 1) throw new CompileError("schema", `guard "${id}" must have exactly one of predicate/not/allOf/anyOf (has ${forms.length})`);
    const toExpr = (node: JsonValue, key: string): GuardExpr => {
      // a guard body references OTHER guards by id (string) or is a leaf predicate (on the top-level `predicate`).
      const refToExpr = (ref: JsonValue): GuardExpr => {
        if (typeof ref !== "string") throw new CompileError("schema", `guard "${id}" ${key} operand must be a guard-id string`);
        const sub = resolveGuard(asNfc(ref, `guard "${id}" operand`), [...stack, id]);
        return normToExpr(sub);
      };
      if (key === "predicate") { const p = asNfc(node, `guard "${id}".predicate`); return { atom: p }; }
      if (key === "not") return { not: refToExpr(node) };
      if (key === "allOf") return { allOf: asArray(node, `guard "${id}".allOf`).map(refToExpr) };
      return { anyOf: asArray(node, `guard "${id}".anyOf`).map(refToExpr) };
    };
    let norm: NormGuard;
    try { norm = normalize(toExpr(raw[forms[0]!]!, forms[0]!)); }
    catch (e) { if (e instanceof GuardError) throw new CompileError("guard", `guard "${id}": ${e.message}`); throw e; }
    normByGuardId.set(id, norm);
    return norm;
  };
  for (const id of guardSourceIds) resolveGuard(id, []);

  // [6] rules: reference closure, applicability, deny/permit split by effect
  interface Internal { rule: CompiledRule; norm: NormGuard; effectSourceId: string; subjectSet: ReadonlySet<string>; entrySet: ReadonlySet<string>; }
  const internal: Internal[] = [];
  const ruleSourceIds = new Set<string>();
  const ruleReferencedGuards = new Set<string>(); // declared guard ids used directly by a rule
  // "*" (any) combined with a specific member is redundant + non-injective (`["*","alice"]` means the same as `["*"]`).
  const noWildcardMix = (xs: readonly string[], where: string): void => {
    if (xs.includes("*") && xs.length > 1) throw new CompileError("schema", `${where} must not combine "*" (any) with specific members — use ["*"] alone`);
  };
  for (const raw of asArray(root.rules, "rules")) {
    if (!isPlainObj(raw)) throw new CompileError("schema", "rule must be an object");
    only(raw, ["id", "decision", "subjects", "entryPoints", "effect", "guard"], "rule");
    const id = asNfc(raw.id, "rule.id");
    if (ruleSourceIds.has(id)) throw new CompileError("set-integrity", `duplicate rule id "${id}"`);
    ruleSourceIds.add(id);
    const decision = raw.decision;
    if (decision !== "permit" && decision !== "deny") throw new CompileError("schema", `rule "${id}".decision must be "permit" or "deny"`);
    const subjects = asStringSet(raw.subjects, `rule "${id}".subjects`);
    if (subjects.length === 0) throw new CompileError("schema", `rule "${id}".subjects must be non-empty (use ["*"] for any principal)`);
    noWildcardMix(subjects, `rule "${id}".subjects`);
    for (const s of subjects) if (s !== "*" && !principalNames.has(s)) throw new CompileError("reference", `rule "${id}" references undefined principal "${s}"`);
    const entryPoints = asStringSet(raw.entryPoints, `rule "${id}".entryPoints`);
    if (entryPoints.length === 0) throw new CompileError("schema", `rule "${id}".entryPoints must be non-empty (use ["*"] for any entry point)`);
    noWildcardMix(entryPoints, `rule "${id}".entryPoints`);
    const effectSourceId = asNfc(raw.effect, `rule "${id}".effect`);
    const eff = effectBySourceId.get(effectSourceId);
    if (eff === undefined) throw new CompileError("reference", `rule "${id}" references undefined effect "${effectSourceId}"`);
    let norm: NormGuard = TRUE;
    if ("guard" in raw) { const gid = asNfc(raw.guard, `rule "${id}".guard`); norm = req(normByGuardId.get(gid), "reference", `rule "${id}" references undefined guard "${gid}"`); ruleReferencedGuards.add(gid); }
    internal.push({
      rule: { id, decision, subjects, entryPoints, effectId: eff.id, guardId: guardKey(norm) },
      norm, effectSourceId, subjectSet: new Set(subjects), entrySet: new Set(entryPoints),
    });
  }

  // [6b] dead-guard closure: every DECLARED guard must be reachable from some rule (directly, or via a composite that
  // is itself reached). An unreferenced declaration is dead policy weight + a non-injectivity source — reject it.
  const operandGids = (raw: Record<string, JsonValue>): string[] => {
    const pick = (x: JsonValue | undefined): string[] => (Array.isArray(x) ? x.filter((e): e is string => typeof e === "string") : typeof x === "string" ? [x] : []);
    if ("not" in raw) return pick(raw.not);
    if ("allOf" in raw) return pick(raw.allOf);
    if ("anyOf" in raw) return pick(raw.anyOf);
    return [];
  };
  const reachedGuards = new Set<string>();
  const markGuard = (gid: string): void => {
    if (reachedGuards.has(gid)) return;
    reachedGuards.add(gid);
    const raw = rawGuardById.get(gid);
    if (raw) for (const sub of operandGids(raw)) markGuard(sub);
  };
  for (const gid of ruleReferencedGuards) markGuard(gid);
  for (const gid of guardSourceIds) if (!reachedGuards.has(gid)) throw new CompileError("dead-guard", `guard "${gid}" is declared but never referenced by any rule (dead declaration — remove it)`);

  // [7] shadow / redundancy / conflict — sound (only flag genuinely-dead or genuinely-ambiguous), deny-overrides.
  const coordSubsumes = (big: Internal, small: Internal): boolean =>
    (big.subjectSet.has("*") || [...small.subjectSet].every((s) => big.subjectSet.has(s) || big.subjectSet.has("*"))) &&
    (big.entrySet.has("*") || [...small.entrySet].every((e) => big.entrySet.has(e) || big.entrySet.has("*")));
  const coordOverlap = (a: Internal, b: Internal): boolean =>
    (a.subjectSet.has("*") || b.subjectSet.has("*") || [...a.subjectSet].some((s) => b.subjectSet.has(s))) &&
    (a.entrySet.has("*") || b.entrySet.has("*") || [...a.entrySet].some((e) => b.entrySet.has(e)));
  const byEffect = new Map<string, Internal[]>();
  for (const it of internal) { const g = byEffect.get(it.effectSourceId) ?? []; g.push(it); byEffect.set(it.effectSourceId, g); }
  for (const it of internal) {
    // a rule whose guard can never be true is dead (structural contradiction).
    if (contradiction(it.norm)) throw new CompileError("shadow", `rule "${it.rule.id}" has an unsatisfiable guard (it can never fire — remove it or fix the policy)`);
  }
  for (const [, group] of byEffect) {
    for (const a of group) for (const b of group) {
      if (a === b) continue;
      const overlapCoord = coordOverlap(a, b);
      // CONFLICT: exact-equivalent applicability, opposite decisions -> ambiguous intent (deny-overrides would silently win).
      if (a.rule.decision !== b.rule.decision && a.rule.id < b.rule.id &&
          setEq(a.subjectSet, b.subjectSet) && setEq(a.entrySet, b.entrySet) && equivalent(a.norm, b.norm)) {
        throw new CompileError("conflict", `rules "${a.rule.id}" and "${b.rule.id}" have identical applicability but opposite decisions (ambiguous — make the override explicit)`);
      }
      // SHADOW: a permit fully covered by a deny (deny-overrides kills it everywhere it applies).
      if (a.rule.decision === "permit" && b.rule.decision === "deny" && coordSubsumes(b, a) && implies(a.norm, b.norm)) {
        throw new CompileError("shadow", `permit rule "${a.rule.id}" is fully shadowed by deny rule "${b.rule.id}" (it can never grant access)`);
      }
      // REDUNDANCY: a same-decision rule fully subsumed by another (adds nothing).
      if (a.rule.decision === b.rule.decision && coordSubsumes(b, a) && implies(a.norm, b.norm) && a.rule.id !== b.rule.id &&
          !(coordSubsumes(a, b) && a.rule.id > b.rule.id)) { // keep exactly one of a mutually-subsuming pair
        if (overlapCoord) throw new CompileError("redundant", `rule "${a.rule.id}" is redundant — fully subsumed by "${b.rule.id}" with the same decision`);
      }
    }
  }

  // [8] combiner: one total DECISION ROOT per DECLARED effect, with an explicit DefaultDeny leaf (coverage closure).
  const ruleRef = (it: Internal): RuleRef => ({ ruleId: it.rule.id, subjects: it.rule.subjects, entryPoints: it.rule.entryPoints, guardId: it.rule.guardId });
  const byId = (a: { ruleId: string }, b: { ruleId: string }) => (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0);
  const decisionRoots: DecisionRoot[] = effects.map((e) => {
    const sourceId = [...effectBySourceId.entries()].find(([, v]) => v.id === e.id)![0];
    const group = byEffect.get(sourceId) ?? [];
    return {
      effectId: e.id, cls: e.cls, algorithm: ALGORITHM,
      denies: group.filter((g) => g.rule.decision === "deny").map(ruleRef).sort(byId),
      permits: group.filter((g) => g.rule.decision === "permit").map(ruleRef).sort(byId),
      fallback: { decision: "deny" as const, reason: "no-applicable-permit" as const },
    };
  }).sort((a, b) => (a.effectId < b.effectId ? -1 : a.effectId > b.effectId ? 1 : 0));
  if (decisionRoots.length !== effects.length) throw new CompileError("coverage", "internal: not every effect produced a decision root");

  // [9] EIR lowering / source map / guard table. The guard table is EXACTLY the set of guards referenced by compiled
  // rules (each rule's fully-inlined normalized guard), deduped by content id. This guarantees REFERENCE CLOSURE
  // within the bundle — every rule.guardId (including guardKey(TRUE) for unguarded rules) is present — and excludes
  // dead declarations, so identity reflects only the reachable decision semantics.
  const guardTable = new Map<string, CompiledGuard>();
  const addGuard = (norm: NormGuard): void => {
    const gid = guardKey(norm);
    if (!guardTable.has(gid)) guardTable.set(gid, { id: gid, expr: guardCanonical(norm), atoms: atomsOf(norm) });
  };
  for (const it of internal) addGuard(it.norm);          // every rule.guardId (incl. guardKey(TRUE)) is present
  for (const norm of normByGuardId.values()) addGuard(norm); // + every declared (reachable) guard -> source-map closure
  const guards: CompiledGuard[] = [...guardTable.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const sourceMap: SourceMapEntry[] = [
    ...[...principalNames].map((name) => ({ id: principals.find((p) => p.name === name)!.id, kind: "principal", sourceId: name })),
    ...[...effectBySourceId.entries()].map(([sid, e]) => ({ id: e.id, kind: "effect", sourceId: sid })),
    ...[...normByGuardId.entries()].map(([sid, n]) => ({ id: guardKey(n), kind: "guard", sourceId: sid })),
    ...internal.map((it) => ({ id: it.rule.id, kind: "rule", sourceId: it.rule.id })),
  ].sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.sourceId < b.sourceId ? -1 : a.sourceId > b.sourceId ? 1 : 0));

  const capabilityBindingDigest = capabilityBindingDigestOf(capBinding);

  const semanticInputs = { algorithm: ALGORITHM, effects: [...effects].sort((a, b) => (a.id < b.id ? -1 : 1)), guards, decisionRoots };
  const payload: BundlePayload = {
    bundleVersion: 1, eirVersion: EIR_VERSION, policyVersion: Number(policyVersion), compiler: { name: COMPILER.name, version: COMPILER.version },
    algorithm: ALGORITHM, capabilityBindingDigest, semanticDigest: semanticDigestOf(semanticInputs),
    principals: [...principals].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    effects: [...effects].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    guards,
    rules: internal.map((it) => it.rule).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    decisionRoots, sourceMap,
    checks: [...CHECKS],
  };
  return payload;
}

function setEq(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  return a.size === b.size && [...a].every((x) => b.has(x));
}

/** normalized guard -> a source expression that re-normalizes to the same guard (used to inline a referenced guard). */
function normToExpr(g: NormGuard): GuardExpr {
  switch (g.t) {
    case "atom": return { atom: g.atom };
    case "not": return { not: normToExpr(g.op) };
    case "and": return { allOf: g.ops.map(normToExpr) };
    case "or": return { anyOf: g.ops.map(normToExpr) };
    case "const": return g.v ? { allOf: [] } : { anyOf: [] }; // TRUE = empty allOf, FALSE = empty anyOf
  }
}

/** Canonical value of the payload — explicit field mapping so no stray field can leak into the content id. */
function payloadCanonical(p: BundlePayload): CanonicalValue {
  return {
    bundleVersion: BigInt(p.bundleVersion),
    eirVersion: BigInt(p.eirVersion),
    policyVersion: BigInt(p.policyVersion),
    compiler: { name: p.compiler.name, version: p.compiler.version },
    algorithm: p.algorithm,
    capabilityBindingDigest: p.capabilityBindingDigest,
    semanticDigest: p.semanticDigest,
    principals: p.principals.map((x) => ({ id: x.id, name: x.name, labels: [...x.labels] })),
    effects: p.effects.map((x) => ({ id: x.id, effectType: x.effectType, resourceSelector: x.resourceSelector, cls: x.cls })),
    guards: p.guards.map((x) => ({ id: x.id, expr: x.expr, atoms: [...x.atoms] })),
    rules: p.rules.map((x) => ({ id: x.id, decision: x.decision, subjects: [...x.subjects], entryPoints: [...x.entryPoints], effectId: x.effectId, guardId: x.guardId })),
    decisionRoots: p.decisionRoots.map((r) => ({
      effectId: r.effectId, cls: r.cls, algorithm: r.algorithm,
      denies: r.denies.map(refCanonical), permits: r.permits.map(refCanonical),
      fallback: { decision: r.fallback.decision, reason: r.fallback.reason },
    })),
    sourceMap: p.sourceMap.map((s) => ({ id: s.id, kind: s.kind, sourceId: s.sourceId })),
    checks: [...p.checks],
  };
}
const refCanonical = (r: RuleRef): CanonicalValue => ({ ruleId: r.ruleId, subjects: [...r.subjects], entryPoints: [...r.entryPoints], guardId: r.guardId });
