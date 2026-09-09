/**
 * Guard-DAG normalization + PROPOSITIONAL analysis over opaque atoms (Mechanical-Enforcement Increment 2, step B).
 *
 * A policy guard is a boolean combination (allOf / anyOf / not) over LEAF ATOMS. Increment 2 treats each atom as an
 * OPAQUE free boolean variable keyed by its predicate string — it does NOT interpret the predicate. Predicate/atom
 * THEORY (what `path.within-root` actually means, typed operators, interval/label solvers) is Increment 6's job
 * (Total Decision Kernel). Keeping that boundary is deliberate: this increment delivers the STRUCTURAL/propositional
 * layer completely, and Increment 6 refines atoms with theory. The two compose — propositional unsat here is a
 * genuine (sound) unsat there; theory only ever makes MORE things unsat, never fewer.
 *
 * What this module guarantees:
 *   - a DETERMINISTIC canonical normal form for a guard (flatten same-op, constant-fold, drop identities, dedup +
 *     sort operands by content id, eliminate double negation, collapse x∧¬x→false / x∨¬x→true) — so two structurally
 *     equivalent guards get the SAME content id;
 *   - EXACT propositional decision procedures (satisfiable / tautology / implies / equivalent) over the free atoms,
 *     used by the compiler for shadowing, conflict, and redundancy checks;
 *   - FAIL-CLOSED bounding: a guard whose distinct-atom count exceeds the decision bound is UNDECIDABLE here and must
 *     become a compilation failure (never a silent "assume satisfiable").
 *
 * Grounding: canonical normal forms + content-addressed identity (canonical.ts, RFC 8949); exact Boolean equivalence
 * (truth-table over a bounded free-variable set — the same soundness a ROBDD gives, simpler and exact for the small
 * atom counts a policy guard has); propositional abstraction of a first-order theory (atoms as free variables).
 */
import { eirDigest, type CanonicalValue } from "../eir/canonical.js";

/** Source guard expression (already reference-resolved by the compiler into a tree of leaves/composites). */
export type GuardExpr =
  | { readonly atom: string }
  | { readonly not: GuardExpr }
  | { readonly allOf: readonly GuardExpr[] }
  | { readonly anyOf: readonly GuardExpr[] };

/** Canonical normalized guard. `and`/`or` operand lists are deduplicated + sorted; constants are folded. */
export type NormGuard =
  | { readonly t: "const"; readonly v: boolean }
  | { readonly t: "atom"; readonly atom: string }
  | { readonly t: "not"; readonly op: NormGuard }
  | { readonly t: "and"; readonly ops: readonly NormGuard[] }
  | { readonly t: "or"; readonly ops: readonly NormGuard[] };

export const TRUE: NormGuard = { t: "const", v: true };
export const FALSE: NormGuard = { t: "const", v: false };

/** Maximum distinct atoms a single decision procedure will enumerate. Above this we FAIL CLOSED (undecidable here). */
export const MAX_DECISION_ATOMS = 20;

export class GuardError extends Error {
  constructor(m: string) { super(`guard: ${m}`); this.name = "GuardError"; }
}
/** Thrown when a guard exceeds the propositional decision bound — the compiler turns this into a compilation failure. */
export class GuardUndecidable extends GuardError {
  constructor(atoms: number) { super(`${atoms} distinct atoms exceeds the decision bound ${MAX_DECISION_ATOMS} — undecidable (fail closed)`); this.name = "GuardUndecidable"; }
}

/** Canonical value of a normalized guard — the basis of its content id and its embedding in the bundle. */
export function toCanonical(g: NormGuard): CanonicalValue {
  switch (g.t) {
    case "const": return { k: "const", v: g.v };
    case "atom": return { k: "atom", atom: g.atom };
    case "not": return { k: "not", op: toCanonical(g.op) };
    case "and":
    case "or": return { k: g.t, ops: g.ops.map(toCanonical) };
  }
}

/** Domain separator for guard content ids (exported so a verifier can re-derive a guard id from its canonical expr). */
export const GUARD_DOMAIN = "keep.policy.guard/v1";
/** Content id of a normalized guard (domain-separated). Structurally-equal guards share it; any change breaks it. */
export function guardKey(g: NormGuard): string { return eirDigest(GUARD_DOMAIN, toCanonical(g)); }

/**
 * Parse a canonical guard value back into a typed NormGuard, VALIDATING its AST shape (fail-closed on anything that is
 * not a well-formed guard node). This is the verifier's inverse of toCanonical: a signed bundle's guard `expr` must be
 * a real guard tree, not arbitrary content that merely hashes to the claimed id. It does NOT assert canonical-normal
 * form — the caller re-normalizes and compares the content id for that.
 */
export function parseCanonical(v: CanonicalValue, depth = 0): NormGuard {
  if (depth > 64) throw new GuardError("guard expr nested too deep");
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new GuardError("guard node must be an object");
  const o = v as Record<string, CanonicalValue>;
  const nkeys = Object.keys(o).length;
  switch (o.k) {
    case "const": if (nkeys !== 2 || typeof o.v !== "boolean") throw new GuardError("bad const node"); return { t: "const", v: o.v };
    case "atom": if (nkeys !== 2 || typeof o.atom !== "string" || o.atom.normalize("NFC") !== o.atom) throw new GuardError("bad atom node"); return { t: "atom", atom: o.atom };
    case "not": if (nkeys !== 2 || !("op" in o)) throw new GuardError("bad not node"); return { t: "not", op: parseCanonical(o.op, depth + 1) };
    case "and":
    case "or": if (nkeys !== 2 || !Array.isArray(o.ops)) throw new GuardError("bad junction node"); return { t: o.k, ops: o.ops.map((x) => parseCanonical(x, depth + 1)) };
    default: throw new GuardError(`unknown guard node kind ${JSON.stringify(o.k)}`);
  }
}

/** Distinct atoms of a guard, sorted. */
export function atomsOf(g: NormGuard): string[] {
  const s = new Set<string>();
  const walk = (x: NormGuard): void => {
    if (x.t === "atom") s.add(x.atom);
    else if (x.t === "not") walk(x.op);
    else if (x.t === "and" || x.t === "or") x.ops.forEach(walk);
  };
  walk(g);
  return [...s].sort();
}

/**
 * Normalize a source guard expression into canonical form. Deterministic and idempotent: normalize(normalize(x)) has
 * the same content id as normalize(x), and operand order / duplication in the source does not affect the result.
 */
export function normalize(expr: GuardExpr): NormGuard {
  if (expr === null || typeof expr !== "object") throw new GuardError("expression must be an object");
  if ("atom" in expr) {
    if (typeof expr.atom !== "string" || expr.atom.normalize("NFC") !== expr.atom) throw new GuardError("atom must be NFC text");
    return { t: "atom", atom: expr.atom };
  }
  if ("not" in expr) return negate(normalize(expr.not));
  if ("allOf" in expr) return junction("and", expr.allOf);
  if ("anyOf" in expr) return junction("or", expr.anyOf);
  throw new GuardError("unknown guard expression (expected atom/not/allOf/anyOf)");
}

function negate(g: NormGuard): NormGuard {
  if (g.t === "const") return { t: "const", v: !g.v };
  if (g.t === "not") return g.op; // double negation
  return { t: "not", op: g };
}

function junction(t: "and" | "or", raw: readonly GuardExpr[]): NormGuard {
  if (!Array.isArray(raw)) throw new GuardError(`${t === "and" ? "allOf" : "anyOf"} must be an array`);
  const zero = t === "and" ? false : true; // annihilator: false for AND, true for OR
  const identity = !zero;                    // identity: true for AND, false for OR
  const flat: NormGuard[] = [];
  for (const e of raw) {
    const g = normalize(e);
    if (g.t === "const") {
      if (g.v === zero) return { t: "const", v: zero }; // annihilator collapses the whole junction
      continue; // identity operand dropped
    }
    if (g.t === t) flat.push(...g.ops); // flatten same-op nesting
    else flat.push(g);
  }
  // dedup by content id, keep deterministic order
  const byKey = new Map<string, NormGuard>();
  for (const g of flat) byKey.set(guardKey(g), g);
  // complementary-literal collapse: if some x and ¬x are both present -> annihilator
  for (const g of byKey.values()) {
    if (byKey.has(guardKey(negate(g)))) return { t: "const", v: zero };
  }
  const ops = [...byKey.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map((e) => e[1]);
  if (ops.length === 0) return { t: "const", v: identity }; // empty AND=true, empty OR=false
  if (ops.length === 1) return ops[0]!;
  return t === "and" ? { t: "and", ops } : { t: "or", ops };
}

// ── Exact propositional decision procedures over the free atoms (bounded; fail-closed above the bound) ──

function evalUnder(g: NormGuard, assign: (atom: string) => boolean): boolean {
  switch (g.t) {
    case "const": return g.v;
    case "atom": return assign(g.atom);
    case "not": return !evalUnder(g.op, assign);
    case "and": return g.ops.every((o) => evalUnder(o, assign));
    case "or": return g.ops.some((o) => evalUnder(o, assign));
  }
}

/** Enumerate every assignment over `atoms`, calling `f(vector)`; returns early false if `f` returns false. */
function forEachAssignment(atoms: readonly string[], f: (assign: (atom: string) => boolean) => boolean): boolean {
  if (atoms.length > MAX_DECISION_ATOMS) throw new GuardUndecidable(atoms.length);
  const index = new Map(atoms.map((a, i) => [a, i] as const));
  const total = 1 << atoms.length;
  for (let mask = 0; mask < total; mask++) {
    const assign = (atom: string): boolean => {
      const i = index.get(atom);
      return i === undefined ? false : (mask & (1 << i)) !== 0;
    };
    if (!f(assign)) return false;
  }
  return true;
}

/** True iff some assignment makes the guard true. */
export function satisfiable(g: NormGuard): boolean {
  let sat = false;
  forEachAssignment(atomsOf(g), (a) => { if (evalUnder(g, a)) { sat = true; return false; } return true; });
  return sat;
}

/** True iff every assignment makes the guard true. */
export function tautology(g: NormGuard): boolean {
  return forEachAssignment(atomsOf(g), (a) => evalUnder(g, a));
}

/** True iff the guard is unsatisfiable (a rule with this guard can never fire — a structural contradiction). */
export function contradiction(g: NormGuard): boolean { return !satisfiable(g); }

/** True iff `a` implies `b` under every assignment (a ⊆ b as applicability regions). */
export function implies(a: NormGuard, b: NormGuard): boolean {
  const atoms = [...new Set([...atomsOf(a), ...atomsOf(b)])].sort();
  return forEachAssignment(atoms, (asg) => !evalUnder(a, asg) || evalUnder(b, asg));
}

/** True iff `a` and `b` are propositionally equivalent (same applicability region over the free atoms). */
export function equivalent(a: NormGuard, b: NormGuard): boolean {
  const atoms = [...new Set([...atomsOf(a), ...atomsOf(b)])].sort();
  return forEachAssignment(atoms, (asg) => evalUnder(a, asg) === evalUnder(b, asg));
}

/** True iff `a` and `b` can BOTH be true under some assignment (their applicability regions overlap). */
export function overlaps(a: NormGuard, b: NormGuard): boolean {
  const atoms = [...new Set([...atomsOf(a), ...atomsOf(b)])].sort();
  let ov = false;
  forEachAssignment(atoms, (asg) => { if (evalUnder(a, asg) && evalUnder(b, asg)) { ov = true; return false; } return true; });
  return ov;
}
