import { test } from "node:test";
import assert from "node:assert/strict";

import {
  normalize, guardKey, atomsOf, satisfiable, tautology, contradiction, implies, equivalent, overlaps,
  MAX_DECISION_ATOMS, GuardUndecidable, TRUE, FALSE, type GuardExpr, type NormGuard,
} from "../src/policy/guard_dag.js";

// Increment 2 (step B) — GUARD-DAG normalization + propositional decision procedures over OPAQUE atoms. Frontier
// property: a deterministic canonical form (equivalent guards share one id) + EXACT, bounded, fail-closed sat/impl.
// Proven by disproof — neutering an identity in normalize() or a procedure reddens the matching test:
//   dedup/sort in junction()        => "order + duplication do not change identity"
//   complementary-literal collapse  => "x AND not x normalizes to FALSE"
//   double-negation in negate()     => "not not x == x"
//   the MAX_DECISION_ATOMS bound     => "over-bound guard is undecidable (fail closed)"

const A: GuardExpr = { atom: "a" };
const B: GuardExpr = { atom: "b" };
const notA: GuardExpr = { not: { atom: "a" } };

test("determinism: operand order + duplication do not change a guard's identity", () => {
  const g1 = normalize({ allOf: [A, B, A] });
  const g2 = normalize({ allOf: [B, A] });
  assert.equal(guardKey(g1), guardKey(g2), "dedup + sort make identity order/multiplicity independent");
});

test("normalization is idempotent (content id stable under re-normalization of the source shapes)", () => {
  const once = normalize({ anyOf: [{ allOf: [A, B] }, A] });
  // flatten/absorb is not required, but re-expressing the same tree must give the same id
  const again = normalize({ anyOf: [A, { allOf: [B, A] }] });
  assert.equal(guardKey(once), guardKey(again));
});

test("x AND not x normalizes to FALSE (structural contradiction); x OR not x to TRUE", () => {
  assert.equal(guardKey(normalize({ allOf: [A, notA] })), guardKey(FALSE));
  assert.equal(guardKey(normalize({ anyOf: [A, notA] })), guardKey(TRUE));
  assert.ok(contradiction(normalize({ allOf: [A, notA] })));
  assert.ok(tautology(normalize({ anyOf: [A, notA] })));
});

test("double negation: not(not a) == a", () => {
  assert.equal(guardKey(normalize({ not: notA })), guardKey(normalize(A)));
});

test("constant folding: empty allOf=TRUE, empty anyOf=FALSE, single-operand collapses", () => {
  assert.equal(guardKey(normalize({ allOf: [] })), guardKey(TRUE));
  assert.equal(guardKey(normalize({ anyOf: [] })), guardKey(FALSE));
  assert.equal(guardKey(normalize({ allOf: [A] })), guardKey(normalize(A)));
});

test("satisfiability / tautology are EXACT over the free atoms", () => {
  assert.ok(satisfiable(normalize(A)));
  assert.ok(!satisfiable(normalize({ allOf: [A, notA] })));
  assert.ok(tautology(normalize({ anyOf: [A, notA] })));
  assert.ok(!tautology(normalize(A)));
});

test("implication + equivalence: (a AND b) implies a; not equivalent to a", () => {
  const aAndB = normalize({ allOf: [A, B] });
  const a = normalize(A);
  assert.ok(implies(aAndB, a), "a∧b ⊆ a");
  assert.ok(!implies(a, aAndB), "a ⊄ a∧b");
  assert.ok(!equivalent(a, aAndB));
  assert.ok(equivalent(normalize({ anyOf: [A, B] }), normalize({ anyOf: [B, A] })), "or is commutative");
});

test("overlap: a and b overlap; a and not a do not", () => {
  assert.ok(overlaps(normalize(A), normalize(B)));
  assert.ok(!overlaps(normalize(A), normalize(notA)));
});

test("fail-closed: a guard exceeding the decision bound is UNDECIDABLE (throws, never assumed sat)", () => {
  const many: GuardExpr = { allOf: Array.from({ length: MAX_DECISION_ATOMS + 1 }, (_, i) => ({ atom: `x${i}` })) };
  const g = normalize(many) as NormGuard;
  assert.equal(atomsOf(g).length, MAX_DECISION_ATOMS + 1);
  assert.throws(() => satisfiable(g), (e: unknown) => e instanceof GuardUndecidable);
});

test("atom must be NFC text (fail-closed on ambiguous identity)", () => {
  const nfd = "é"; // é as NFD
  assert.throws(() => normalize({ atom: nfd }), /NFC/);
});
