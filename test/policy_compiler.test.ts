import { test } from "node:test";
import assert from "node:assert/strict";

import {
  compilePolicy, verifyBundle, CompileError, ALGORITHM, type SignedBundle, type CompilerSigner,
} from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import { principalId } from "../src/eir/eir.js";
import type { JsonValue } from "../src/policy/json.js";

// Mechanical-Enforcement Increment 2 — TOTAL POLICY COMPILER. Frontier property: every accepted policy => a COMPLETE,
// SIGNED, self-verifying bundle in which absence/ambiguity/error is DENY, or compilation FAILS. Proven by disproof —
// neutering a check in src/policy/compiler.ts reddens the matching test:
//   capability (unknown=>error)    => "unknown effectType is REJECTED"
//   reference closure               => "dangling reference is REJECTED"
//   cycle detection                 => "guard reference cycle is REJECTED"
//   shadow (permit under deny)      => "fully-shadowed permit is REJECTED"
//   conflict (equal-applic opposite)=> "identical applicability opposite decisions REJECTED"
//   deterministic sort/canonical    => "digest is invariant under source permutation"
//   sign self-verify                => "compiler self-verifies; tamper breaks verification"

const KEYID = "k1";
const SECRET = "s3cr3t";
const signer: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const trust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };

// A valid baseline policy (as a parsed JsonValue: numbers are bigint). effectType must resolve in the capability table.
function basePolicy(): JsonValue {
  return {
    version: 1n,
    combiningAlgorithm: ALGORITHM,
    principals: [{ name: "agent", labels: ["untrusted"] }, { name: "operator", labels: [] }],
    effects: [
      { id: "readFile", effectType: "fs.read", resourceSelector: "/data/*" },
      { id: "sendMail", effectType: "email.send", resourceSelector: "*" },
    ],
    guards: [
      { id: "inRoot", predicate: "path.within-root" },
      { id: "confirmed", predicate: "op.confirmed" },
      { id: "safeRead", allOf: ["inRoot"] },
    ],
    rules: [
      { id: "r-read", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "readFile", guard: "safeRead" },
      { id: "r-mail", decision: "deny", subjects: ["agent"], entryPoints: ["*"], effect: "sendMail" },
      { id: "r-mail-op", decision: "permit", subjects: ["operator"], entryPoints: ["cli"], effect: "sendMail", guard: "confirmed" },
    ],
  };
}

test("happy path: a valid policy compiles to a signed bundle that verifies", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  assert.equal(b.payload.algorithm, ALGORITHM);
  assert.equal(b.signatures.length, 1);
  assert.equal(verifyBundle(b, trust).valid, true);
  // every declared effect has exactly one decision root with an explicit default-deny leaf (coverage/totality).
  assert.equal(b.payload.decisionRoots.length, 2);
  for (const r of b.payload.decisionRoots) {
    assert.equal(r.fallback.decision, "deny");
    assert.equal(r.fallback.reason, "no-applicable-permit");
    assert.equal(r.algorithm, ALGORITHM);
  }
});

test("determinism: the payload digest is INVARIANT under semantically-irrelevant source permutation", () => {
  const a = compilePolicy(basePolicy(), [signer]);
  const permuted = basePolicy() as Record<string, JsonValue>;
  (permuted.principals as JsonValue[]).reverse();
  (permuted.effects as JsonValue[]).reverse();
  (permuted.guards as JsonValue[]).reverse();
  (permuted.rules as JsonValue[]).reverse();
  const b = compilePolicy(permuted, [signer]);
  assert.equal(a.payloadDigest, b.payloadDigest, "reordering declarations must not change the compiled identity");
});

test("semantic-change oracle: changing a decision, a guard, or an effect changes the digest", () => {
  const base = compilePolicy(basePolicy(), [signer]).payloadDigest;
  const flipDecision = basePolicy() as Record<string, JsonValue>;
  (flipDecision.rules as Record<string, JsonValue>[])[1]!.decision = "permit"; // deny -> permit
  assert.notEqual(compilePolicy(flipDecision, [signer]).payloadDigest, base);
  const changeGuard = basePolicy() as Record<string, JsonValue>;
  (changeGuard.guards as Record<string, JsonValue>[])[0]!.predicate = "path.within-DIFFERENT";
  assert.notEqual(compilePolicy(changeGuard, [signer]).payloadDigest, base);
});

test("capability: an unknown effectType is REJECTED (unknown => deny-by-default, not compilable)", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  (p.effects as Record<string, JsonValue>[])[0]!.effectType = "totally.unknown.capability";
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "capability");
});

test("schema: a policy may NOT declare an effect's consequence class (cls is derived)", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  (p.effects as Record<string, JsonValue>[])[0]!.cls = "recoverable";
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "schema");
});

test("reference closure: dangling effect / guard / principal references are REJECTED", () => {
  const noEffect = basePolicy() as Record<string, JsonValue>;
  (noEffect.rules as Record<string, JsonValue>[])[0]!.effect = "ghostEffect";
  assert.throws(() => compilePolicy(noEffect, [signer]), (e: unknown) => e instanceof CompileError && e.code === "reference");
  const noGuard = basePolicy() as Record<string, JsonValue>;
  (noGuard.rules as Record<string, JsonValue>[])[0]!.guard = "ghostGuard";
  assert.throws(() => compilePolicy(noGuard, [signer]), (e: unknown) => e instanceof CompileError && e.code === "reference");
  const noPrin = basePolicy() as Record<string, JsonValue>;
  (noPrin.rules as Record<string, JsonValue>[])[0]!.subjects = ["ghost"];
  assert.throws(() => compilePolicy(noPrin, [signer]), (e: unknown) => e instanceof CompileError && e.code === "reference");
});

test("cycle: a guard reference cycle is REJECTED with a deterministic witness", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  p.guards = [
    { id: "g1", allOf: ["g2"] },
    { id: "g2", allOf: ["g1"] },
  ];
  (p.rules as Record<string, JsonValue>[])[0]!.guard = "g1";
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "cycle");
});

test("shadow: a permit fully covered by a deny is REJECTED (it can never grant access)", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  // deny agent all sendMail (entry *), then a narrower permit for agent sendMail on cli -> shadowed.
  p.guards = [];
  (p.rules as JsonValue[]) = [
    { id: "d-all", decision: "deny", subjects: ["agent"], entryPoints: ["*"], effect: "sendMail" },
    { id: "p-narrow", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "sendMail" },
  ];
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "shadow");
});

test("shadow: a rule with an unsatisfiable guard is REJECTED (can never fire)", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  p.guards = [{ id: "never", allOf: ["a", "na"] }, { id: "a", predicate: "x" }, { id: "na", not: "a" }];
  (p.rules as JsonValue[]) = [{ id: "r-dead", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "readFile", guard: "never" }];
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "shadow");
});

test("conflict: identical applicability with opposite decisions is REJECTED (ambiguous)", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  p.guards = [{ id: "inRoot", predicate: "path.within-root" }];
  (p.rules as JsonValue[]) = [
    { id: "a-permit", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "readFile", guard: "inRoot" },
    { id: "b-deny", decision: "deny", subjects: ["agent"], entryPoints: ["cli"], effect: "readFile", guard: "inRoot" },
  ];
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "conflict");
});

test("redundancy: a same-decision rule fully subsumed by another is REJECTED", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  p.guards = [];
  (p.rules as JsonValue[]) = [
    { id: "wide", decision: "deny", subjects: ["*"], entryPoints: ["*"], effect: "sendMail" },
    { id: "narrow", decision: "deny", subjects: ["agent"], entryPoints: ["cli"], effect: "sendMail" },
  ];
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "redundant");
});

test("set-integrity: duplicate ids are REJECTED", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  (p.effects as JsonValue[]).push({ id: "readFile", effectType: "fs.read", resourceSelector: "/other" });
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "set-integrity");
});

test("version: a non-1 version is REJECTED", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  p.version = 2n;
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "version");
});

test("signing: tampering the payload breaks verification (digest is recomputed, never trusted)", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const tampered: SignedBundle = { ...b, payload: { ...b.payload, policyVersion: 999 } };
  assert.equal(verifyBundle(tampered, trust).valid, false);
  // an untrusted key never counts
  assert.equal(verifyBundle(b, { trustedKeys: new Map([["other", SECRET]]), threshold: 1 }).valid, false);
  // sub-threshold fails closed
  assert.equal(verifyBundle(b, { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 2 }).valid, false);
  // version skew fails closed
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, bundleVersion: 2 as 1 } }, trust).valid, false);
});

test("signing: an unsigned bundle is never emitted; threshold must be in range", () => {
  assert.throws(() => compilePolicy(basePolicy(), []), (e: unknown) => e instanceof CompileError && e.code === "signing");
  assert.throws(() => compilePolicy(basePolicy(), [signer], 2), (e: unknown) => e instanceof CompileError && e.code === "signing");
});

test("k-of-n: two signers with threshold 2 verifies; one signer falls short", () => {
  const s2: CompilerSigner = { signer: new StubSigner("second", "k2"), keyid: "k2", verifyKey: "second" };
  const b = compilePolicy(basePolicy(), [signer, s2], 2);
  assert.equal(b.signatures.length, 2);
  assert.equal(verifyBundle(b, { trustedKeys: new Map([[KEYID, SECRET], ["k2", "second"]]), threshold: 2 }).valid, true);
  assert.equal(verifyBundle(b, { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 2 }).valid, false);
});

test("silent-permit defense: two effects with IDENTICAL identity (same type+selector) are REJECTED", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  // different source ids, identical effectType+resourceSelector -> same EIR effect id -> one root would drop the other.
  (p.effects as JsonValue[]).push({ id: "readFileAlias", effectType: "fs.read", resourceSelector: "/data/*" });
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "set-integrity");
});

test("injectivity: \"*\" may not be combined with specific members in subjects/entryPoints", () => {
  const s = basePolicy() as Record<string, JsonValue>;
  (s.rules as Record<string, JsonValue>[])[1]!.subjects = ["*", "agent"];
  assert.throws(() => compilePolicy(s, [signer]), (e: unknown) => e instanceof CompileError && e.code === "schema");
});

test("dead-guard closure: a declared but unreferenced guard is REJECTED", () => {
  const p = basePolicy() as Record<string, JsonValue>;
  (p.guards as JsonValue[]).push({ id: "orphan", predicate: "never.used" });
  assert.throws(() => compilePolicy(p, [signer]), (e: unknown) => e instanceof CompileError && e.code === "dead-guard");
});

test("guard-table closure: every rule.guardId (incl. TRUE for unguarded rules) is present in the bundle", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const ids = new Set(b.payload.guards.map((g) => g.id));
  for (const r of b.payload.rules) assert.ok(ids.has(r.guardId), `rule ${r.id} guardId missing from table`);
});

test("threshold-bypass defense: verifyBundle rejects a non-positive / non-integer threshold", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  assert.equal(verifyBundle(b, { trustedKeys: new Map(), threshold: 0 }).valid, false);
  assert.equal(verifyBundle(b, { trustedKeys: new Map(), threshold: -1 }).valid, false);
  assert.equal(verifyBundle(b, { trustedKeys: new Map(), threshold: Number.NaN }).valid, false);
});

test("semantic injectivity: renaming guards/rules (same decision function) keeps the SAME semanticDigest", () => {
  const a: JsonValue = {
    version: 1n, combiningAlgorithm: ALGORITHM,
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "e", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [{ id: "g1", predicate: "p" }],
    rules: [{ id: "r1", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "e", guard: "g1" }],
  };
  const b: JsonValue = {
    version: 1n, combiningAlgorithm: ALGORITHM,
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "effect-renamed", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [{ id: "guard-renamed", predicate: "p" }],
    rules: [{ id: "rule-renamed", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "effect-renamed", guard: "guard-renamed" }],
  };
  const ba = compilePolicy(a, [signer]); const bb = compilePolicy(b, [signer]);
  assert.equal(ba.payload.semanticDigest, bb.payload.semanticDigest, "author names are not semantic — same decision function => same semanticDigest");
  assert.notEqual(ba.payloadDigest, bb.payloadDigest, "the provenance (author ids/source map) still differs, so the artifact digest differs");
});

test("semantic injectivity: a real decision change DOES move the semanticDigest", () => {
  const base = compilePolicy(basePolicy(), [signer]).payload.semanticDigest;
  const flip = basePolicy() as Record<string, JsonValue>;
  (flip.rules as Record<string, JsonValue>[])[1]!.decision = "permit";
  assert.notEqual(compilePolicy(flip, [signer]).payload.semanticDigest, base);
});

test("structural revalidation: an extra (unsigned) payload field is REJECTED by verifyBundle", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const extended = { ...b, payload: { ...b.payload, backdoor: true } as unknown as typeof b.payload };
  // the extra field is ignored by the canonical digest (so the signature still matches) — structural closure catches it.
  const v = verifyBundle(extended, trust);
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /structural/);
});

test("structural revalidation: a decision root referencing a non-existent rule is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const roots = b.payload.decisionRoots.map((r) => ({ ...r }));
  const target = roots.find((r) => r.denies.length > 0)!;
  const tampered = { ...b, payload: { ...b.payload, decisionRoots: roots.map((r) => r === target ? { ...r, denies: [{ ...r.denies[0]!, ruleId: "ghost-rule" }] } : r) } };
  assert.equal(verifyBundle(tampered, trust).valid, false);
});

test("verify integrity: a falsely content-addressed effect (mutated type, stale id) is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const effs = b.payload.effects.map((e, i) => i === 0 ? { ...e, effectType: "email.send" } : e); // id no longer matches content
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, effects: effs } }, trust).valid, false);
});

test("verify integrity: a deny rule placed in a root's permits list is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  // find the sendMail root (has a deny) and move that deny ref into permits
  const roots = b.payload.decisionRoots.map((r) => {
    if (r.denies.length > 0) return { ...r, permits: [...r.permits, ...r.denies], denies: [] };
    return r;
  });
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, decisionRoots: roots } }, trust).valid, false);
});

test("verify integrity: an extra field on a nested effect object is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const effs = b.payload.effects.map((e, i) => i === 0 ? ({ ...e, sneaky: 1 } as unknown as typeof e) : e);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, effects: effs } }, trust).valid, false);
});

test("verify integrity: a re-ordered (non-canonical) payload list is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, effects: [...b.payload.effects].reverse() } }, trust).valid, false);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, principals: [...b.payload.principals].reverse() } }, trust).valid, false);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, sourceMap: [...b.payload.sourceMap].reverse() } }, trust).valid, false);
});

test("verify integrity: a stripped checks manifest or fabricated source-map is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, checks: [] } }, trust).valid, false);
  const sm = [...b.payload.sourceMap, { id: "0".repeat(64), kind: "effect", sourceId: "phantom" }];
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, sourceMap: sm } }, trust).valid, false);
  const dropped = b.payload.sourceMap.filter((e) => e.kind !== "rule"); // drop rule provenance -> incomplete
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, sourceMap: dropped } }, trust).valid, false);
  // a SECOND provenance entry for the same effect (1:1 kinds) is fabricated -> rejected
  const eff = b.payload.sourceMap.find((e) => e.kind === "effect")!;
  const dupProv = [...b.payload.sourceMap, { ...eff, sourceId: `${eff.sourceId}-alias` }]
    .sort((a, x) => (a.kind < x.kind ? -1 : a.kind > x.kind ? 1 : a.sourceId < x.sourceId ? -1 : a.sourceId > x.sourceId ? 1 : 0));
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, sourceMap: dupProv } }, trust).valid, false);
});

test("verify integrity: a rule referencing an undeclared principal is REJECTED at load", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const target = b.payload.rules[0]!;
  const rules = b.payload.rules.map((r) => r.id === target.id ? { ...r, subjects: ["undeclared-x"] } : r);
  // keep the decision-root refs consistent so the applicability check (not root-faithfulness) is what rejects it
  const roots = b.payload.decisionRoots.map((root) => ({
    ...root,
    denies: root.denies.map((ref) => ref.ruleId === target.id ? { ...ref, subjects: ["undeclared-x"] } : ref),
    permits: root.permits.map((ref) => ref.ruleId === target.id ? { ...ref, subjects: ["undeclared-x"] } : ref),
  }));
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, rules, decisionRoots: roots } }, trust).valid, false);
});

test("verify integrity: a guard with a misleading atoms field is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const gs = b.payload.guards.map((g, i) => i === 0 ? { ...g, atoms: [...g.atoms, "phantom.atom"] } : g);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, guards: gs } }, trust).valid, false);
  // a non-array atoms value (string masquerading as ["a","b"]) must not slip past array-equality
  const gs2 = b.payload.guards.map((g, i) => i === 0 ? ({ ...g, atoms: g.atoms.join("") as unknown as string[] }) : g);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, guards: gs2 } }, trust).valid, false);
});

test("verify robustness: malformed bundles/trust policies fail closed (no exception)", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  assert.equal(verifyBundle(null as unknown as typeof b, trust).valid, false);
  assert.equal(verifyBundle({ ...b, signatures: null as unknown as typeof b.signatures }, trust).valid, false);
  assert.equal(verifyBundle({ ...b, signatures: [null as unknown as typeof b.signatures[0]] }, trust).valid, false);
  assert.equal(verifyBundle({ ...b, extra: 1 } as unknown as typeof b, trust).valid, false); // extra wrapper field
  assert.equal(verifyBundle(b, { trustedKeys: null as unknown as Map<string, string>, threshold: 1 }).valid, false);
  // two signers, deliberately given in non-canonical (unsorted) signature order
  const s2: CompilerSigner = { signer: new StubSigner("second", "k2"), keyid: "k2", verifyKey: "second" };
  const bb = compilePolicy(basePolicy(), [signer, s2], 2);
  const unsorted = { ...bb, signatures: [...bb.signatures].reverse() };
  const trust2: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET], ["k2", "second"]]), threshold: 2 };
  assert.equal(verifyBundle(unsorted, trust2).valid, false);
});

test("verify integrity: two principals with the same NAME (distinct ids) are REJECTED (ambiguous resolution)", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const dup = { id: principalId({ kind: "principal", name: "agent", labels: ["z"] }), name: "agent", labels: ["z"] };
  const prins = [...b.payload.principals, dup];
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, principals: prins } }, trust).valid, false);
});

test("verify integrity: a forged principal content id is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const prins = b.payload.principals.map((x, i) => i === 0 ? { ...x, name: "IMPOSTER" } : x); // id no longer matches name
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, principals: prins } }, trust).valid, false);
});

test("verify integrity: a decision root whose cls contradicts its effect is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const roots = b.payload.decisionRoots.map((r, i) => i === 0 ? { ...r, cls: (r.cls === "destructive" ? "recoverable" : "destructive") as typeof r.cls } : r);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, decisionRoots: roots } }, trust).valid, false);
});

test("verify integrity: an extra field on a principal or source-map entry is REJECTED", () => {
  const b = compilePolicy(basePolicy(), [signer]);
  const prins = b.payload.principals.map((x, i) => i === 0 ? ({ ...x, sneaky: 1 } as unknown as typeof x) : x);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, principals: prins } }, trust).valid, false);
  const sm = b.payload.sourceMap.map((x, i) => i === 0 ? ({ ...x, sneaky: 1 } as unknown as typeof x) : x);
  assert.equal(verifyBundle({ ...b, payload: { ...b.payload, sourceMap: sm } }, trust).valid, false);
});

test("strict frontend: a raw string policy with a duplicate key is REJECTED before compilation", () => {
  const src = '{"version":1,"version":1,"combiningAlgorithm":"deny-overrides","principals":[],"effects":[],"guards":[],"rules":[]}';
  assert.throws(() => compilePolicy(src, [signer]), /duplicate object key/);
});
