import { test } from "node:test";
import assert from "node:assert/strict";

import { effectProvenance, type EffectProvenance } from "../src/provenance/effect_provenance.js";
import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";

// Finding 2.6 — effect provenance-gating. These prove an effect derived from untrusted content is
// untrusted-derived (deny-capable), taint propagates conservatively, and the agent cannot
// self-declassify. Verify by disproof.

test("PROV: an all-trusted-origin effect is trusted", () => {
  const p: EffectProvenance = { inputs: [{ source: "repo", trust: "trusted" }, { source: "operator", trust: "trusted" }] };
  assert.equal(effectProvenance(p).verdict, "trusted");
});

test("PROV: ANY untrusted input taints the whole effect (conservative least-trusted propagation)", () => {
  const p: EffectProvenance = { inputs: [{ source: "repo", trust: "trusted" }, { source: "tool:web_fetch", trust: "untrusted" }] };
  const r = effectProvenance(p);
  assert.equal(r.verdict, "untrusted-derived");
  assert.ok(r.reasons.some((x) => x.includes("tool:web_fetch")));
});

test("PROV: an UNKNOWN input trust fails safe → untrusted-derived", () => {
  const p: EffectProvenance = { inputs: [{ source: "issue:external" }] }; // no trust label
  assert.equal(effectProvenance(p).verdict, "untrusted-derived");
});

test("PROV: NO declared provenance fails safe → untrusted-derived (declare at the border)", () => {
  const p: EffectProvenance = { inputs: [] };
  const r = effectProvenance(p);
  assert.equal(r.verdict, "untrusted-derived");
  assert.ok(r.reasons.includes("no-provenance-declared"));
});

test("PROV: the agent CANNOT self-declassify — an unauthorized declassification is ignored", () => {
  const p: EffectProvenance = {
    inputs: [{ source: "tool:web_fetch", trust: "untrusted" }],
    declassification: { by: "agent", reason: "trust me", authorized: false }, // agent's own claim
  };
  const r = effectProvenance(p);
  assert.equal(r.verdict, "untrusted-derived", "an unauthorized declassification does not clear taint");
  assert.ok(r.reasons.some((x) => x.includes("unauthorized-declassification-ignored")));
});

test("PROV: an AUTHORIZED declassification (a trusted step's capability) clears taint", () => {
  const p: EffectProvenance = {
    inputs: [{ source: "tool:web_fetch", trust: "untrusted" }],
    declassification: { by: "operator", reason: "reviewed + endorsed", authorized: true },
  };
  assert.equal(effectProvenance(p).verdict, "trusted");
});

test("PROV: is pure — deterministic on frozen input", () => {
  const p = Object.freeze({ inputs: [{ source: "repo", trust: "trusted" as const }] });
  assert.deepEqual(effectProvenance(p), effectProvenance(p));
});

// ── the gate veto: an untrusted-derived provenance forces human-hold ──
const green: GateInputs = { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true };

test("PROV+GATE: an untrusted-derived provenance vetoes an otherwise-green op → human-hold", () => {
  const r = composeGate({ ...green, provenance: "untrusted-derived" }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("untrusted-derived-provenance"));
});

test("PROV+GATE: a trusted provenance does not veto (op still auto-proceeds)", () => {
  const r = composeGate({ ...green, provenance: "trusted" }, defaultGatePolicy());
  assert.equal(r.route, "auto-proceed");
});
