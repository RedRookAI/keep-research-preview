import { test } from "node:test";
import assert from "node:assert/strict";

import {
  trusted,
  tainted,
  mapL,
  combine,
  declassify,
  toProvenance,
  StubInterceptor,
} from "../src/provenance/taint_tracer.js";
import { effectProvenance } from "../src/provenance/effect_provenance.js";
import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";

// R32 — taint-tracer propagation conformance. Proves the ENVELOPE-SIDE labeling/propagation that
// feeds effectProvenance; the real cross-process interception is the SEAM. Verify by disproof.

test("R32: seeding — tainted at a boundary is untrusted; internal is trusted", () => {
  assert.equal(tainted("page", "web_fetch").taint, "untrusted");
  assert.equal(trusted("code").taint, "trusted");
});

test("R32: mapL PRESERVES taint through a transform (isolated propagation property)", () => {
  const t = tainted("<script>", "web_fetch");
  const derived = mapL(t, (s) => s.toUpperCase() + "!"); // an arbitrary transform
  assert.equal(derived.taint, "untrusted", "a transform of tainted data stays tainted");
});

test("R32: combine is CONSERVATIVE — [trusted, tainted] joins to tainted (any untrusted taints)", () => {
  const a = trusted("internal");
  const b = tainted("external", "issue:external");
  // order [trusted, tainted]: a naive 'take first input's taint' bug would wrongly yield trusted.
  const joined = combine([a, b], "merged");
  assert.equal(joined.taint, "untrusted", "any untrusted input taints the whole");
});

test("R32: the agent CANNOT self-declassify — an unauthorized declassify is ignored", () => {
  const t = tainted("payload", "tool");
  const stillTainted = declassify(t, { by: "agent", authorized: false, reason: "trust me" });
  assert.equal(stillTainted.taint, "untrusted");
});

test("R32: an AUTHORIZED declassify (a trusted step) clears taint", () => {
  const t = tainted("payload", "tool");
  const cleared = declassify(t, { by: "operator", authorized: true, reason: "reviewed" });
  assert.equal(cleared.taint, "trusted");
});

test("R32: toProvenance feeds effectProvenance → a tainted input yields untrusted-derived → gate veto", () => {
  const inputs = [trusted("repo"), tainted("fetched", "web_fetch")];
  const prov = effectProvenance({ inputs: toProvenance(inputs) });
  assert.equal(prov.verdict, "untrusted-derived");
  const green: GateInputs = { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true };
  const r = composeGate({ ...green, provenance: prov.verdict }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("untrusted-derived-provenance"));
});

test("R32: an all-trusted derivation stays trusted end-to-end (no false gate)", () => {
  const inputs = [trusted("repo"), trusted("operator")];
  assert.equal(effectProvenance({ inputs: toProvenance(inputs) }).verdict, "trusted");
});

test("R32: the stub interceptor labels boundary sources untrusted, internal trusted", () => {
  const i = new StubInterceptor();
  assert.equal(i.label("web_fetch", "x").taint, "untrusted");
  assert.equal(i.label("tool", "x").taint, "untrusted");
  assert.equal(i.label("internal", "x").taint, "trusted");
});
