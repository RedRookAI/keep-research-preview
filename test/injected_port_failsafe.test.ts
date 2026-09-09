import { test } from "node:test";
import assert from "node:assert/strict";

import { preReturnDeliberation } from "../src/routing/uncertainty_router.js";
import { deslopPass } from "../src/privacy/deslop.js";

const throwingCritic = { score: () => { throw new Error("evil critic"); } };
const throwingTransform = { transform: () => { throw new Error("evil transform"); } };

test("INJECTED-PORT-FAILSAFE (a): a throwing deliberation critic → the original is returned, not a crash", () => {
  const r = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "irreversible", critic: throwingCritic });
  assert.equal(r.returned, "orig", "failed safe to the original");
  assert.equal(r.outcome, "critic-error", "the error is surfaced honestly");
});

test("INJECTED-PORT-FAILSAFE (b): a throwing deslop transform → the original is returned", () => {
  const r = deslopPass({ text: "the report is 42.", transform: throwingTransform });
  assert.equal(r.output, "the report is 42.", "failed safe to the original, byte-identical");
  assert.equal(r.outcome, "transform-error");
});

test("INJECTED-PORT-FAILSAFE (c): the error outcome is honest and changes no verdict", () => {
  const d = preReturnDeliberation({ original: "o", revision: "r", consequence: "irreversible", critic: throwingCritic });
  assert.equal(d.changesVerdict, false, "still report-plus-choose, no verdict change");
  const s = deslopPass({ text: "x", transform: throwingTransform });
  assert.equal(s.changesVerdict, false, "still transform-plus-verify, no verdict change");
  assert.equal(s.protectedSpansPreserved, true, "nothing was altered, so protected spans trivially preserved");
});

test("INJECTED-PORT-FAILSAFE (d): a WELL-BEHAVED port still works exactly as before (catch doesn't swallow real results)", () => {
  // deliberation: a clearly-better revision still replaces
  const good = preReturnDeliberation({ original: "o", revision: "r", consequence: "irreversible", critic: { score: (c) => (c === "r" ? 9 : 1) } });
  assert.equal(good.outcome, "replaced-with-revision", "a real improvement is not swallowed by the catch");
  assert.equal(good.returned, "r");
  // deslop: a real prose cleanup still cleans
  const clean = deslopPass({ text: "It's worth noting that x.", transform: { transform: (t) => t.replace(/It's worth noting that /, "") } });
  assert.equal(clean.outcome, "cleaned");
  assert.equal(clean.output, "x.");
});

test("INJECTED-PORT-FAILSAFE (e): deterministic — same throwing port → same fail-safe outcome", () => {
  const a = preReturnDeliberation({ original: "o", revision: "r", consequence: "irreversible", critic: throwingCritic });
  const b = preReturnDeliberation({ original: "o", revision: "r", consequence: "irreversible", critic: throwingCritic });
  assert.deepEqual(a, b);
  const c = deslopPass({ text: "z", transform: throwingTransform });
  const d = deslopPass({ text: "z", transform: throwingTransform });
  assert.deepEqual(c, d);
});
