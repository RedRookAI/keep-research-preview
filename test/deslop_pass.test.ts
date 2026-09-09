import { test } from "node:test";
import assert from "node:assert/strict";

import { deslopPass, referenceDeslopTransform, SURROGATE_TOKEN, type DeslopTransform } from "../src/privacy/deslop.js";

test("DESLOP-PASS (a): filler/hedge prose is removed by the reference transform", () => {
  const r = deslopPass({ text: "It's worth noting that the cache is fast.", transform: referenceDeslopTransform });
  assert.equal(r.outcome, "cleaned");
  assert.equal(r.output, "the cache is fast.");
  assert.ok(!/worth noting/i.test(r.output), "filler removed");
});

test("DESLOP-PASS (b): a number is a protected span — a transform that alters it is caught (byte-identical or reject)", () => {
  const mangleNumber: DeslopTransform = { transform: (t) => t.replace(/42/g, "99") };
  const r = deslopPass({ text: "The limit is 42 requests.", transform: mangleNumber });
  assert.equal(r.outcome, "rejected-protected-span-changed", "a changed number is caught");
  assert.equal(r.output, "The limit is 42 requests.", "original returned — the number is byte-preserved");
  // and a legitimate prose pass leaves the number byte-identical
  const clean = deslopPass({ text: "It's worth noting that the limit is 42.", transform: referenceDeslopTransform });
  assert.equal(clean.outcome, "cleaned");
  assert.ok(clean.output.includes("42"), "the number survives a legitimate cleanup");
});

test("DESLOP-PASS (c): a redaction surrogate token is never altered (survives to re-hydration)", () => {
  // mangle the CATEGORY LETTERS (not the embedded digit, which the number-pattern would also catch) so ONLY the
  // surrogate pattern can protect it — isolating surrogate protection.
  const mangleSurrogate: DeslopTransform = { transform: (t) => t.replace(/EMAIL/g, "PHONE") };
  const r = deslopPass({ text: "It's worth noting that \u27E6EMAIL#1\u27E7 was seen.", transform: mangleSurrogate, surrogatePattern: SURROGATE_TOKEN });
  assert.equal(r.outcome, "rejected-protected-span-changed", "a changed surrogate is caught");
  assert.ok(r.output.includes("\u27E6EMAIL#1\u27E7"), "the surrogate is byte-preserved for re-hydration");
  // a legitimate cleanup leaves the surrogate intact
  const clean = deslopPass({ text: "It's worth noting that \u27E6EMAIL#1\u27E7 was seen.", transform: referenceDeslopTransform, surrogatePattern: SURROGATE_TOKEN });
  assert.equal(clean.outcome, "cleaned");
  assert.ok(clean.output.includes("\u27E6EMAIL#1\u27E7"));
});

test("DESLOP-PASS (d): if a protected span changed, the pass is rejected and the original returned (fail-safe)", () => {
  const mangleCode: DeslopTransform = { transform: (t) => t.replace(/foo/g, "bar") };
  const text = "Needless to say, run ```foo()``` now.";
  const r = deslopPass({ text, transform: mangleCode });
  assert.equal(r.outcome, "rejected-protected-span-changed");
  assert.equal(r.output, text, "the ORIGINAL is returned untouched — never a corrupted output");
  assert.equal(r.protectedSpansPreserved, false);
});

test("DESLOP-PASS (e): transform-plus-verify + deterministic (changes no verdict; same input → same output)", () => {
  const input = { text: "It's worth noting that x.", transform: referenceDeslopTransform };
  const a = deslopPass(input);
  const b = deslopPass(input);
  assert.equal(a.changesVerdict, false, "changes no verdict");
  assert.deepEqual(a, b, "deterministic");
});

test("DESLOP-PASS (both-tracks): a no-op transform is honest; a mixed prose+code payload cleans prose only", () => {
  const noop = deslopPass({ text: "plain text", transform: { transform: (t) => t } });
  assert.equal(noop.outcome, "no-op");
  const mixed = deslopPass({ text: 'When it comes to config, set `mode="fast"` and limit 5.', transform: referenceDeslopTransform });
  assert.equal(mixed.outcome, "cleaned");
  assert.ok(mixed.output.includes('`mode="fast"`') && mixed.output.includes("5"), "code + number preserved; only prose cleaned");
});
