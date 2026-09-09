import { test } from "node:test";
import assert from "node:assert/strict";

import { trustReport, type TrustEvidence } from "../src/audit/decision_audit.js";

const full: TrustEvidence = {
  deterministicPass: true, sealValid: true, attesterLive: true,
  signatureValid: true, signatureGuarantee: "keyed-integrity",
  witnessed: true, reconciled: true, reconcileScope: "single-external",
};

test("TRUST-REPORT (a): a full, verified chain reports the top level with no capping gaps", () => {
  const r = trustReport(full);
  assert.equal(r.level, "L6-externally-anchored");
  assert.equal(r.levelIndex, 6);
  assert.deepEqual(r.gaps, [], "no missing-layer gaps in a complete chain");
  // horizons remain (honest): keyed-integrity + single-external + hardware/public-log
  assert.ok(r.seams.some((s) => /non-repudiation/.test(s)) && r.seams.some((s) => /M-of-N/.test(s)));
});

test("TRUST-REPORT (b): the level is bounded by the WEAKEST present layer (a missing middle layer caps it)", () => {
  // deterministic + seal present, but attestation MISSING, even though signature/witness/reconcile are 'present'
  const r = trustReport({ ...full, attesterLive: false });
  assert.equal(r.level, "L2-tamper-evident", "the gap at attribution caps assurance — later layers don't lift it");
  assert.equal(r.levelIndex, 2);
  assert.ok(r.gaps.some((g) => /attributed identity/.test(g)), "the capping gap is named");
});

test("TRUST-REPORT (c): a not-present layer lowers the ceiling and is listed, never fabricated as satisfied", () => {
  const r = trustReport({ deterministicPass: true, sealValid: true, attesterLive: true }); // no signature/witness/reconcile
  assert.equal(r.level, "L3-attributed");
  assert.equal(r.layers.find((l) => l.name === "verified signature")!.present, false, "absent layer not fabricated present");
  assert.ok(r.gaps.some((g) => /no verified signature/.test(g)), "the absent layer is listed as the cap");
});

test("TRUST-REPORT (d): the report never overclaims — keyed-integrity is not reported as non-repudiation", () => {
  const r = trustReport(full); // signatureGuarantee keyed-integrity
  // the achieved level is 'signed' (L4+), but non-repudiation is a SEAM, not a claimed guarantee
  assert.ok(r.seams.some((s) => /keyed-integrity/.test(s) && /non-repudiation/.test(s)), "keyed-integrity honestly flagged, non-repudiation named as the upgrade");
  assert.ok(!r.summary.includes("non-repudiation"), "the summary does not claim non-repudiation");
});

test("TRUST-REPORT (e): report-only + deterministic (same evidence → same report; input unmutated)", () => {
  const input: TrustEvidence = { ...full };
  const before = JSON.stringify(input);
  const a = trustReport(input);
  const b = trustReport(input);
  assert.equal(JSON.stringify(input), before, "input not mutated (report-only)");
  assert.deepEqual(a, b, "deterministic");
  assert.deepEqual(JSON.parse(JSON.stringify(a)), a, "JSON round-trips");
});

test("TRUST-REPORT (both-tracks): an n=1 deterministic-only fix reports L1 honestly", () => {
  const r = trustReport({ deterministicPass: true });
  assert.equal(r.level, "L1-verified");
  assert.ok(r.gaps.some((g) => /tamper-evident seal/.test(g)), "the next rung is named as the cap");
});

test("TRUST-REPORT (L0): an unverified fix is L0, never assumed", () => {
  assert.equal(trustReport({}).level, "L0-unverified");
  assert.equal(trustReport({ deterministicPass: false }).level, "L0-unverified");
});
