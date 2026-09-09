import { test } from "node:test";
import assert from "node:assert/strict";

import { trustReport, assuranceHeadline, type TrustEvidence } from "../src/audit/decision_audit.js";

const full: TrustEvidence = {
  deterministicPass: true, sealValid: true, attesterLive: true,
  signatureValid: true, signatureGuarantee: "keyed-integrity",
  witnessed: true, reconciled: true, reconcileScope: "single-external",
};
const partial: TrustEvidence = { deterministicPass: true, sealValid: true }; // caps at L2, attribution missing

test("ASSURANCE-SURFACE (a): the headline states the actual level and its capping gap", () => {
  const h = assuranceHeadline(trustReport(partial), "auto-proceed");
  assert.ok(h.startsWith("assurance L2-tamper-evident"), "the actual (not rounded-up) level leads the line");
  assert.ok(/attributed identity/.test(h), "the capping gap (the why) is named");
});

test("ASSURANCE-SURFACE (b): a held gate is shown as held, a proceed as proceed", () => {
  assert.ok(assuranceHeadline(trustReport(partial), "human-hold").includes("HELD for review"));
  assert.ok(assuranceHeadline(trustReport(full), "auto-proceed").includes("proceeding"));
  assert.ok(!assuranceHeadline(trustReport(full), "auto-proceed").includes("HELD"));
});

test("ASSURANCE-SURFACE (c): the headline never overstates — a low/partial level is not softened", () => {
  const h = assuranceHeadline(trustReport({ deterministicPass: true }), "auto-proceed"); // L1
  assert.ok(h.includes("L1-verified"), "the low level is stated plainly");
  assert.ok(!/(fully secure|trusted|all clear|looks good|✓ ok)/i.test(h), "no false reassurance for a partial level");
  // the cap is still present even while proceeding
  assert.ok(/tamper-evident seal/.test(h), "the next-rung gap is shown, not hidden by the proceed status");
});

test("ASSURANCE-SURFACE (d): presentation-only — rendering mutates nothing and is deterministic", () => {
  const report = trustReport(partial); // has a capping gap → a mutation of gaps is detectable
  const snapshot = JSON.stringify(report);
  const a = assuranceHeadline(report, "auto-proceed");
  const b = assuranceHeadline(report, "auto-proceed");
  assert.equal(JSON.stringify(report), snapshot, "the report is not mutated by rendering");
  assert.equal(a, b, "deterministic — same inputs → same line");
});

test("ASSURANCE-SURFACE (e): glanceable + honest — both the level AND the capping gap are present", () => {
  const h = assuranceHeadline(trustReport(partial), "human-hold");
  assert.ok(h.includes("L2-tamper-evident") && /attributed identity/.test(h), "level and gap both present");
  assert.ok(h.split("\n").length === 1, "one line — glanceable");
  assert.ok(h.length < 200, "concise, no jargon dump");
});

test("ASSURANCE-SURFACE (full-chain): a complete chain says 'full chain present', no fabricated gap", () => {
  const h = assuranceHeadline(trustReport(full), "auto-proceed");
  assert.ok(h.includes("L6-externally-anchored") && h.includes("full chain present"));
});

test("ASSURANCE-SURFACE (no-gate): without a gate route, only the assurance is shown (no false proceed)", () => {
  const h = assuranceHeadline(trustReport(full));
  assert.ok(!h.includes("proceeding") && !h.includes("HELD"), "no gate status invented when none supplied");
  assert.ok(h.includes("L6-externally-anchored"));
});
