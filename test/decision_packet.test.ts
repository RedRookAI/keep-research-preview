import { test } from "node:test";
import assert from "node:assert/strict";
import { assembleDecisionPacket, renderPacket, type AssembleInputs } from "../src/cli/decision_packet.js";
import type { PrManifest } from "../src/git/pull_request.js";
import type { DecisionBrief } from "../src/pipeline/decision_brief.js";
import type { ForecastVerdict } from "../src/pipeline/consequence_forecast.js";

function manifest(over: Partial<PrManifest> = {}): PrManifest {
  return {
    id: "KEEP-1", title: "Fix", body: "…", branch: "keep/solve/KEEP-1", baseBranch: "main",
    diff: "--- a/x.ts\n+++ b/x.ts\n@@\n-a\n+b\n-c\n+d", intent: "fix the thing",
    executed: ["edited x.ts"], checks: [{ name: "unit tests", passed: true } as PrManifest["checks"][number]],
    attribution: "keep-run-1", humanApprovalRequired: true,
    oversight: { band: "low", disposition: "human-approval-required", mode: "notify-async", requiresImmediateAttention: false, reasons: ["reversible change"] },
    ...over,
  };
}
const brief = (over: Partial<DecisionBrief> = {}): DecisionBrief => ({
  whatChanges: "changes the tax calc", facts: [{ label: "files touched", value: "x.ts" }], verifyThis: "Does x.ts still handle zero-total carts?",
  routedBecause: ["touches billing logic"], reversible: true, ...over,
});
function forecast(over: Partial<ForecastVerdict> = {}): ForecastVerdict {
  return { decision: "pass", risks: [], reachedSinks: [], maxOrder: 1, reason: "ok", ...over };
}

// ─── minimum fields + evidence-first ───

test("the packet carries the Edilec-minimum fields and leads with executed evidence", () => {
  const p = assembleDecisionPacket({ manifest: manifest() });
  assert.equal(p.intent, "fix the thing");
  assert.ok(p.diff.length > 0);
  assert.deepEqual(p.executed, ["edited x.ts"]);
  assert.ok(p.evidence.some((e) => e.label === "unit tests" && e.value === "passed"));
  assert.equal(p.band, "low");
  const rendered = renderPacket(p);
  assert.match(rendered, /you're confirming, not catching/); // evidence-first framing, non-persuasive
});

// ─── reversibility + blast-radius from the forecast ───

test("no reached sinks → reversible/bounded; the diff is hidden behind a --full hint (compact depth)", () => {
  const p = assembleDecisionPacket({ manifest: manifest(), forecast: forecast() });
  assert.equal(p.reversible, true);
  assert.equal(p.depth, "compact");
  const r = renderPacket(p);
  assert.match(r, /reversible/);
  assert.doesNotMatch(r, /\+d/); // the diff body is NOT shown in compact
  assert.match(r, /--full/); // but the hint to see it is
});

test("a reached sink → NOT reversible, names the sink, and forces full depth (richer evidence)", () => {
  const f = forecast({ decision: "escalate", reachedSinks: [{ sink: "data-exfiltration", via: [], reason: "writes to network" }], maxOrder: 2 });
  const p = assembleDecisionPacket({ manifest: manifest({ oversight: { band: "high", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: true, reasons: ["reaches network"] } }), forecast: f });
  assert.equal(p.reversible, false);
  assert.equal(p.depth, "full");
  assert.match(p.blastRadius, /data-exfiltration/);
  const r = renderPacket(p);
  assert.match(r, /NOT fully reversible/);
  assert.match(r, /\+d/); // full depth shows the diff body
});

// ─── evidence fusion + structured uncertainty ───

test("evidence fuses the manifest checks with the brief's facts (deduplicated), and verifyThis surfaces", () => {
  const p = assembleDecisionPacket({ manifest: manifest(), brief: brief() });
  assert.ok(p.evidence.some((e) => e.label === "unit tests"));        // from manifest
  assert.ok(p.evidence.some((e) => e.label === "files touched"));      // from brief
  assert.equal(p.verifyThis, "Does x.ts still handle zero-total carts?");
  const r = renderPacket(p);
  assert.match(r, /Before you approve, please verify/);
  assert.match(r, /zero-total carts/);
});

test("whyAttention fuses brief.routedBecause + oversight.reasons without duplicates", () => {
  const p = assembleDecisionPacket({ manifest: manifest({ oversight: { band: "medium", disposition: "human-approval-required", mode: "notify-async", requiresImmediateAttention: false, reasons: ["touches billing logic"] } }), brief: brief({ routedBecause: ["touches billing logic"] }) });
  const billing = p.whyAttention.filter((r) => /billing logic/.test(r));
  assert.equal(billing.length, 1, "deduplicated across brief + oversight");
});

// ─── selective confidence (automation-bias guard) ───

test("confidence renders only when low or high-stakes (not on every output)", () => {
  const high = assembleDecisionPacket({ manifest: manifest(), confidence: 0.95 });
  assert.doesNotMatch(renderPacket(high), /Confidence:/); // high confidence, low band → not shown
  const low = assembleDecisionPacket({ manifest: manifest(), confidence: 0.4 });
  assert.match(renderPacket(low), /Confidence: 40%/); // low confidence → shown with a caution
  assert.match(renderPacket(low), /look closely/);
});

// ─── graceful degradation (N=1 / free-tier: no brief, no forecast) ───

test("degrades gracefully with no brief and no forecast — still a valid packet", () => {
  const p = assembleDecisionPacket({ manifest: manifest() });
  assert.equal(p.reversible, true); // manifest-only default
  assert.ok(p.evidence.length >= 1);
  assert.equal(p.verifyThis, undefined);
  assert.match(renderPacket(p), /Review: KEEP-1/);
});

// ─── explicit --full override on a compact packet ───

test("--full override shows the diff even when depth is compact", () => {
  const p = assembleDecisionPacket({ manifest: manifest(), forecast: forecast() });
  assert.equal(p.depth, "compact");
  assert.match(renderPacket(p, { full: true }), /\+d/); // override reveals the diff body
});

// ─── disposition framing (the machine vetting is primary; human is the residual) ───

test("an auto-approved packet frames as a spot-check; a gated packet frames as a required decision", () => {
  const auto = assembleDecisionPacket({ manifest: manifest({ oversight: { band: "low", disposition: "auto-approved", mode: "silent-auto", requiresImmediateAttention: false, reasons: ["low risk"] } }) });
  assert.equal(auto.disposition, "auto-approved");
  assert.match(renderPacket(auto), /cleared this and auto-approved/);
  assert.match(renderPacket(auto), /optional confirmation, not a required gate/);

  const gated = assembleDecisionPacket({ manifest: manifest({ oversight: { band: "high", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: true, reasons: ["reaches sensitive path"] } }) });
  assert.equal(gated.disposition, "human-approval-required");
  assert.match(renderPacket(gated), /routed this to you for a decision/);
  assert.match(renderPacket(gated), /does not proceed without you/);
});

test("packet defaults to requiring a human decision when the machine verdict is absent (safe default)", () => {
  const base = manifest();
  const noOversight = { ...base } as Record<string, unknown>;
  delete noOversight["oversight"];
  const p = assembleDecisionPacket({ manifest: noOversight as unknown as PrManifest });
  assert.equal(p.disposition, "human-approval-required");
  assert.equal(p.requiresImmediateAttention, true);
});
