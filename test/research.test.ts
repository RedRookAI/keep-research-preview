import { test } from "node:test";
import assert from "node:assert/strict";

import {
  detectResearchNeed,
  type ResearchClaim,
} from "../src/research/research_need.js";
import {
  ResearchLoop,
  type ResearchSource,
} from "../src/research/research_loop.js";
import {
  verifyClaim,
  verifyProvenance,
  ResearchProvenanceFloorTier,
  type ResearchVetPayload,
} from "../src/research/provenance_floor.js";
import { VerificationCascade } from "../src/cascade/verification_cascade.js";
import { ConfidenceEscalationPolicy } from "../src/cascade/escalation_policy.js";

// ── Research-need detector ──────────────────────────────────────────────────

test("research-need detector fires on recency / research-goal / prior-art signals", () => {
  assert.equal(detectResearchNeed("what is the latest SOTA in drone control 2026").needed, true);
  assert.equal(detectResearchNeed("survey the literature on RAG faithfulness").needed, true);
  assert.equal(detectResearchNeed("does an open-source alternative to X already exist").needed, true);
  // a plain, non-recency task doesn't trigger
  assert.equal(detectResearchNeed("add two numbers together").needed, false);
});

test("detector extracts keywords for the search seam", () => {
  const need = detectResearchNeed("latest SOTA techniques for drone flight controllers 2026");
  assert.ok(need.keywords.includes("drone"));
  assert.ok(need.keywords.length > 0 && need.keywords.length <= 8);
});

// ── ResearchLoop: bounded + honest offline ──────────────────────────────────

test("INVARIANT: offline research is HONEST — no search, marked unverifiable, no fabricated currency", async () => {
  const loop = new ResearchLoop({
    search: () => null, // offline
    context: { canVerify: false, todayISO: "2026-08-04" },
  });
  const report = await loop.run("what is the current best drone SDK");
  assert.equal(report.searched, false, "no live search ran");
  assert.equal(report.claims.length, 0, "no claims fabricated when offline");
  assert.match(report.caveat ?? "", /UNVERIFIED|unverified|local knowledge/, "honest offline caveat");
});

test("INVARIANT: ResearchLoop respects the iteration bound (rabbit-hole guard)", async () => {
  let calls = 0;
  const loop = new ResearchLoop({
    search: () => { calls++; return [{ title: "s", locator: "http://x", snippet: "info" }]; },
    context: { canVerify: true, todayISO: "2026-08-04" },
    maxIterations: 2,
  });
  await loop.run("survey latest SOTA for X 2026");
  assert.ok(calls <= 2, `search called ${calls} times, must be ≤ maxIterations (2)`);
});

test("ResearchLoop distills sources into cited claims when search succeeds", async () => {
  const sources: ResearchSource[] = [
    { title: "Paper A", locator: "https://arxiv.org/abs/1", snippet: "Technique A improves X by 20%.", asOf: "2026-07" },
  ];
  const loop = new ResearchLoop({
    search: () => sources,
    context: { canVerify: true, todayISO: "2026-08-04" },
  });
  const report = await loop.run("research latest technique for X 2026");
  assert.equal(report.searched, true);
  assert.ok(report.claims.length >= 1);
  assert.ok(report.claims[0]!.citations[0]!.locator, "claim carries a citation with a locator");
});

// ── Provenance floor: BOTH hallucination modes ──────────────────────────────

test("INVARIANT: ungrounded claim (no citation) → ungrounded (never cite from memory)", () => {
  const claim: ResearchClaim = { id: "c", text: "X is true", citations: [] };
  assert.equal(verifyClaim(claim).status, "ungrounded");
});

test("INVARIANT: citation with no locator → citation-unresolvable (citation hallucination)", () => {
  const claim: ResearchClaim = { id: "c", text: "X", citations: [{ id: "1", title: "Fake Paper", supportingText: "X" }] };
  assert.equal(verifyClaim(claim).status, "citation-unresolvable");
});

test("INVARIANT: source resolves but doesn't support claim → unsupported (statement hallucination)", () => {
  const claim: ResearchClaim = {
    id: "c",
    text: "Drones can fly to Mars",
    citations: [{ id: "1", title: "Real Paper", locator: "https://arxiv.org/abs/1", supportingText: "Drones are used for aerial photography." }],
  };
  // faithfulness checker returns low support (claim not in source)
  const prov = verifyClaim(claim, { faithfulness: () => 0.1 });
  assert.equal(prov.status, "unsupported", "statement hallucination caught");
});

test("INVARIANT: resolvable + supported citation → grounded", () => {
  const claim: ResearchClaim = {
    id: "c",
    text: "Technique A improves X",
    citations: [{ id: "1", title: "Paper", locator: "https://arxiv.org/abs/1", supportingText: "Technique A improves X by 20%." }],
  };
  assert.equal(verifyClaim(claim, { faithfulness: () => 0.95 }).status, "grounded");
});

test("no faithfulness checker → unverifiable (honest, not a false pass)", () => {
  const claim: ResearchClaim = {
    id: "c",
    text: "X",
    citations: [{ id: "1", title: "Paper", locator: "https://arxiv.org/abs/1", supportingText: "some text" }],
  };
  assert.equal(verifyClaim(claim).status, "unverifiable", "can't confirm support → unverifiable, not grounded");
});

test("verifyProvenance summarizes a batch", () => {
  const claims: ResearchClaim[] = [
    { id: "a", text: "grounded", citations: [{ id: "1", title: "P", locator: "http://x", supportingText: "grounded" }] },
    { id: "b", text: "fake", citations: [{ id: "2", title: "Fake" }] },
    { id: "c", text: "memory", citations: [] },
  ];
  const { summary } = verifyProvenance(claims, { faithfulness: () => 0.9 });
  assert.equal(summary.grounded, 1);
  assert.equal(summary["citation-unresolvable"], 1);
  assert.equal(summary.ungrounded, 1);
});

// ── Cascade integration ─────────────────────────────────────────────────────

test("INVARIANT: fabricated citations FAIL at the research floor (Tier 0), brain never overturns", async () => {
  const claims: ResearchClaim[] = [
    { id: "a", text: "real", citations: [{ id: "1", title: "P", locator: "http://x", supportingText: "real" }] },
    { id: "b", text: "fabricated", citations: [{ id: "2", title: "Fake Paper (no locator)" }] },
  ];
  const payload: ResearchVetPayload = { claims, options: { faithfulness: () => 0.9 } };
  const tiers = [
    new ResearchProvenanceFloorTier(),
    { tier: 1, name: "brain", sound: false, available: () => true, verify: () => ({ tier: 1, name: "brain", decision: "pass" as const, reason: "brain says fine", sound: false, certainty: 1 }) },
  ];
  const cascade = new VerificationCascade<ResearchVetPayload>(tiers, new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "r1", kind: "research", payload });
  assert.equal(out.finalDecision, "fail", "fabricated citation fails at the sound floor");
  assert.equal(out.decidedAtTier, 0, "brain never got to overturn the fabricated citation");
});

test("all-grounded research PASSES the floor", async () => {
  const claims: ResearchClaim[] = [
    { id: "a", text: "real", citations: [{ id: "1", title: "P", locator: "http://x", supportingText: "real" }] },
  ];
  const payload: ResearchVetPayload = { claims, options: { faithfulness: () => 0.9 } };
  const cascade = new VerificationCascade<ResearchVetPayload>([new ResearchProvenanceFloorTier()], new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "r2", kind: "research", payload });
  assert.equal(out.finalDecision, "pass");
  assert.equal(out.decidedAtTier, 0);
});

test("INVARIANT: ResearchLoop dedups identical sources across iterations", async () => {
  const dup: ResearchSource[] = [{ title: "Same Paper", locator: "https://arxiv.org/abs/dup", snippet: "same finding" }];
  const loop = new ResearchLoop({
    search: () => dup, // returns the SAME source every iteration
    context: { canVerify: true, todayISO: "2026-08-04" },
    maxIterations: 3,
  });
  const report = await loop.run("survey latest SOTA for X 2026");
  assert.equal(report.claims.length, 1, "identical sources deduped — not re-distilled per iteration");
});
