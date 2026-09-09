import { test } from "node:test";
import assert from "node:assert/strict";
import { buildVettingGates, type ConsequenceVetPayload, type PatchVetPayload } from "../src/cascade/vetting_gates.js";
import type { SolveResult } from "../src/solve/issue_model.js";
import type { Issue } from "../src/solve/issue_model.js";

const issue = (text: string): Issue => ({ id: "I1", text, repoRef: "." });

// A patch payload whose deterministic floor (verifyPatch) will FAIL: a solve that leaks a secret / fails a sound check.
function failingPatch(): PatchVetPayload {
  const solveResult = {
    issueId: "I1", solved: true, stagesRun: [], repairRounds: 0,
    validation: { testsPassed: true, detail: "ok" },
    prProposal: { title: "x", body: "y", branch: "b", edits: [{ file: "calc.test.ts", search: "expect(add(1,2)).toBe(3)", replace: "expect(add(1,2)).toBe(99)" }] },
  } as unknown as SolveResult;
  return { solveResult, issueText: "add an adder function" };
}
function cleanPatch(): PatchVetPayload {
  const solveResult = {
    issueId: "I1", solved: true, stagesRun: [], repairRounds: 0,
    validation: { testsPassed: true, detail: "ok" },
    prProposal: { title: "x", body: "y", branch: "b", edits: [{ file: "calc.ts", search: "export const add = (a,b) => 0;", replace: "export const add = (a,b) => a+b;" }] },
  } as unknown as SolveResult;
  return { solveResult, issueText: "add an adder function that returns the sum of two numbers" };
}

test("CROWN JEWEL (soundness dominates): a sound floor FAIL is authoritative — a model tier saying 'pass' cannot overturn it", async () => {
  // A single-brain verifier that ALWAYS blesses (adversarial: the model tries to wave the patch through).
  const blessingBrain = () => ({ decision: "pass" as const, reason: "looks fine to me", certainty: 1 });
  const gates = buildVettingGates({ capability: "lean", patchSingleBrain: blessingBrain });
  const out = await gates.vetPatch(failingPatch());
  assert.equal(out.finalDecision, "fail", "the sound floor's fail stood — the model could not override it");
  assert.equal(out.decidedAtTier, 0, "decided at the sound floor (Tier 0), never climbed to the model");
});

test("capability=none → the gate reproduces the deterministic floor verdict exactly (N=1, no brain)", async () => {
  const gates = buildVettingGates({ capability: "none" });
  assert.equal((await gates.vetPatch(failingPatch())).finalDecision, "fail", "sound floor fail passes through");
  assert.equal((await gates.vetPatch(cleanPatch())).finalDecision, "pass", "a clean patch clears the floor");
});

test("plan gate: a blocking consequence is a sound floor fail", async () => {
  const gates = buildVettingGates({ capability: "none" });
  // A destructive/irreversible-sounding goal that the consequence floor should block or escalate.
  const payload: ConsequenceVetPayload = { issue: issue("delete all user records and drop the production database") };
  const out = await gates.vetPlan(payload);
  assert.notEqual(out.finalDecision, "pass", "a dangerous plan does not cleanly pass the deterministic floor");
});

test("WIRE: composeKeep exposes the vetting gates, floor always-on regardless of brain", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-vg-")) });
  assert.ok(app.vettingGates, "vetting gates wired onto the app");
  const out = await app.vettingGates.vetPatch(failingPatch());
  assert.equal(out.finalDecision, "fail", "the composed gate enforces the sound floor end-to-end");
});

// ─── Research grounding gates (provenance floor + RAG grounding floor) ───

import type { ResearchVetPayload } from "../src/research/provenance_floor.js";

test("RESEARCH PROVENANCE (structural): a claim with NO citation is a sound fail (never cite from memory)", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const payload: ResearchVetPayload = { claims: [{ id: "c1", text: "revenue tripled in Q3", citations: [] }] };
  const out = await gates.vetResearchClaim(payload);
  assert.equal(out.finalDecision, "fail");
  assert.equal(out.decidedAtTier, 0, "the provenance floor decides — fabricated attribution filtered structurally");
});

test("RESEARCH PROVENANCE: an unresolvable citation (dead/fake locator) is a sound fail", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const payload: ResearchVetPayload = {
    claims: [{ id: "c1", text: "X", citations: [{ id: "z", title: "Ghost Paper", locator: "http://not-real" }] }],
    options: { resolver: () => false },
  };
  assert.equal((await gates.vetResearchClaim(payload)).finalDecision, "fail");
});

test("RESEARCH PROVENANCE (crown jewel): a fabricated citation FAILS even when a model tier blesses it", async () => {
  // Adversarial single-brain that always passes — the sound floor must still win.
  const blessing = () => ({ decision: "pass" as const, reason: "trust me", certainty: 1 });
  const gates = buildVettingGates({ capability: "lean", researchSingleBrain: blessing });
  const payload: ResearchVetPayload = { claims: [{ id: "c1", text: "made-up fact", citations: [] }] };
  const out = await gates.vetResearchClaim(payload);
  assert.equal(out.finalDecision, "fail", "the model could not bless away an absent citation");
  assert.equal(out.decidedAtTier, 0, "decided at the sound provenance floor");
});

test("RESEARCH PROVENANCE: a resolvable + faithful citation passes", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const payload: ResearchVetPayload = {
    claims: [{ id: "c1", text: "the sky is blue", citations: [{ id: "z", title: "Optics", locator: "http://real", supportingText: "the sky is blue due to Rayleigh scattering" }] }],
    options: { resolver: () => true, faithfulness: () => 0.9 },
  };
  assert.equal((await gates.vetResearchClaim(payload)).finalDecision, "pass");
});

test("RAG GROUNDING (abstain): insufficient retrieval → fail (never answer without evidence)", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const out = await gates.vetRagAnswer({ answer: "the answer is 42", chunks: [] });
  assert.equal(out.finalDecision, "fail");
  assert.match(out.reason, /abstain/i);
});

test("RAG GROUNDING (fabrication): an answer that traces to no chunk → fail", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const out = await gates.vetRagAnswer({
    answer: "zebras migrate across the Serengeti in vast herds every spring.",
    chunks: [{ text: "quantum computing relies on qubits and superposition", sourceId: "s1", score: 1 }],
  });
  assert.equal(out.finalDecision, "fail", "ungrounded answer is fabrication");
});

test("RAG GROUNDING: a grounded, sufficient answer passes", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const out = await gates.vetRagAnswer({
    answer: "quantum computing relies on qubits.",
    chunks: [{ text: "quantum computing relies on qubits and superposition to compute", sourceId: "s1", score: 1 }],
  });
  assert.notEqual(out.finalDecision, "fail", "a grounded answer is not failed");
});

test("WIRE: composeKeep's vetting gates expose the research + RAG grounding floors", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-rg-")) });
  assert.equal((await app.vettingGates.vetResearchClaim({ claims: [{ id: "c1", text: "x", citations: [] }] })).finalDecision, "fail");
  assert.equal((await app.vettingGates.vetRagAnswer({ answer: "x", chunks: [] })).finalDecision, "fail");
});
