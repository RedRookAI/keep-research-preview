import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  captureTriResearchManifest,
  evaluateResearchPlanningEligibility,
  triResearchManifestDigest,
  type CrossFamilyResearchReview,
  type TriResearchManifest,
} from "../src/research/tri_research_admission.js";

const D = "1".repeat(64);
const P = "2".repeat(64);
const E = "3".repeat(64);
const F = "4".repeat(64);
const R = "5".repeat(64);

function manifest(): TriResearchManifest {
  return {
    schemaVersion: "keep.tri-research/v1",
    milestoneId: "planner.security.v1",
    buildDomain: "agent-orchestration",
    candidateDigest: D,
    planDigest: P,
    researchAsOf: "2026-08-19",
    currentWindowStart: "2026-02-19",
    currentWindowEnd: "2026-08-19",
    completedAt: "2026-08-19T11:00:00.000Z",
    searchScopeRef: "repo:docs/research/search-scope.json",
    searchScopeDigest: E,
    searchLimitations: ["No source proves absence of unpublished attacks."],
    sources: [
      {
        id: "cross-1", lane: "cross-disciplinary", title: "GSN Standard v3", locator: "https://scsc.uk/gsn-standard",
        publisher: "SCSC", domain: "safety-engineering", sourceDate: "2021-05-01", retrievedAt: "2026-08-19T10:00:00.000Z",
        bodyRef: "repo:docs/research/cross-source.html", bodySha256: F, primary: true, supports: ["claim-1"], limitation: "Structured arguments do not make weak evidence strong.",
        transferMechanism: "Represent research readiness as claims, arguments, evidence, assumptions, and undeveloped nodes.",
      },
      {
        id: "current-1", lane: "current", title: "Current attestation specification", locator: "https://in-toto.io/",
        publisher: "in-toto", domain: "software-supply-chain", sourceDate: "2026-03-18", retrievedAt: "2026-08-19T10:01:00.000Z",
        bodyRef: "repo:docs/research/current-source.html", bodySha256: F, primary: true, supports: ["claim-1"], limitation: "Attestation authenticates provenance, not truth of the claim.", transferMechanism: null,
      },
      {
        id: "history-1", lane: "historical", title: "Engineering Trustworthy Secure Systems", locator: "https://doi.org/10.6028/NIST.SP.800-160v1r1",
        publisher: "NIST", domain: "systems-security", sourceDate: "2022-11-01", retrievedAt: "2026-08-19T10:02:00.000Z",
        bodyRef: "repo:docs/research/history-source.html", bodySha256: F, primary: true, supports: ["claim-1"], limitation: "Assurance cases reduce uncertainty but are not complete proofs.", transferMechanism: null,
      },
    ],
    claims: [{ id: "claim-1", text: "Plan promotion requires traceable multi-lane evidence plus independent review.", sourceIds: ["cross-1", "current-1", "history-1"], applicability: "Consequential Keep research and planning milestones.", limitation: "This gate establishes evidence closure, not correctness of every cited proposition." }],
  };
}

function review(m = manifest()): CrossFamilyResearchReview {
  return {
    schemaVersion: "keep.cross-family-research-review/v1", manifestDigest: triResearchManifestDigest(m), candidateDigest: D,
    authorFamily: "openai", reviewerFamily: "anthropic", provider: "anthropic-first-party", model: "claude-opus-5",
    sessionId: "review-session-1", transport: "provider-first-party", outputTokens: 1200,
    reviewedAt: "2026-08-19T12:00:00.000Z", expiresAt: "2026-09-18T12:00:00.000Z", verdict: "GO",
    findingsDigest: R, rawEvidenceDigest: E,
  };
}

const context = { candidateDigest: D, planDigest: P, observedNow: "2026-08-19T13:00:00.000Z" } as const;

test("repository fixture has the independently pinned semantic manifest identity", () => {
  const fixture = JSON.parse(readFileSync(new URL("../../test/fixtures/tri_research/valid-manifest.json", import.meta.url), "utf8"));
  const captured = captureTriResearchManifest(fixture);
  assert.equal(captured.candidateDigest, "880a9ee6ea87be2ad96463d6e08e3cb097f087e3bd96af461bff761c4b40ecf3");
  assert.equal(triResearchManifestDigest(captured), "0cf7aed239bce2662dad83ce47ddeb1a62d141fd2d2b9b12e84ba19fc6abf331");
});

test("tri-research structural eligibility binds exact candidate, plan, three lanes, date window, and review claim", () => {
  const m = manifest();
  const verdict = evaluateResearchPlanningEligibility(m, review(m), context);
  assert.equal(verdict.readyForExternalVerification, true, verdict.reasons.join("\n"));
  assert.match(verdict.manifestDigest ?? "", /^[0-9a-f]{64}$/);
});

test("each missing or stale research lane blocks promotion", () => {
  const base = manifest();
  for (const lane of ["current", "historical", "cross-disciplinary"] as const) {
    const mutant = { ...base, sources: base.sources.filter((source) => source.lane !== lane) };
    assert.equal(evaluateResearchPlanningEligibility(mutant, review(base), context).readyForExternalVerification, false, lane);
  }
  const stale = structuredClone(base);
  (stale.sources[1] as { sourceDate: string }).sourceDate = "2026-02-18";
  assert.equal(evaluateResearchPlanningEligibility(stale, review(stale), context).readyForExternalVerification, false, "current evidence before six-month window refuses");
  const oldRetrieved = structuredClone(base);
  (oldRetrieved.sources[1] as { retrievedAt: string }).retrievedAt = "2026-08-18T23:59:59.000Z";
  assert.equal(evaluateResearchPlanningEligibility(oldRetrieved, review(oldRetrieved), context).readyForExternalVerification, false, "today must be verified, never assumed");
});

test("calendar-exact six-month lookback and claim-to-all-lanes closure are load-bearing", () => {
  const wrongWindow = { ...manifest(), currentWindowStart: "2026-02-20" };
  assert.equal(evaluateResearchPlanningEligibility(wrongWindow, review(wrongWindow as TriResearchManifest), context).readyForExternalVerification, false);
  const base = manifest();
  const missingClaimLane = { ...base, claims: [{ ...base.claims[0]!, sourceIds: ["current-1", "history-1"] }] };
  assert.match(evaluateResearchPlanningEligibility(missingClaimLane, review(missingClaimLane), context).reasons.join(" "), /all three lanes|bidirectionally/);
});

test("candidate/plan substitution, same-family review, no real execution, and non-GO all refuse", () => {
  const m = manifest();
  assert.equal(evaluateResearchPlanningEligibility(m, review(m), { ...context, candidateDigest: "a".repeat(64) }).readyForExternalVerification, false);
  assert.equal(evaluateResearchPlanningEligibility(m, review(m), { ...context, planDigest: "b".repeat(64) }).readyForExternalVerification, false);
  assert.equal(evaluateResearchPlanningEligibility(m, { ...review(m), reviewerFamily: "openai" }, context).readyForExternalVerification, false);
  assert.equal(evaluateResearchPlanningEligibility(m, { ...review(m), verdict: "REVISE" }, context).readyForExternalVerification, false);
  assert.equal(evaluateResearchPlanningEligibility(m, { ...review(m), outputTokens: 0 }, context).readyForExternalVerification, false);
});

test("chronology, bounded review lifetime, and bidirectional source/claim edges fail closed", () => {
  const m = manifest();
  const earlyReview = { ...review(m), reviewedAt: "2026-08-19T10:30:00.000Z" };
  assert.equal(evaluateResearchPlanningEligibility(m, earlyReview, context).readyForExternalVerification, false);
  const longReview = { ...review(m), expiresAt: "2026-10-01T12:00:00.000Z" };
  assert.equal(evaluateResearchPlanningEligibility(m, longReview, context).readyForExternalVerification, false);
  const lateSource = structuredClone(m);
  (lateSource.sources[0] as { retrievedAt: string }).retrievedAt = "2026-08-19T11:30:00.000Z";
  assert.equal(evaluateResearchPlanningEligibility(lateSource, review(lateSource), context).readyForExternalVerification, false);
  const asymmetric = { ...m, claims: [...m.claims, { id: "claim-2", text: "Second claim.", sourceIds: ["cross-1", "current-1", "history-1"], applicability: "Parity test.", limitation: "Test-only." }] };
  assert.match(evaluateResearchPlanningEligibility(asymmetric, review(asymmetric), context).reasons.join(" "), /bidirectionally/);
});

test("hostile Proxy is rejected before any reflective trap can execute", () => {
  let traps = 0;
  const proxy = new Proxy(manifest(), {
    getPrototypeOf() { traps++; throw new Error("trap"); },
    ownKeys() { traps++; throw new Error("trap"); },
    getOwnPropertyDescriptor() { traps++; throw new Error("trap"); },
    get() { traps++; throw new Error("trap"); },
  });
  assert.throws(() => captureTriResearchManifest(proxy), /inert record/);
  assert.equal(traps, 0);

  for (const field of ["sources", "claims", "searchLimitations"] as const) {
    const nested = manifest() as unknown as Record<string, unknown>;
    nested[field] = new Proxy(nested[field] as object, {
      ownKeys() { traps++; throw new Error("trap"); }, getOwnPropertyDescriptor() { traps++; throw new Error("trap"); }, get() { traps++; throw new Error("trap"); },
    });
    assert.throws(() => captureTriResearchManifest(nested), /inert array/);
  }
  const contextProxy = new Proxy(context, { getPrototypeOf() { traps++; throw new Error("trap"); }, ownKeys() { traps++; throw new Error("trap"); }, getOwnPropertyDescriptor() { traps++; throw new Error("trap"); }, get() { traps++; throw new Error("trap"); } });
  assert.equal(evaluateResearchPlanningEligibility(manifest(), review(), contextProxy).readyForExternalVerification, false);
  assert.equal(traps, 0);
});
