import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { vetPlan, type Plan, type PlanPolicy, type PlanStep } from "../src/logic/plan_gate.js";
import { captureTriResearchManifest, triResearchManifestDigest, type CrossFamilyResearchReview } from "../src/research/tri_research_admission.js";
import { mintVerifiedMeaningfulReviewPass, reviewAdverseHistoryDigest, type MeaningfulReviewPass, type ReviewPassReceiptV1 } from "../src/discipline/review_policy.js";
import type { Sha256Digest, StableOperationId } from "../src/discipline/contracts.js";
import { Ed25519ExternalReviewCorroborationVerifier, externalReviewEvidenceSignaturePreimage, type ExternalReviewTrustRootV1 } from "../src/discipline/external_review_corroboration.js";
import { monolithicReviewTransactionDigest, verifyMonolithicReviewTransaction } from "../src/discipline/review_composition.js";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalize } from "../src/spine/event.js";

// The logic/plan-vetting layer — LLM-Modulo external SOUND critics for the AI's own PLAN. Deterministic;
// the LLM is the generator, not the verifier. Verify by disproof; each critic isolated.

const policy: PlanPolicy = { maxCostValueRatio: 3, maxNoProgressRun: 2, researchRequirement: "not-required", reviewRequirement: "not-required" };

// a well-formed step with sensible defaults; override per test.
const step = (id: string, o: Partial<PlanStep> = {}): PlanStep => ({
  id,
  prerequisites: "prerequisites" in o ? (o.prerequisites as readonly string[]) : [],
  advancesGoal: "advancesGoal" in o ? o.advancesGoal : "G",
  predictedCost: "predictedCost" in o ? o.predictedCost : 1,
  subProblemValue: "subProblemValue" in o ? o.subProblemValue : 1,
  undoes: "undoes" in o ? (o.undoes as readonly string[]) : [],
  progressAfter: "progressAfter" in o ? o.progressAfter : 0,
  requires: "requires" in o ? (o.requires as readonly string[] | undefined) : [],
  establishes: "establishes" in o ? (o.establishes as readonly string[]) : [],
  deletes: "deletes" in o ? (o.deletes as readonly string[]) : [],
});

// a clean plan: two in-order, on-goal, proportional, progressing steps.
const cleanPlan = (): Plan => ({
  goals: ["G"],
  committed: [],
  initialState: [],
  goalFacts: [],
  steps: [
    step("a", { progressAfter: 1 }),
    step("b", { prerequisites: ["a"], progressAfter: 2 }),
  ],
});

test("plan-vet: a clean aligned in-order proportional plan PROCEEDS (no false positive)", () => {
  assert.equal(vetPlan(cleanPlan(), policy).proceed, true);
});

test("plan-vet: consequential research policy fails closed without a package or trusted external verifier", () => {
  const required: PlanPolicy = { ...policy, researchRequirement: "structural-and-external" };
  const missing = vetPlan(cleanPlan(), required);
  assert.equal(missing.proceed, false);
  assert.ok(missing.hardHolds.includes("research:package-required"));
});

test("plan-vet: unknown or missing runtime research policy never falls through as not-required", () => {
  const typo = { maxCostValueRatio: 3, maxNoProgressRun: 2, researchRequirement: "typo", reviewRequirement: "not-required" } as unknown as PlanPolicy;
  const missing = { maxCostValueRatio: 3, maxNoProgressRun: 2 } as unknown as PlanPolicy;
  assert.ok(vetPlan(cleanPlan(), typo).hardHolds.includes("research:unknown-policy-requirement"));
  assert.ok(vetPlan(cleanPlan(), missing).hardHolds.includes("policy:invalid-or-noninert"));
});

test("plan-vet: caller-owned policy is captured once and hostile accessors/Proxies fail without traps", () => {
  let reads = 0;
  const alternating = {
    maxCostValueRatio: 3,
    maxNoProgressRun: 2,
    reviewRequirement: "not-required",
    get researchRequirement() {
      reads++;
      return reads < 3 ? "structural-and-external" : "not-required";
    },
  } as unknown as PlanPolicy;
  const accessorVerdict = vetPlan(cleanPlan(), alternating);
  assert.equal(accessorVerdict.proceed, false);
  assert.ok(accessorVerdict.hardHolds.includes("policy:invalid-or-noninert"));
  assert.equal(reads, 0);

  let traps = 0;
  const proxy = new Proxy(policy, {
    getPrototypeOf() { traps++; throw new Error("trap"); },
    ownKeys() { traps++; throw new Error("trap"); },
    getOwnPropertyDescriptor() { traps++; throw new Error("trap"); },
    get() { traps++; throw new Error("trap"); },
  });
  const proxyVerdict = vetPlan(cleanPlan(), proxy);
  assert.equal(proxyVerdict.proceed, false);
  assert.ok(proxyVerdict.hardHolds.includes("policy:invalid-or-noninert"));
  assert.equal(traps, 0);
});

test("plan-vet: policy is frozen before hostile plan access and the plan shell is inertly captured", () => {
  const required: { maxCostValueRatio: number; maxNoProgressRun: number; researchRequirement: "not-required" | "structural-and-external"; reviewRequirement: "not-required" | "two-to-four-cross-family" } = { ...policy, researchRequirement: "structural-and-external" };
  let reads = 0;
  const hostilePlan = {
    goals: ["G"], committed: [], initialState: [], goalFacts: [],
    get steps() {
      reads++;
      required.researchRequirement = "not-required";
      return [];
    },
  } as unknown as Plan;
  const verdict = vetPlan(hostilePlan, required);
  assert.equal(verdict.proceed, false);
  assert.ok(verdict.hardHolds.includes("plan:invalid-or-noninert"));
  assert.equal(required.researchRequirement, "structural-and-external");
  assert.equal(reads, 0);
});

test("plan-vet: consequential plan reaches normal critics only after structural closure and deployment-selected external verification", () => {
  const manifest = captureTriResearchManifest(JSON.parse(readFileSync("test/fixtures/tri_research/valid-manifest.json", "utf8")));
  const review: CrossFamilyResearchReview = {
    schemaVersion: "keep.cross-family-research-review/v1", manifestDigest: triResearchManifestDigest(manifest), candidateDigest: manifest.candidateDigest,
    authorFamily: "family-a", reviewerFamily: "family-b", provider: "operator-selected-provider", model: "independent-model",
    sessionId: "fixture-session", transport: "operator-pinned-api", outputTokens: 1,
    reviewedAt: "2026-08-19T12:00:00.000Z", expiresAt: "2026-09-18T12:00:00.000Z", verdict: "GO",
    findingsDigest: "3".repeat(64), rawEvidenceDigest: "4".repeat(64),
  };
  const plan: Plan = { ...cleanPlan(), researchPackage: { manifest, review, context: { candidateDigest: manifest.candidateDigest, planDigest: manifest.planDigest, observedNow: "2026-08-19T13:00:00.000Z" } } };
  const required: PlanPolicy = { ...policy, researchRequirement: "structural-and-external" };
  assert.ok(vetPlan(plan, required).hardHolds.includes("research:external-verifier-unavailable"));
  assert.equal(vetPlan(plan, required, { verify: () => ({ verified: true, reason: "fixture deployment adapter verified raw evidence" }) }).proceed, true);
  assert.equal(vetPlan(plan, required, { verify: () => ({ verified: false, reason: "provider evidence invalid" }) }).proceed, false);
});

test("plan-vet: substantive review requires two verifier-minted clean cross-family passes over identical candidate and adverse history", async () => {
  const candidateDigest = "a".repeat(64) as Sha256Digest;
  const subjectManifestDigest = "d".repeat(64) as Sha256Digest;
  const transactionInput = { schema: "keep.monolithic-review-transaction/v1" as const, candidateDigest, subjectManifestDigest };
  const transactionDigest = monolithicReviewTransactionDigest(transactionInput);
  const adverseHistoryDigest = reviewAdverseHistoryDigest([]);
  const receipt = (pass: number): ReviewPassReceiptV1 => ({
    schema: "keep.review-pass-receipt/v1",
    campaignId: "plan-review-campaign" as StableOperationId,
    operationId: "plan-review-operation" as StableOperationId,
    operationPredecessorId: null,
    pass,
    candidateDigest,
    adverseHistoryDigest,
    adverseObservationDigests: [],
    disposition: "go",
    findings: [],
    authoritySurfaceChanged: false,
    transaction: { transactionDigest, kind: "monolithic", exactSubjectCoverage: true, allChildResultsPresent: true, compositionVerified: true, unresolvedCrossPartCriticalCount: 0 },
  });
  const keys = generateKeyPairSync("ed25519");
  const trust: ExternalReviewTrustRootV1 = { schema: "keep.external-review-trust-root/v1", anchors: [{ keyId: "review-key", captureClass: "provider-signed", provider: "review-provider", familyId: "review-family", publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), validFromMs: 1, validUntilMs: 1_000, revokedAtMs: null }] };
  const verifier = new Ed25519ExternalReviewCorroborationVerifier(trust, () => 500);
  const reviewPass = async (pass: number) => {
    const row = receipt(pass);
    const unsigned = { schema: "keep.signed-external-review-evidence/v1" as const, candidateDigest, subjectManifestDigest, policyDigest: "e".repeat(64), rawEvidenceDigest: "f".repeat(64), requestDigest: "1".repeat(64), transactionDigest: row.transaction.transactionDigest, campaignId: row.campaignId, operationId: row.operationId, operationPredecessorId: row.operationPredecessorId, attemptId: `attempt-${pass}`, round: pass, independence: "cross-family-external-technical" as const, verdict: "go" as const, findingDigests: [] as string[], limitations: [] as string[], provider: "review-provider", model: "review-model", familyId: "review-family", sessionId: `session-${pass}`, captureClass: "provider-signed" as const, observedAtMs: 200, expiresAtMs: 800, keyId: "review-key" };
    const carrier = Buffer.from(`${canonicalize({ ...unsigned, signatureBase64: sign(null, externalReviewEvidenceSignaturePreimage(unsigned), keys.privateKey).toString("base64") })}\n`);
    const external = await verifier.verifyExternalReview(carrier, { candidateDigest, subjectManifestDigest, policyDigest: "e".repeat(64) as Sha256Digest, requestDigest: "1".repeat(64) as Sha256Digest, builderFamilyId: "builder-family" });
    const verifiedTransaction = verifyMonolithicReviewTransaction(transactionInput, external);
    return mintVerifiedMeaningfulReviewPass(external, row, verifiedTransaction);
  };
  const required: PlanPolicy = { ...policy, reviewRequirement: "two-to-four-cross-family" };
  assert.equal(vetPlan(cleanPlan(), required).proceed, false);
  const pass1 = await reviewPass(1), pass2 = await reviewPass(2);
  assert.ok(vetPlan({ ...cleanPlan(), reviewPasses: [pass1] }, required).hardHolds.includes("review:minimum-passes-not-met"));
  const reviewed = { ...cleanPlan(), reviewPasses: [pass1, pass2] };
  assert.equal(vetPlan(reviewed, required).proceed, true);
  const forged = { ...pass2 } as unknown as typeof pass2;
  assert.ok(vetPlan({ ...cleanPlan(), reviewPasses: [pass1, forged] }, required).hardHolds.includes("review:invalid-review-lineage"));
});

test("plan-vet: an OUT-OF-ORDER plan (step before its prerequisite) is HELD (isolated)", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: [],
    initialState: [],
    goalFacts: [],
    steps: [
      step("b", { prerequisites: ["a"], progressAfter: 1 }), // b before a
      step("a", { progressAfter: 2 }),
    ],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.holds.some((h) => h.startsWith("order:prereq-after-step")));
});

test("plan-vet: a step that does NOT advance a declared goal is HELD (isolated)", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: [],
    initialState: [],
    goalFacts: [],
    steps: [step("a", { advancesGoal: "SOMETHING-ELSE", progressAfter: 1 })],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.holds.some((h) => h.startsWith("goal:step-off-goal")));
});

test("plan-vet: a DISPROPORTIONATE step (cost >> value) is HELD — over-reaction (isolated)", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: [],
    initialState: [],
    goalFacts: [],
    steps: [step("a", { predictedCost: 100, subProblemValue: 1, progressAfter: 1 })], // ratio 100 > 3
  };
  const v = vetPlan(plan, policy);
  // proportionality is a SOFT critic (heuristic, not sound): surfaced as an advisory, not a hard veto.
  assert.ok(v.softHolds.some((h) => h.startsWith("proportion:disproportionate")), "disproportion surfaced as soft advisory");
  assert.ok(!v.hardHolds.some((h) => h.startsWith("proportion")), "proportionality is not a hard veto");
});

test("plan-vet: a NO-PROGRESS LOOP is HELD — rabbit-hole (isolated)", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: [],
    initialState: [],
    goalFacts: [],
    steps: [
      step("a", { progressAfter: 5 }),
      step("b", { prerequisites: ["a"], progressAfter: 5 }), // no progress
      step("c", { prerequisites: ["b"], progressAfter: 5 }), // no progress → run reaches 2
    ],
  };
  const v = vetPlan(plan, policy);
  assert.ok(v.softHolds.some((h) => h.startsWith("proportion:no-progress-loop")), "rabbit-hole surfaced as soft advisory");
});

test("plan-vet: a REGRESSION step (undoes committed goal-serving work) is HELD (isolated)", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: ["done-1"],
    initialState: [],
    goalFacts: [],
    steps: [step("a", { undoes: ["done-1"], progressAfter: 1 })],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.holds.some((h) => h.startsWith("regression:undoes-committed")));
});

test("plan-vet: unknown declared fields ⇒ HOLD (fail-safe, isolated)", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: [],
    initialState: [],
    goalFacts: [],
    steps: [step("a", { advancesGoal: undefined, predictedCost: undefined, progressAfter: undefined })],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.holds.some((h) => h.includes("unknown")));
});

test("plan-vet: deny-overrides + NO MASKING — a plan failing TWO critics reports BOTH", () => {
  const plan: Plan = {
    goals: ["G"],
    committed: ["done-1"],
    initialState: [],
    goalFacts: [],
    steps: [
      step("a", { advancesGoal: "OFF", undoes: ["done-1"], progressAfter: 1 }), // off-goal AND regression
    ],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.holds.some((h) => h.startsWith("goal:step-off-goal")), "goal reason present");
  assert.ok(v.holds.some((h) => h.startsWith("regression:undoes-committed")), "regression reason present (not masked)");
});

test("plan-vet: a plan with NO declared goal ⇒ HOLD (fail-safe)", () => {
  const plan: Plan = { goals: [], committed: [], initialState: [], goalFacts: [], steps: [step("a", { advancesGoal: undefined })] };
  assert.equal(vetPlan(plan, policy).proceed, false);
});

// ---- HARDENING (red-team): state-simulation hard critic + hard/soft stratification + schema ----

test("plan-vet/sim: a step whose precondition is NOT established by the simulated state is HELD (isomorphic, not extensional)", () => {
  // the plan is well-ordered by DECLARATION, but step b needs fact 'F' that nothing establishes → internally inconsistent.
  const plan: Plan = {
    goals: ["G"], committed: [], initialState: [], goalFacts: [],
    steps: [
      step("a", { progressAfter: 1 }),
      step("b", { prerequisites: ["a"], requires: ["F"], progressAfter: 2 }), // needs F; never established
    ],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.hardHolds.some((h) => h.startsWith("sim:unmet-precondition:F")), "simulation catches the missing fact");
});

test("plan-vet/sim: a plan that does NOT achieve its goal facts is HELD (goal ACHIEVEMENT, not per-step tagging)", () => {
  const plan: Plan = {
    goals: ["G"], committed: [], initialState: [], goalFacts: ["done"],
    steps: [step("a", { establishes: ["something-else"], progressAfter: 1 })], // never establishes 'done'
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.hardHolds.some((h) => h === "sim:goal-not-achieved:done"));
});

test("plan-vet/sim: a plan whose steps establish the required facts in order ACHIEVES the goal and proceeds", () => {
  const plan: Plan = {
    goals: ["G"], committed: [], initialState: ["start"], goalFacts: ["done"],
    steps: [
      step("a", { requires: ["start"], establishes: ["mid"], progressAfter: 1 }),
      step("b", { prerequisites: ["a"], requires: ["mid"], establishes: ["done"], progressAfter: 2 }),
    ],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, true, "a simulable, goal-achieving plan proceeds");
  assert.equal(v.hardHolds.length, 0);
});

test("plan-vet/sim: unknown (undefined) preconditions ⇒ HOLD (fail-safe, isolated)", () => {
  const plan: Plan = {
    goals: ["G"], committed: [], initialState: [], goalFacts: [],
    steps: [step("a", { requires: undefined, progressAfter: 1 })],
  };
  assert.ok(vetPlan(plan, policy).hardHolds.some((h) => h.startsWith("sim:unknown-precondition")));
});

test("plan-vet/schema: a malformed plan (duplicate step id) HARD-holds and takes precedence", () => {
  const plan: Plan = {
    goals: ["G"], committed: [], initialState: [], goalFacts: [],
    steps: [step("dup", { progressAfter: 1 }), step("dup", { progressAfter: 2 })],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, false);
  assert.ok(v.hardHolds.some((h) => h.startsWith("schema:duplicate-step-id")));
});

test("plan-vet/stratify: a SOFT-only hold (disproportionate but sound-valid) still PROCEEDS with the advisory surfaced", () => {
  // hard-valid (simulable, goal-achieving, in-order, on-goal, no regression) but disproportionate cost.
  const plan: Plan = {
    goals: ["G"], committed: [], initialState: ["start"], goalFacts: ["done"],
    steps: [step("a", { requires: ["start"], establishes: ["done"], predictedCost: 100, subProblemValue: 1, progressAfter: 1 })],
  };
  const v = vetPlan(plan, policy);
  assert.equal(v.proceed, true, "a sound-valid plan proceeds even with a soft advisory");
  assert.ok(v.softHolds.some((h) => h.startsWith("proportion:disproportionate")), "the advisory is surfaced, not hidden");
});
