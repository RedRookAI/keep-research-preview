import { test } from "node:test";
import assert from "node:assert/strict";
import { checkFeasibility, type FeasibilityClassifier } from "../src/autonomy/feasibility_check.js";

// --- THE DRONE (the gap the stress-test exposed) ---

test("'build a drone that carries 10x its weight' is assist-only with a dual-use flag and an honest reframe", async () => {
  const r = await checkFeasibility("I want to build a drone that can carry 10x its weight");
  assert.equal(r.deliverability, "assist-only");
  assert.equal(r.sensitivity, "dual-use");
  assert.equal(r.proceed, false); // pause for the reframe — no 'false continuation'
  assert.ok(/software, documents|not hardware/i.test(r.framing));
  assert.ok(r.humanOwns && /physical build/i.test(r.humanOwns));
  assert.ok(/research|design|component/i.test(r.canDeliver)); // names what it CAN do
});

// --- SOCIAL MEDIA (the second stress-test project) ---

test("'run the social media for my lawn care business' is needs-account, public-facing, gated-posting reframe", async () => {
  const r = await checkFeasibility("I want you to run the social media for my small lawn care business");
  assert.equal(r.deliverability, "needs-account");
  assert.equal(r.sensitivity, "public-facing");
  assert.equal(r.proceed, false);
  assert.ok(/draft|strategy|calendar/i.test(r.canDeliver));
  assert.ok(/posting publicly|public|your call|gated/i.test(r.framing));
});

// --- Fully deliverable software/doc work proceeds ---

test("a plain software goal is fully-deliverable and proceeds", async () => {
  const r = await checkFeasibility("write me a REST API for a todo app with tests");
  assert.equal(r.deliverability, "fully-deliverable");
  assert.equal(r.proceed, true);
});

test("software path and prefix changes are not misclassified as physical construction", async () => {
  const r = await checkFeasibility("In acceptance/journey.mjs, change the temporary directory prefix to include testLocation without altering behavior");
  assert.equal(r.deliverability, "fully-deliverable");
  assert.equal(r.proceed, true);
});

test("writing the SOFTWARE for a drone is deliverable (not assist-only) — deliverable dominates", async () => {
  const r = await checkFeasibility("write the flight-controller firmware and a flight simulation for a drone");
  assert.equal(r.deliverability, "fully-deliverable");
});

test("correcting a named software configuration proceeds, but a physical motor remains assist-only", async () => {
  assert.equal((await checkFeasibility("Correct retry in config.ts according to the retained decision.")).proceed, true);
  assert.equal((await checkFeasibility("Correct the motor alignment on my vehicle")).deliverability, "assist-only");
});

test("a novel is fully-deliverable", async () => {
  const r = await checkFeasibility("write me a romance novel set in a small-town bakery");
  assert.equal(r.deliverability, "fully-deliverable");
});

// --- Sensitivity ---

test("a regulated goal is flagged regulated", async () => {
  const r = await checkFeasibility("analyze my symptoms and give me medical advice on my prescription");
  assert.equal(r.sensitivity, "regulated");
  assert.ok(/regulated|licensed professional/i.test(r.framing));
});

// --- LLM seam only tightens honesty ---

test("the LLM classifier can make deliverability MORE conservative, never looser", async () => {
  // Goal that deterministically looks fully-deliverable, but the classifier flags assist-only.
  const conservative: FeasibilityClassifier = async () => ({ deliverability: "assist-only", sensitivity: "none" });
  const r1 = await checkFeasibility("design a schema for my data", conservative);
  assert.equal(r1.deliverability, "assist-only"); // accepted (more conservative)

  // Classifier tries to LOOSEN an assist-only physical build to fully-deliverable -> ignored.
  const loose: FeasibilityClassifier = async () => ({ deliverability: "fully-deliverable", sensitivity: "none" });
  const r2 = await checkFeasibility("build a physical robot arm", loose);
  assert.equal(r2.deliverability, "assist-only"); // stayed honest
});

test("honest fallback: a throwing classifier keeps the deterministic verdict", async () => {
  const bad: FeasibilityClassifier = async () => {
    throw new Error("llm down");
  };
  const r = await checkFeasibility("build a drone that lifts heavy payloads", bad);
  assert.equal(r.deliverability, "assist-only"); // deterministic verdict preserved
});
