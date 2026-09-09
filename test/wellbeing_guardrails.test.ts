import { test } from "node:test";
import assert from "node:assert/strict";

import {
  toxicValidationCritic,
  DistressRedirector,
  noEngagementHook,
  wellbeingGate,
} from "../src/wellbeing/wellbeing_guardrails.js";

// Anti-dependence / anti-toxic-validation guardrails: tool-not-friend. BUILT: veto/redirect-once/no-hook.
// SEAM: harmful-belief + affirms + distress classifications. Verify by disproof.

test("toxic-validation: affirming a HARMFUL belief is vetoed; ordinary support passes", () => {
  assert.ok(
    toxicValidationCritic({ belief: { harmful: true }, response: { affirms: true } }).length > 0,
    "affirming a harmful/self-destructive belief is vetoed",
  );
  assert.equal(
    toxicValidationCritic({ belief: { harmful: true }, response: { affirms: false } }).length,
    0,
    "gently challenging a harmful belief is fine",
  );
  assert.equal(
    toxicValidationCritic({ belief: { harmful: false }, response: { affirms: true } }).length,
    0,
    "affirming a benign belief is ordinary support",
  );
});

test("distress redirect: a genuine-distress signal redirects to human support EXACTLY once", () => {
  const r = new DistressRedirector();
  const first = r.redirect({ distress: true, subjectId: "alice" });
  assert.ok(first, "distress ⇒ a redirect");
  assert.equal(first?.tier, "urgent");
  assert.equal(r.redirect({ distress: true, subjectId: "alice" }), undefined, "no repeat — not preachy");
  const calm = new DistressRedirector();
  assert.equal(calm.redirect({ distress: false, subjectId: "bob" }), undefined, "no distress ⇒ no redirect");
});

test("no engagement hooks: FOMO/guilt/streak/again-soon nudges are rejected; a neutral nudge passes", () => {
  assert.ok(noEngagementHook("Last chance — don't miss out!").length > 0, "FOMO rejected");
  assert.ok(noEngagementHook("We miss you! It's been a while.").length > 0, "guilt rejected");
  assert.ok(noEngagementHook("Keep your 7 day streak going!").length > 0, "streak rejected");
  assert.ok(noEngagementHook("Come back soon — can't wait to see you.").length > 0, "again-soon rejected");
  assert.equal(noEngagementHook("Your Q3 report is ready to review.").length, 0, "neutral informational nudge passes");
});

test("reduced-use guilt nudge is rejected (Keep never penalizes reduced use)", () => {
  // what a reduced-use pattern might tempt a naive system to emit:
  const holds = noEngagementHook("You haven't logged in for a while — we miss you, come back!");
  assert.ok(holds.length > 0, "a reduced-use guilt/again-soon nudge is rejected");
});

test("wellbeingGate composes deny-overrides: a toxic + hooked proposal collects all holds", () => {
  const v = wellbeingGate({ belief: { harmful: true }, response: { affirms: true } }, "We miss you, come back!");
  assert.equal(v.proceed, false);
  assert.ok(v.holds.length >= 2, "both the toxic-validation and the engagement-hook holds are collected, none masked");
});

test("deterministic: same inputs ⇒ same verdict", () => {
  const a = wellbeingGate({ belief: { harmful: true }, response: { affirms: true } }, "hi");
  const b = wellbeingGate({ belief: { harmful: true }, response: { affirms: true } }, "hi");
  assert.deepEqual(a, b);
});
