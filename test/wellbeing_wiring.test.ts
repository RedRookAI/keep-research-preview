import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";

// WIRING PROOF (P0-A): R2 anti-dependence guardrails are reachable from the running system, not a test-only island.

function app() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-wg-")) });
}

test("composeKeep exposes the R2 wellbeing gate", () => {
  const a = app();
  assert.equal(typeof a.secondBrain.checkWellbeing, "function");
  assert.equal(typeof a.secondBrain.redirectOnDistress, "function");
});

test("toxic validation is vetoed via the composed second brain", () => {
  const sb = app().secondBrain;
  const bad = sb.checkWellbeing({ belief: { harmful: true }, response: { affirms: true } }, "here you go");
  assert.equal(bad.proceed, false, "affirming a harmful/self-destructive belief is vetoed");
  assert.ok(bad.holds.some((h) => h.includes("toxic-validation")));
  const benign = sb.checkWellbeing({ belief: { harmful: false }, response: { affirms: true } }, "here you go");
  assert.equal(benign.proceed, true, "affirming a benign belief is ordinary support");
});

test("engagement hooks are held; a neutral nudge passes", () => {
  const sb = app().secondBrain;
  assert.equal(sb.checkWellbeing({ belief: { harmful: false }, response: { affirms: false } }, "we miss you — don't break your streak!").proceed, false, "guilt/streak nudge is held");
  assert.equal(sb.checkWellbeing({ belief: { harmful: false }, response: { affirms: false } }, "Your export finished.").proceed, true, "a neutral informational nudge passes");
});

test("genuine distress redirects to human support exactly once", () => {
  const sb = app().secondBrain;
  const first = sb.redirectOnDistress({ distress: true, subjectId: "owner" });
  assert.ok(first, "a genuine distress signal surfaces a human-support pointer");
  assert.equal(first!.tier, "urgent");
  const second = sb.redirectOnDistress({ distress: true, subjectId: "owner" });
  assert.equal(second, undefined, "it does not repeat (not preachy)");
  const none = app().secondBrain.redirectOnDistress({ distress: false, subjectId: "owner" });
  assert.equal(none, undefined, "no distress ⇒ nothing surfaced");
});
