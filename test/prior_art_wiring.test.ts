import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { PriorArtInput } from "../src/currency/prior_art.js";

// WIRING PROOF (P0-A #6): the anti-reinvention prior-art check is reachable + consulted during planning.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-pa-")) }).secondBrain;
}
const agentGoal: PriorArtInput = { goal: "build a self-hosted agent gateway", keywords: ["agent", "gateway"] };

test("composeKeep exposes the prior-art check", () => {
  assert.equal(typeof sb().checkPriorArt, "function");
});

test("a plannable need surfaces existing options (don't reinvent the wheel)", async () => {
  const report = await sb().checkPriorArt(agentGoal);
  const names = report.options.map((o) => o.name);
  assert.ok(names.includes("OpenClaw"), "surfaces OpenClaw as an existing option");
  assert.equal(report.verdict, "adopt", "a free existing option ⇒ recommend adopt, not rebuild");
});

test("the recommendation is ADVISORY (names options for the human, never auto-adopts)", async () => {
  const report = await sb().checkPriorArt(agentGoal);
  assert.ok(report.recommendation.length > 0, "a plain-language advisory recommendation is present");
  assert.match(report.recommendation, /OpenClaw|Hermes/, "it names the existing options for the human to choose");
});

test("honest currency: with no live search the report is verified:false (never fabricates currency)", async () => {
  const report = await sb().checkPriorArt(agentGoal); // no search dep passed
  assert.equal(report.verified, false, "it does not claim to have verified currency it couldn't");
  assert.ok(report.caveat, "an honest staleness caveat is present");
});

test("a core differentiator favors build/combine (doesn't blindly adopt)", async () => {
  const report = await sb().checkPriorArt({ ...agentGoal, isCoreDifferentiator: true });
  assert.notEqual(report.verdict, "adopt", "the user's differentiating core is not outsourced wholesale");
});

test("deterministic: same input ⇒ same verdict", async () => {
  const a = await sb().checkPriorArt(agentGoal);
  const b = await sb().checkPriorArt(agentGoal);
  assert.equal(a.verdict, b.verdict);
});
