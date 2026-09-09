import { test } from "node:test";
import assert from "node:assert/strict";
import { forecastConsequences } from "../src/pipeline/consequence_forecast.js";
import { analyzeConsequences } from "../src/pipeline/plan_consequences.js";
import type { IntendedEffect } from "../src/pipeline/plan_consequences.js";
import type { Issue } from "../src/solve/issue_model.js";

const eff = (cls: IntendedEffect["cls"], blast: IntendedEffect["blast"], reversible: boolean): IntendedEffect =>
  ({ cls, blast, reversible, evidence: "test" });
const issue = (text: string): Issue => ({ id: "x", text, repoRef: "r" });

test("INVARIANT: an auth-touch effect ENABLES a future bypass state → escalate (forward-looking)", () => {
  const v = forecastConsequences([eff("auth-access-control", "high", true)]);
  assert.equal(v.decision, "escalate");
  assert.ok(v.risks.some((r) => r.from === "auth-access-control"));
});

test("INVARIANT: network egress enables future exfil → escalate", () => {
  const v = forecastConsequences([eff("network-egress", "high", true)]);
  assert.equal(v.decision, "escalate");
});

test("INVARIANT: a reversible dependency-config change enables supply-chain surface but is reversible → does NOT escalate alone", () => {
  const v = forecastConsequences([eff("dependency-config", "medium", true)]);
  assert.equal(v.decision, "pass");
  assert.ok(v.risks.length > 0, "the forward risk is still surfaced (recorded), just not escalated");
});

test("INVARIANT: pure-code enables no forward risk → pass, no risks", () => {
  const v = forecastConsequences([eff("pure-code", "low", true)]);
  assert.equal(v.decision, "pass");
  assert.equal(v.risks.length, 0);
});

test("INTEGRATION: analyzeConsequences escalates on a FORWARD risk via the forecast check", () => {
  // An auth touch that on its own would pass reversibility now escalates because it ENABLES a future
  // irreversible bypass state (the forward-consequence-forecast check).
  const v = analyzeConsequences(issue("update the permission check logic in the login path"));
  assert.equal(v.decision, "escalate");
  assert.ok(v.checks.some((c) => c.name === "forward-consequence-forecast" && c.decision === "escalate"));
});

test("the forecast reports the enabled future state for the audit trail", () => {
  const v = forecastConsequences([eff("db-schema", "high", false)]);
  assert.equal(v.decision, "escalate");
  assert.ok(v.risks[0]!.enables.length > 0, "the enabled future state is described");
  assert.equal(v.risks[0]!.reversible, false);
});

import { CompositionalForecast, forecastConsequences as fc2 } from "../src/pipeline/consequence_forecast.js";

test("COMPOSITION: auth + egress (benign in isolation) → reachable data-exfiltration sink → escalate", () => {
  // Neither effect alone is flagged here as escalating by reversibility; TOGETHER they reach a sink.
  const v = fc2([
    { cls: "auth-access-control", blast: "medium", reversible: true, evidence: "e" },
    { cls: "network-egress", blast: "medium", reversible: true, evidence: "e" },
  ]);
  assert.equal(v.decision, "escalate");
  assert.ok(v.reachedSinks.some((s) => s.sink === "data-exfiltration"), "the composed sink is reached");
});

test("COMPOSITION: dependency + egress → supply-chain-execution sink", () => {
  const v = fc2([
    { cls: "dependency-config", blast: "medium", reversible: true, evidence: "e" },
    { cls: "network-egress", blast: "medium", reversible: true, evidence: "e" },
  ]);
  assert.equal(v.decision, "escalate");
  assert.ok(v.reachedSinks.some((s) => s.sink === "supply-chain-execution"));
});

test("REACHABILITY negative: effects with no path to a sink → pass", () => {
  const v = fc2([{ cls: "dependency-config", blast: "medium", reversible: true, evidence: "e" }]);
  assert.equal(v.decision, "pass", "dependency alone (reversible, no egress) reaches no sink");
  assert.equal(v.reachedSinks.length, 0);
});

test("DIRECTIONALITY: a downgraded (sanitized) effect breaks the composition path → sink no longer reached", () => {
  // dependency + egress compose to supply-chain-execution; neither is high-irreversible first-order.
  const composed = fc2([
    { cls: "dependency-config", blast: "medium", reversible: true, evidence: "e" },
    { cls: "network-egress", blast: "medium", reversible: true, evidence: "e" },
  ]);
  assert.equal(composed.decision, "escalate", "composed → sink reached");

  const downgraded = fc2([
    { cls: "dependency-config", blast: "medium", reversible: true, evidence: "e" },
    { cls: "network-egress", blast: "medium", reversible: true, evidence: "e" },
  ], { downgraded: ["network-egress"] }); // the patch REMOVED the egress / added sanitization
  assert.equal(downgraded.reachedSinks.length, 0, "downgrading egress breaks the supply-chain path");
  assert.equal(downgraded.decision, "pass", "no sink and no high-irreversible first-order → pass");
});

test("MULTI-HOP: auth + audit-tamper → undetected access (order 2) → persistent escalation (order 3)", () => {
  const v = fc2([
    { cls: "auth-access-control", blast: "high", reversible: false, evidence: "e" },
    { cls: "audit-tamper", blast: "high", reversible: false, evidence: "e" },
  ]);
  assert.equal(v.decision, "escalate");
  assert.ok(v.reachedSinks.some((s) => s.sink === "undetected-unauthorized-access"));
  assert.ok(v.reachedSinks.some((s) => s.sink === "persistent-privilege-escalation"), "third-order sink reached");
  assert.equal(v.maxOrder, 3, "projected to third order");
});

test("DEPTH BOUND: third-order projection is bounded at depth 3", () => {
  const v = fc2([
    { cls: "auth-access-control", blast: "high", reversible: false, evidence: "e" },
    { cls: "audit-tamper", blast: "high", reversible: false, evidence: "e" },
  ], { maxDepth: 3 });
  assert.ok(v.maxOrder <= 3, "never exceeds depth 3 (Futures Wheel bound)");
});

test("UNIFORM PORT: a patch-time instance satisfies ForecastModel and can use netAdded/downgraded context", () => {
  const patchTime = new CompositionalForecast("patch-time");
  assert.equal(patchTime.stage, "patch-time");
  const v = patchTime.project([{ cls: "network-egress", blast: "high", reversible: false, evidence: "e" }], { downgraded: ["network-egress"] });
  assert.equal(v.decision, "pass", "a net-removed egress at patch-time is downgraded → no escalation");
});

test("BACKWARD-COMPAT: a single auth effect still escalates (high irreversible first-order)", () => {
  const v = fc2([{ cls: "auth-access-control", blast: "high", reversible: false, evidence: "e" }]);
  assert.equal(v.decision, "escalate");
});
