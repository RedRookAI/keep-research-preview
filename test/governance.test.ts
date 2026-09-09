import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { PolicyEngine, type PolicyRule } from "../src/governance/policy_engine.js";
import { GovernanceLedger } from "../src/governance/decision_record.js";
import { ResidencyEnforcer } from "../src/governance/residency.js";
import { ComplianceExporter } from "../src/governance/evidence_pack.js";
import { IncidentReporter } from "../src/governance/incident.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-gov-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- Policy engine: deterministic, fail-closed, Article 5 non-overridable ---

test("policy engine is deterministic ALLOW when no rule matches", () => {
  const engine = new PolicyEngine("v1", []);
  const d = engine.evaluate({ model: "m" });
  assert.equal(d.effect, "allow");
});

test("policy engine FAILS CLOSED (deny) when a rule predicate throws", () => {
  const bad: PolicyRule = {
    id: "boom", effect: "allow", description: "throws",
    when: () => { throw new Error("predicate error"); },
  };
  const engine = new PolicyEngine("v1", [bad], false);
  const d = engine.evaluate({});
  assert.equal(d.effect, "deny");
  assert.equal(d.ruleId, "fail-closed");
});

test("Article 5 DENY is non-overridable even if an allow rule also matches", () => {
  const allowAll: PolicyRule = { id: "allow-all", effect: "allow", description: "allow", when: () => true };
  const engine = new PolicyEngine("v1", [allowAll]); // Article 5 auto-included
  const d = engine.evaluate({ contentFlags: ["csam"] });
  assert.equal(d.effect, "deny");
  assert.equal(d.ruleId, "article5.csam");
});

test("deny takes precedence over warn", () => {
  const warn: PolicyRule = { id: "w", effect: "warn", description: "warn", when: () => true };
  const deny: PolicyRule = { id: "d", effect: "deny", description: "deny", when: () => true };
  const engine = new PolicyEngine("v1", [warn, deny], false);
  assert.equal(engine.evaluate({}).effect, "deny");
});

// --- Governance record: the foundational artifact ---

test("governance record links action->policy->outcome and replays from the spine", () => {
  const spine = newSpine();
  const engine = new PolicyEngine("v1", []);
  const ledger = new GovernanceLedger(spine);
  const decision = engine.evaluate({ model: "m" });
  ledger.record({ action: "merge PR #12", actor: "agent-1", policy: decision, outcome: "proceeded" });
  const trail = ledger.readTrail();
  assert.equal(trail.length, 1);
  assert.equal(trail[0]!.action, "merge PR #12");
  assert.equal(trail[0]!.policy.policyVersion, "v1");
  assert.equal(trail[0]!.outcome, "proceeded");
});

test("governance trail is continuous across many decisions", () => {
  const spine = newSpine();
  const ledger = new GovernanceLedger(spine);
  const engine = new PolicyEngine("v1", []);
  for (let i = 0; i < 5; i++) {
    ledger.record({ action: `act-${i}`, actor: "a", policy: engine.evaluate({}), outcome: "proceeded" });
  }
  assert.equal(ledger.readTrail().length, 5);
});

// --- Residency + air-gap: hard DENY ---

test("residency denies a region outside the allowed set", () => {
  const enf = new ResidencyEnforcer({ allowedRegions: ["eu"], egressAllowlist: ["api.eu.example.com"] });
  assert.equal(enf.checkRegion("us").allowed, false);
  assert.equal(enf.checkRegion("eu").allowed, true);
});

test("egress allowlist denies non-allowlisted hosts", () => {
  const enf = new ResidencyEnforcer({ allowedRegions: ["eu"], egressAllowlist: ["ok.example.com"] });
  assert.equal(enf.checkEgress("evil.example.com").allowed, false);
  assert.equal(enf.checkEgress("ok.example.com").allowed, true);
});

test("air-gapped mode denies ALL egress (air-gap is enforced, not asserted)", () => {
  const enf = new ResidencyEnforcer({ allowedRegions: ["eu"], egressAllowlist: ["ok.example.com"], airGapped: true });
  assert.equal(enf.checkEgress("ok.example.com").allowed, false); // even allowlisted host denied
  assert.equal(enf.isAirGapped, true);
});

// --- Evidence pack: signed, offline-verifiable, tamper-detected, honesty-labeled ---

test("evidence pack is signed and verifies offline", () => {
  const key = randomBytes(32);
  const exporter = new ComplianceExporter("EU-AI-Act@2026-07-27", "Reg (EU) 2024/1689 as amended", key);
  const pack = exporter.buildPack([]);
  const signed = exporter.sign(pack);
  assert.equal(ComplianceExporter.verify(signed, key), true);
});

test("tampering with a signed pack breaks verification", () => {
  const key = randomBytes(32);
  const exporter = new ComplianceExporter("v", "basis", key);
  const signed = exporter.sign(exporter.buildPack([]));
  const tampered = { ...signed, pack: { ...signed.pack, decisionCount: 999 } };
  assert.equal(ComplianceExporter.verify(tampered, key), false);
});

test("a wrong key fails verification", () => {
  const exporter = new ComplianceExporter("v", "basis", randomBytes(32));
  const signed = exporter.sign(exporter.buildPack([]));
  assert.equal(ComplianceExporter.verify(signed, randomBytes(32)), false);
});

test("evidence pack ALWAYS carries the audit-ready-not-certified disclaimer + crosswalks", () => {
  const exporter = new ComplianceExporter("v", "basis", randomBytes(32));
  const pack = exporter.buildPack([]);
  assert.ok(pack.disclaimer.includes("NOT CERTIFIED"));
  assert.ok(pack.controls.length > 0);
  assert.ok(pack.controls.every((c) => c.crosswalk.nistAiRmf || c.crosswalk.iso42001)); // map-once-comply-across
});

// --- Incident hooks: multi-clock deadlines ---

test("a personal-data breach carries the 72h GDPR and 15-day AI Act clocks", () => {
  const spine = newSpine();
  const reporter = new IncidentReporter(spine, () => 0);
  const incident = reporter.capture("personal-data-breach", "PII leaked in a prompt");
  const clocks = incident.deadlines.map((d) => d.clock).sort();
  assert.deepEqual(clocks, ["aiact-15d", "gdpr-72h"]);
  const gdpr = incident.deadlines.find((d) => d.clock === "gdpr-72h")!;
  assert.equal(gdpr.dueTs, 72 * 3600 * 1000); // 72h from detection at t=0
});

test("a cyber incident carries the 24h NIS2 clock and the soonest deadline is 24h", () => {
  const spine = newSpine();
  const reporter = new IncidentReporter(spine, () => 0);
  const incident = reporter.capture("cyber-incident", "intrusion detected");
  const soonest = reporter.soonestDeadline(incident)!;
  assert.equal(soonest.clock, "nis2-24h");
  assert.equal(soonest.hours, 24);
});

test("incidents are recorded to the spine trail", () => {
  const spine = newSpine();
  const reporter = new IncidentReporter(spine);
  reporter.capture("containment-activated", "kill-switch fired");
  const events = spine.currentEvents().filter((e) => (e.payload as Record<string, unknown>)["event"] === "incident.captured");
  assert.equal(events.length, 1);
});
