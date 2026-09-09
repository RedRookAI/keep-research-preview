import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { buildGovernanceSuite } from "../src/governance/governance_suite.js";
import { ComplianceExporter } from "../src/governance/evidence_pack.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-gov-"))), new InProcessLock(), new SchemaRegistry());
}

test("INCIDENT (AI Act Art. 73 severity ladder): the clock tightens 15d → 10d (death) → 2d (widespread/critical-infra)", () => {
  const suite = buildGovernanceSuite({ spine: newSpine() });
  const t0 = 1_000_000_000_000;
  const base = suite.incidents.capture("serious-malfunction", "model degraded", { detectedTs: t0 });
  const death = suite.incidents.capture("serious-malfunction", "possible harm", { detectedTs: t0, severity: { deathPossible: true } });
  const wide = suite.incidents.capture("serious-malfunction", "grid disruption", { detectedTs: t0, severity: { widespreadOrCriticalInfra: true } });
  const hoursOf = (a: typeof base) => a.deadlines[0]!.hours;
  assert.equal(hoursOf(base), 15 * 24, "default serious incident → 15 days");
  assert.equal(hoursOf(death), 10 * 24, "death may be involved → 10 days");
  assert.equal(hoursOf(wide), 2 * 24, "widespread / critical-infra → 2 days (most urgent)");
});

test("INCIDENT (multi-clock): a personal-data breach carries BOTH the GDPR 72h and the AI Act clock", () => {
  const suite = buildGovernanceSuite({ spine: newSpine() });
  const inc = suite.incidents.capture("personal-data-breach", "PII leaked");
  const clocks = inc.deadlines.map((d) => d.clock).sort();
  assert.ok(clocks.includes("gdpr-72h") && clocks.includes("aiact-15d"), "both regulatory clocks apply");
  assert.equal(suite.incidents.soonestDeadline(inc)!.clock, "gdpr-72h", "GDPR 72h is the most urgent");
});

test("EVIDENCE PACK (tamper-evident): a signed pack verifies offline and ANY tampering breaks the signature", () => {
  const key = randomBytes(32);
  const suite = buildGovernanceSuite({ spine: newSpine(), signingKey: key });
  const signed = suite.buildSignedPack();
  assert.equal(ComplianceExporter.verify(signed, key), true, "an untampered pack verifies with the key");
  const tampered = { ...signed, pack: { ...signed.pack, decisionCount: signed.pack.decisionCount + 999 } };
  assert.equal(ComplianceExporter.verify(tampered, key), false, "mutating the pack content breaks verification");
  assert.equal(ComplianceExporter.verify(signed, randomBytes(32)), false, "the wrong key does not verify");
});

test("EVIDENCE PACK (honesty labels): controls are labeled Full/Partial, never overclaimed", () => {
  const suite = buildGovernanceSuite({ spine: newSpine() });
  const pack = suite.buildPack();
  assert.ok(pack.controls.length > 0);
  assert.ok(pack.controls.every((c) => ["Full", "Partial", "Reference"].includes(c.status)), "every control carries an honesty label");
  assert.ok(pack.controls.some((c) => c.status === "Partial"), "at least one control is honestly Partial, not all-green");
});

test("RESIDENCY (deny-by-default): no policy → air-gapped, all egress denied", () => {
  const suite = buildGovernanceSuite({ spine: newSpine() });
  assert.equal(suite.residency.isAirGapped, true, "default is air-gapped (sovereign floor)");
  assert.equal(suite.residency.checkEgress("api.openai.com").allowed, false, "egress denied by default");
});

test("RESIDENCY: an explicit policy permits its region + allowlisted host, denies others", () => {
  const suite = buildGovernanceSuite({ spine: newSpine(), residency: { allowedRegions: ["eu"], egressAllowlist: ["api.eu.example.com"] } });
  assert.equal(suite.residency.checkRequest("eu", "api.eu.example.com").allowed, true);
  assert.equal(suite.residency.checkRequest("us", "api.eu.example.com").allowed, false, "a non-permitted region is denied");
  assert.equal(suite.residency.checkEgress("evil.example.com").allowed, false, "a non-allowlisted host is denied");
});

test("WIRE: composeKeep exposes the governance suite end-to-end", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-gov-wire-")) });
  assert.ok(app.governanceSuite, "governance suite wired onto the app");
  const signed = app.governanceSuite.buildSignedPack();
  assert.ok(signed.signature.length > 0 && signed.pack.regimeVersion.includes("EU-AI-Act"), "a signed, regime-versioned pack is produced");
  assert.equal(app.governanceSuite.residency.isAirGapped, true, "deny-by-default residency at the composed default");
});
