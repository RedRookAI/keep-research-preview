import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { IncidentReporter } from "../src/governance/incident.js";

/**
 * FIX (SOTA 2026-08-19, filed from the R5 tri-formula backfill) — a CYBER-INCIDENT must not auto-start the EU
 * AI Act Art.73 clock (Art.73 needs a HARM OUTCOME; the Sept-2025 draft guidance excludes bare system-integrity
 * compromise) nor GDPR (only if personal data is implicated). NIS2 24h always applies. The clocks are CONDITIONAL.
 *
 * PROVEN-LIVE. Disproof neuter: make clocksFor's cyber-incident case return the AI-Act clock unconditionally ->
 * CYBER-INCIDENT-NIS2-ONLY reddens. The CONDITIONAL tests prove the clocks ARM when the outcome/personal-data
 * signals are present (so this is conditionality, not removal).
 */

function reporter(): IncidentReporter {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-clk-"))), new InProcessLock(), new SchemaRegistry());
  return new IncidentReporter(spine);
}
const clocksOf = (a: { deadlines: readonly { clock: string }[] }): string[] => a.deadlines.map((d) => d.clock);

test("CYBER-INCIDENT-NIS2-ONLY: a bare cyber-incident starts NIS2 only — no AI-Act, no GDPR", () => {
  const clocks = clocksOf(reporter().capture("cyber-incident", "audit-chain tamper"));
  assert.deepEqual(clocks, ["nis2-24h"], "bare integrity tamper = NIS2 only (no over-reporting)");
});

test("CONDITIONAL-AIACT: a cyber-incident that meets an Art.73 outcome DOES arm the AI-Act clock", () => {
  const clocks = clocksOf(reporter().capture("cyber-incident", "tamper w/ rights impact", { severity: { aiActSeriousIncident: true } }));
  assert.ok(clocks.includes("nis2-24h") && clocks.includes("aiact-15d"), "harm-outcome cyber-incident arms the AI-Act clock");
  const critical = clocksOf(reporter().capture("cyber-incident", "critical-infra", { severity: { widespreadOrCriticalInfra: true } }));
  assert.ok(critical.includes("aiact-2d-critical"), "critical-infra tightens the AI-Act clock to 2 days");
});

test("CONDITIONAL-GDPR: a cyber-incident implicating personal data arms the GDPR clock", () => {
  const clocks = clocksOf(reporter().capture("cyber-incident", "tamper touched PII", { severity: { personalDataImplicated: true } }));
  assert.ok(clocks.includes("nis2-24h") && clocks.includes("gdpr-72h"), "personal-data cyber-incident arms GDPR");
  assert.ok(!clocks.some((c) => c.startsWith("aiact")), "but not the AI-Act clock, absent a harm outcome");
});
