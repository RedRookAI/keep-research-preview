import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import { InMemoryWitnessSink } from "../src/spine/witness_sink.js";

/**
 * ROUND 5 (ledger L-INCIDENT-ON-TAMPER) — does a detected audit-chain tamper actually START the regulatory
 * clocks, or is the IncidentReporter dead machinery?
 *
 * MEASURED FIRST: `incidents.capture()` (governance_suite.ts / incident.ts) computes NIS2-24h / GDPR-72h /
 * AI-Act Art.73 deadlines — but had ZERO call sites in src. So a detected tamper started NO clock (the
 * guarantee existed but nothing fired it). This round fires `governanceSuite.incidents.capture("cyber-incident", …)`
 * when L20a's boot reconcile reports `diverged`. Composes with L20a.
 *
 * PROVEN-LIVE (harness A1). Disproof neuter: drop the `if (status==="diverged") incidents.capture(...)` block
 * -> TAMPER-FIRES-INCIDENT goes RED. NO-FALSE-INCIDENT guards against firing on a clean boot.
 */

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "keep-inc-"));
}
function incidentEvents(app: { spine: { replay(): readonly { payload: unknown }[] } }): Record<string, unknown>[] {
  return app.spine
    .replay()
    .map((e) => e.payload as Record<string, unknown> | undefined)
    .filter((p): p is Record<string, unknown> => p?.["event"] === "incident.captured");
}

test("TAMPER-FIRES-INCIDENT: a boot tamper auto-captures a cyber-incident and starts the NIS2 24h clock", async () => {
  const sink = new InMemoryWitnessSink();
  sink.publish({ seq: 5, cumulativeRoot: "a".repeat(64), headHash: "b".repeat(64) }); // ahead-witness the empty chain can't satisfy = tamper
  const app = composeKeep({ dataDir: tmp(), witnessSink: sink });
  assert.equal(app.witnessReconciliation.status, "diverged", "precondition: the boot reconcile detected the tamper");

  await app.spine.seal(); // the incident was staged at boot; seal it onto the chain
  const incidents = incidentEvents(app);
  assert.equal(incidents.length, 1, "exactly one incident.captured event was fired by the tamper");
  assert.equal(incidents[0]!["incidentType"], "cyber-incident", "an audit-chain tamper is a cyber-incident");
  const clocks = (incidents[0]!["deadlines"] as { clock: string }[]).map((d) => d.clock);
  assert.ok(clocks.includes("nis2-24h"), "the NIS2 24h regulatory clock was started");
  // SOTA 2026-08-19 correction: a bare integrity tamper must NOT auto-start the AI-Act Art.73 clock (needs a harm
  // outcome) nor GDPR (no personal data) — auto-starting either over-reports.
  assert.ok(!clocks.some((c) => c.startsWith("aiact")), "AI-Act Art.73 clock is NOT auto-started for a bare integrity tamper");
  assert.ok(!clocks.includes("gdpr-72h"), "GDPR clock is NOT auto-started (no personal data implicated)");
});

test("NO-FALSE-INCIDENT: a clean boot (unreconciled) fires NO regulatory incident", async () => {
  const app = composeKeep({ dataDir: tmp() }); // fresh — status `unreconciled`
  assert.notEqual(app.witnessReconciliation.status, "diverged");
  await app.spine.seal();
  assert.equal(incidentEvents(app).length, 0, "no incident.captured on a clean boot");
});
