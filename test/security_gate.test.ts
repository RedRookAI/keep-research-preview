import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep, type KeepApp } from "../src/compose.js";
import { runCli } from "../src/cli/cli_core.js";
import { authorizeSecurityCritical } from "../src/identity/security_gate.js";
import { OWNER, type Principal } from "../src/identity/rbac.js";

function app(over: Record<string, unknown> = {}): KeepApp {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-sod-")), ...over });
}
const deps = (a: KeepApp) => ({ authorization: a.authorization, separationOfDuties: a.separationOfDuties, spine: a.spine });
const payloads = (a: KeepApp) => a.spine.currentEvents().map((e) => e.payload as Record<string, unknown>);
function makeCandidate(a: KeepApp, cls: string): void {
  for (let i = 0; i < 12; i++) { a.calibrationWire.recordDecision(cls, true, true); a.calibrationWire.observeOutcome(cls, "clean"); }
}

test("SoD N=1: reducing oversight REQUIRES step-up — without it, refused and audited", () => {
  const a = app();
  const out = authorizeSecurityCritical(deps(a), { action: "calibration.reduce_escalation", author: OWNER, stepUpVerified: false, now: 1 });
  assert.equal(out.ok, false);
  assert.match(out.reason!, /step-up/);
  assert.ok(payloads(a).some((p) => p["event"] === "sod.denied"), "denial audited on the spine");
});

test("SoD N=1: with step-up → authorized, and the dual-control approval is recorded to the spine", () => {
  const a = app();
  const out = authorizeSecurityCritical(deps(a), { action: "calibration.reduce_escalation", author: OWNER, stepUpVerified: true, now: 1 });
  assert.equal(out.ok, true);
  const rec = payloads(a).find((p) => p["event"] === "sod.approved");
  assert.equal(rec!["action"], "calibration.reduce_escalation");
  assert.equal(rec!["stepUpVerified"], true);
  assert.equal(rec!["mode"], "single-operator");
});

test("SoD gate: RBAC runs FIRST — a role without the permission is refused before dual-control", () => {
  const a = app();
  const viewer: Principal = { id: "v", kind: "human", role: "viewer" };
  const out = authorizeSecurityCritical(deps(a), { action: "calibration.reduce_escalation", author: viewer, stepUpVerified: true, now: 1 });
  assert.equal(out.ok, false);
  assert.ok(payloads(a).some((p) => p["event"] === "authz.denied" && p["layer"] === "rbac"), "refused at the RBAC layer");
  assert.equal(payloads(a).some((p) => p["event"] === "sod.approved"), false, "SoD never reached");
});

test("SoD multi-operator (N=2): needs two distinct approvers — the author alone is refused", () => {
  const a = app({ operators: [{ id: "owner", isOperator: true, displayName: "Owner" }, { id: "sam", isOperator: true, displayName: "Sam" }], sodN: 2 });
  const solo = authorizeSecurityCritical(deps(a), { action: "calibration.reduce_escalation", author: OWNER, approvers: ["owner"], stepUpVerified: true, now: 1 });
  assert.equal(solo.ok, false, "one approver is not enough when N=2");
  const dual = authorizeSecurityCritical(deps(a), { action: "calibration.reduce_escalation", author: OWNER, approvers: ["owner", "sam"], stepUpVerified: true, now: 2 });
  assert.equal(dual.ok, true);
  assert.ok(payloads(a).find((p) => p["event"] === "sod.approved" && p["mode"] === "multi-operator"));
});

test("CLI: `keep calibration authorize <cls>` is refused without --step-up (no policy activated)", async () => {
  const a = app();
  makeCandidate(a, "low");
  const out: string[] = [];
  await runCli(["calibration", "authorize", "low"], { write: (s: string) => out.push(s), prompt: async () => "" }, { app: a });
  assert.match(out.join("\n"), /step-up/);
  assert.equal(a.calibrationWire.activePolicyGates().has("low"), false, "no reduction was applied");
});

test("CLI: `keep calibration authorize low --step-up` authorizes with dual-control recorded on the spine", async () => {
  const a = app();
  makeCandidate(a, "low");
  assert.ok(a.calibrationWire.pendingReductions().includes("low"), "precondition: 'low' is a reduce candidate");
  const out: string[] = [];
  await runCli(["calibration", "authorize", "low", "--step-up"], { write: (s: string) => out.push(s), prompt: async () => "" }, { app: a });
  assert.match(out.join("\n"), /Authorized reduced escalation/);
  assert.equal(a.calibrationWire.activePolicyGates().has("low"), true, "reduction applied");
  assert.ok(payloads(a).some((p) => p["event"] === "sod.approved" && p["action"] === "calibration.reduce_escalation"));
});
