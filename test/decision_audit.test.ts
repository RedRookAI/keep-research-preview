import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  auditDecision,
  toOtlp,
  emitDecisionAudit,
  InMemoryAuditSink,
  type OtlpExporter,
} from "../src/audit/decision_audit.js";
import { composeGate, defaultGatePolicy, type GateInputs, type GateRoute } from "../src/gate/composed_gate.js";
import { InMemoryFileTree, type FileTree } from "../src/solve/patch.js";
import { mediatedTree } from "../src/solve/mediated_tree.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { defaultFloorPolicy } from "../src/floor/structural_floor.js";
import { defaultBudgetPolicy } from "../src/budget/budget_ledger.js";
import { defaultAcceptanceTest } from "../src/ree/reversible_envelope.js";
import { executeReversibly, type ReversibleIntent, type IntegrationPolicies } from "../src/integrate/reversible_execution.js";

// Core Addition D — local-audit + OTLP. These prove every gate decision produces a faithful, DERIVED
// (not re-judged) audit record + OTLP shape, local-first, never altering the decision. Verify by disproof.

const allBarriers: GateInputs = {
  floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal",
  ownerPresent: true, provenance: "trusted", twin: "match", bomVerified: true, identityLive: true,
};

test("AUDIT: a decision produces a record with all eight barrier verdicts + route + reasons", () => {
  const decision = composeGate(allBarriers, defaultGatePolicy());
  const rec = auditDecision(allBarriers, decision);
  assert.equal(rec.route, "auto-proceed");
  for (const k of ["floor", "budget", "actionTier", "ownerPresent", "provenance", "twin", "bomVerified", "identityLive"] as const) {
    assert.ok(rec.barriers[k] !== undefined, `barrier ${k} present`);
  }
});

test("AUDIT: the record is DERIVED, not re-judged — an inconsistent route/reasons pair is reflected exactly", () => {
  // a hand-built decision whose route/reasons do NOT match what composeGate would compute for the inputs.
  const fabricated: GateRoute = { route: "human-hold", reasons: ["some-upstream-reason"] };
  const rec = auditDecision(allBarriers, fabricated); // inputs say all-green, decision says hold
  assert.equal(rec.route, "human-hold", "the audit reflects the GIVEN route, it did not recompute");
  assert.deepEqual(rec.reasons, ["some-upstream-reason"]);
});

test("AUDIT: the OTLP shape has traceId/spanId/severity/attributes", () => {
  const rec = auditDecision(allBarriers, composeGate(allBarriers, defaultGatePolicy()));
  const otlp = toOtlp(rec);
  assert.equal(otlp.eventName, "keep.gate.decision");
  assert.equal(otlp.severityText, "INFO");
  assert.equal(otlp.severityNumber, 9);
  assert.ok(otlp.traceId.length === 32 && otlp.spanId.length === 16);
  assert.equal(otlp.attributes["keep.gate.route"], "auto-proceed");
  assert.equal(otlp.attributes["keep.barrier.floor"], "reversible-execute");
});

test("AUDIT: a HOLD is WARN severity and carries its deciding reasons", () => {
  const held = composeGate({ ...allBarriers, twin: "mismatch" }, defaultGatePolicy());
  const otlp = toOtlp(auditDecision({ ...allBarriers, twin: "mismatch" }, held));
  assert.equal(otlp.severityText, "WARN");
  assert.equal(otlp.severityNumber, 13);
  assert.ok(otlp.body.includes("digital-twin-mismatch"));
});

test("AUDIT: local-first — works with NO exporter, records the drop, never throws", () => {
  const sink = new InMemoryAuditSink();
  const out = emitDecisionAudit(allBarriers, composeGate(allBarriers, defaultGatePolicy()), sink /* no exporter */);
  assert.equal(sink.records.length, 1, "the record was written locally");
  assert.equal(out.exportDropped, true, "no exporter ⇒ export dropped, but recorded");
});

test("AUDIT: a THROWING exporter never blocks — the drop is recorded, the local write stands", () => {
  const sink = new InMemoryAuditSink();
  const badExporter: OtlpExporter = { export: () => { throw new Error("collector down"); } };
  const out = emitDecisionAudit(allBarriers, composeGate(allBarriers, defaultGatePolicy()), sink, badExporter);
  assert.equal(sink.records.length, 1);
  assert.equal(out.exportDropped, true, "export failure recorded, not thrown");
});

test("AUDIT: a working exporter delivers and is not marked dropped", () => {
  const sink = new InMemoryAuditSink();
  const delivered: unknown[] = [];
  const good: OtlpExporter = { export: (o) => { delivered.push(o); } };
  const out = emitDecisionAudit(allBarriers, composeGate(allBarriers, defaultGatePolicy()), sink, good);
  assert.equal(delivered.length, 1);
  assert.equal(out.exportDropped, false);
});

// ── end-to-end: audit observes but never changes the route ──
function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "audit-spine-"))), new InProcessLock(), new SchemaRegistry());
}
test("AUDIT E2E: the audit sink receives the decision and the route is UNCHANGED by auditing", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree: FileTree = mediatedTree(inner);
  const policies: IntegrationPolicies = {
    floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest,
  };
  const sink = new InMemoryAuditSink();
  const intent: ReversibleIntent = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "new" },
    apply: async (t) => { await t.write("a.txt", "new"); },
    actionTier: "reversible-internal",
  };
  const res = await executeReversibly(intent, policies, {
    spine: newSpine(), actor: "t", operator: "o", sign: (p) => p, tree, ownerPresent: true, envelopeEnabled: true, auditSink: sink,
  });
  assert.equal(sink.records.length, 1, "the decision was audited");
  assert.equal(sink.records[0]!.record.route, "auto-proceed");
  assert.equal(res.path, "envelope", "auditing did not change the route");
});
