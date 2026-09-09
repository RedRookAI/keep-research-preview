/**
 * BUILD-ORDER 2.6 (ARM-THE-THIRD-CONSTRUCTION-SITE, Z138) — proves the DOCUMENTED-REFUSAL decision
 * at the synthetic-suite construction site. The measured evidence (offline, in-memory fixture; no
 * operator; no external effect on the governed surface) says a kill switch here is inert-by-
 * construction, so the honest exit is a durable, auditable, FAIL-CLOSED refusal record — not an
 * inert kill switch (control-theatre) and not a silent gap (drift).
 *
 * Each test is paired with a real isolating neuter (captured RED under
 * redrook-ops/.round-artifacts/ARM-THE-THIRD-CONSTRUCTION-SITE/):
 *  - REFUSE(a): the documented reason/revisit is REQUIRED   — neuter: allow an empty reason → RED.
 *  - REFUSE(b): the eval baseline outcomes are UNCHANGED     — neuter: break an instance outcome → RED.
 *  - WIRING:    the construction site AUDITS the refusal      — neuter: drop the stage() call → RED.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import {
  SyntheticSuite,
  SyntheticInstanceRunner,
  EVAL_KILL_SWITCH_REFUSAL,
  evalKillSwitchRefusalFact,
} from "../src/eval/synthetic_suite.js";
import { runSuite } from "../src/eval/harness.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-ks-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// ── REFUSE(a): a refusal with no recorded reason/revisit is drift — fail closed. ────────────────
test("Z138: eval kill-switch REFUSAL fails closed on an empty reason (a refusal with no reason is drift)", () => {
  assert.throws(
    () => evalKillSwitchRefusalFact({ ...EVAL_KILL_SWITCH_REFUSAL, reason: "   " }),
    /undocumented/i,
    "an empty reason must throw, never audit a hollow refusal",
  );
});

test("Z138: eval kill-switch REFUSAL fails closed on a missing revisit condition", () => {
  assert.throws(
    () => evalKillSwitchRefusalFact({ ...EVAL_KILL_SWITCH_REFUSAL, revisitWhen: "" }),
    /undocumented/i,
    "a refusal with no revisit trigger is a silent permanent gap — must throw",
  );
});

test("Z138: the populated refusal names the SPECIFIC measured reason and NEVER claims revocation is armed", () => {
  const fact = evalKillSwitchRefusalFact();
  assert.ok(fact.reason.trim().length > 0, "reason recorded");
  assert.ok(fact.revisitWhen.trim().length > 0, "revisit trigger recorded");
  // The SPECIFIC measured reason — offline / in-memory / no operator / no external effect.
  assert.match(fact.reason, /in-memory|offline|no network|no operator|no external effect/i);
  // HONESTY BOUND: the disposition names the deliberate ABSENCE; it must never claim the switch is armed.
  assert.match(fact.disposition, /refus|absent/i);
  assert.doesNotMatch(fact.disposition, /\barmed\b/i);
});

// ── REFUSE(b): the refusal record does not move any eval outcome — front-of-house unchanged. ────
test("Z138: the refusal record leaves the eval baseline outcomes UNCHANGED — calc+str resolve, math gives up (2 of 3)", async () => {
  const suite = new SyntheticSuite();
  const runner = new SyntheticInstanceRunner(); // no-identity / no-sink: the only way the suite is run
  const tasks = await suite.load();
  const spine = newSpine();
  const runs = await runSuite(tasks, runner, spine);
  assert.equal(runs.length, 3, "all three instances ran");
  assert.equal(
    runs.filter((r) => r.verdict.resolved).length,
    2,
    "calc + str resolve; math gives up — the refusal record changes no outcome",
  );
});

// ── WIRING: the construction site routes the refusal fact to an operator-visible spine on solve. ──
test("Z138 WIRING: the construction site audits the kill_switch.refused fact to the operator spine on every solve", async () => {
  const auditSpine = newSpine();
  const runner = new SyntheticInstanceRunner(auditSpine);
  const tasks = await new SyntheticSuite().load();
  await runner.solve(tasks[0]!);
  await auditSpine.seal();
  const events = auditSpine.replay().filter((e) => {
    const p = e.payload as Record<string, unknown>;
    return p["event"] === "kill_switch.refused";
  });
  assert.equal(events.length, 1, "the deliberately-absent kill switch is audited, not silent");
  const p = events[0]!.payload as Record<string, unknown>;
  assert.ok(String(p["reason"]).trim().length > 0, "the audited refusal carries its specific reason");
  assert.match(String(p["disposition"]), /refus|absent/i);
});

// ── Additive-only proof: supplying an audit sink does not change the eval OUTCOME. ──────────────
test("Z138: providing an audit sink is observe-only — the solve outcome is identical with or without it", async () => {
  const tasks = await new SyntheticSuite().load();
  const calc = tasks.find((t) => t.instanceId === "calc__add-subtracts")!;
  const withoutSink = await new SyntheticInstanceRunner().solve(calc);
  const withSink = await new SyntheticInstanceRunner(newSpine()).solve(calc);
  assert.equal(withSink.solved, withoutSink.solved, "the audit sink never changes whether the solve resolved");
  assert.deepEqual(withSink.stagesRun, withoutSink.stagesRun, "the audit sink never changes the trajectory");
});
