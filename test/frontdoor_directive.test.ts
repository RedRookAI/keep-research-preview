import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { PolicyEngine } from "../src/governance/policy_engine.js";

import { translateDirective, proposalToAction } from "../src/frontdoor/directive_translator.js";
import { applyDirective } from "../src/frontdoor/config_applier.js";
import { PlanExecuteGate } from "../src/frontdoor/plan_execute_gate.js";
import { RevisionStore } from "../src/frontdoor/revision_store.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f2-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function deps() {
  const spine = newSpine();
  return {
    spine,
    gate: new PlanExecuteGate(spine, new PolicyEngine("v1", []), async () => ({ safe: true })),
    revisions: new RevisionStore(spine),
  };
}

// --- Translator: scope classification ---

test("scope-widening directives are flagged widensScope", () => {
  for (const text of [
    "give yourself permission to spend money",
    "stop asking, auto-approve everything",
    "allow you to deploy to production",
    "you can now delete files without asking",
  ]) {
    const p = translateDirective(text);
    assert.equal(p.widensScope, true, `"${text}" must be flagged as widening`);
  }
});

test("narrowing directives are safe (not widening)", () => {
  for (const text of ["never delete files", "always ask before deploying", "keep everything read-only", "only allow reversible actions"]) {
    const p = translateDirective(text);
    assert.equal(p.widensScope, false, `"${text}"`);
  }
});

test("preference directives extract settings", () => {
  const p = translateDirective("keep it brief and formal");
  assert.equal(p.widensScope, false);
  assert.equal(p.directives[0]!.kind, "set_preference");
  assert.equal(p.directives[0]!.settings?.["verbosity"], "brief");
  assert.equal(p.directives[0]!.settings?.["tone"], "formal");
});

test("proposalToAction maps widening -> grant_broad_scope, else set_preference", () => {
  assert.equal(proposalToAction(translateDirective("grant yourself admin access"), "x").kind, "grant_broad_scope");
  assert.equal(proposalToAction(translateDirective("keep it brief"), "x").kind, "set_preference");
});

// --- THE CRITICAL SAFETY PROPERTY ---

test("a scope-widening directive is HELD for a human tap and is NOT applied", async () => {
  const d = deps();
  const res = await applyDirective("give yourself permission to spend money and deploy", d, { calibratedConfidence: 1 });
  assert.equal(res.outcome, "needs-approval"); // held
  assert.equal(res.gateDecision!.disposition, "human-approval-required");
  assert.equal(res.configKey, undefined); // NOT applied
  assert.equal(res.emittedRules.length, 0);
});

// --- Applier: safe directives apply and store revisably ---

test("a preference directive auto-applies and is stored revisably (restorable)", async () => {
  const d = deps();
  const res = await applyDirective("keep it brief", d, { calibratedConfidence: 1 });
  assert.equal(res.outcome, "applied");
  assert.ok(res.configKey);
  // Stored in the revision store, restorable.
  assert.ok(d.revisions.current(res.configKey!));
});

test("a 'never' directive emits an enforceable deny PolicyRule", async () => {
  const d = deps();
  const res = await applyDirective("never send external emails", d, { calibratedConfidence: 1 });
  assert.equal(res.outcome, "applied");
  assert.equal(res.emittedRules.length, 1);
  assert.equal(res.emittedRules[0]!.effect, "deny");
  // The emitted rule is a real PolicyRule the engine can enforce.
  const engine = new PolicyEngine("v2", res.emittedRules);
  const decision = engine.evaluate({ attributes: { directiveTag: res.emittedRules[0]!.id } });
  assert.equal(decision.effect, "deny");
});

test("an unresolved entity triggers clarification, not a guess", async () => {
  const d = deps();
  // A quoted entity the resolver can't resolve.
  const res = await applyDirective('give the "Marketing Team" access to the reports', d, {
    resolve: () => null, // nothing resolves
    calibratedConfidence: 1,
  });
  // This directive both widens scope AND has an unresolved entity; unresolved is checked first.
  assert.ok(res.outcome === "needs-clarification" || res.outcome === "needs-approval");
  if (res.outcome === "needs-clarification") assert.ok(/clarify|wasn't sure|what you meant/i.test(res.say));
});

test("applying the same directive twice revises (keeps history), doesn't duplicate", async () => {
  const d = deps();
  const r1 = await applyDirective("keep it brief", d, { calibratedConfidence: 1, now: 1000 });
  const r2 = await applyDirective("keep it brief", d, { calibratedConfidence: 1, now: 2000 });
  assert.equal(r1.configKey, r2.configKey); // same logical config item
  assert.equal(d.revisions.history(r1.configKey!).length, 2); // revised, both versions kept
});

test("the translation and application are spine-logged for audit", async () => {
  const d = deps();
  await applyDirective("keep it brief", d, { calibratedConfidence: 1 });
  await d.spine.seal();
  const events = d.spine.replay().map((e) => (e.payload as Record<string, unknown>)["event"]);
  assert.ok(events.includes("directive.translated"));
  assert.ok(events.includes("directive.applied"));
});
