import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { buildLearningSignals } from "../src/learning/learning_signals.js";
import type { Lesson } from "../src/memory/model.js";

function newSignals() {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-ls-"))), new InProcessLock(), new SchemaRegistry());
  return buildLearningSignals(spine, new ModelGateway(new LocalProvider()));
}
function lesson(id: string, tier: Lesson["tier"]): Lesson {
  return { id, content: "x", tier, origin: "external", provenanceEventId: "e" } as Lesson;
}

test("HUMAN CORRECTION → LESSON: a real edit-delta distills a generalized lesson into memory", async () => {
  const ls = newSignals();
  const distilled = await ls.recordEdit("const x = foo()", "const x = foo() ?? defaultValue", "src/auth.ts");
  assert.ok(distilled, "a lesson was distilled from the human's correction");
  assert.ok(distilled!.lesson.id, "it has an id in memory");
  assert.ok(distilled!.patternSignature, "and a pattern signature so recurrences of the PATTERN match (not the literal text)");
});

test("NO SIGNAL: an edit with no structural change distills nothing (no noise)", async () => {
  const ls = newSignals();
  const same = await ls.recordEdit("const x = 1", "const x = 1", "src/a.ts");
  assert.equal(same, undefined, "no correction → no lesson");
});

test("DISMISSAL → SUPPRESSION LESSON: a dismissed finding class is captured to stop resurfacing", async () => {
  const ls = newSignals();
  const l = await ls.recordDismissal("style", "single-vs-double-quotes", "src/ui.ts");
  assert.ok(l, "a suppression lesson was recorded");
  assert.match(l!.content, /down-weight/i);
});

test("LESSON BADGE (merge-readiness): only CONFIRMED lessons earn authority; probation informs but doesn't count", () => {
  const ls = newSignals();
  const badge = ls.lessonBadge([lesson("a", "confirmed"), lesson("b", "probation"), lesson("c", "confirmed")]);
  assert.equal(badge.confirmedCount, 2, "only the two confirmed lessons count");
  assert.deepEqual([...badge.lessonIds].sort(), ["a", "c"]);
  assert.match(badge.text, /2 confirmed lessons/);
});

test("SPEC-DRIFT (objective, never agent-judges-agent): failing spec tests = drift", () => {
  const ls = newSignals();
  const r = ls.specDrift({ approvedIntent: "add auth", requiredCapabilities: ["login"], changeSummary: "added login flow", testsPass: false });
  assert.equal(r.drifted, true);
  assert.match(r.reason, /tests fail/i);
});

test("SPEC-DRIFT: a required capability not evidenced in the change = drift", () => {
  const ls = newSignals();
  const r = ls.specDrift({ approvedIntent: "add auth with logout", requiredCapabilities: ["login", "logout"], changeSummary: "added login only", testsPass: true });
  assert.equal(r.drifted, true);
  assert.deepEqual([...r.missingCapabilities], ["logout"]);
});

test("SPEC-DRIFT: capabilities evidenced + tests pass = no drift", () => {
  const ls = newSignals();
  const r = ls.specDrift({ approvedIntent: "add login", requiredCapabilities: ["login"], changeSummary: "added login flow with tests", testsPass: true });
  assert.equal(r.drifted, false);
});

test("WIRE: composeKeep exposes the learning signals, and a captured edit lands in its memory", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-ls-wire-")) });
  assert.ok(app.learningSignals, "learning signals wired onto the app");
  const distilled = await app.learningSignals.recordEdit("return a+b", "return a + b // spacing", "src/m.ts");
  assert.ok(distilled, "a human correction distills a lesson through the composed app");
});
