import { test } from "node:test";
import assert from "node:assert/strict";

import { estimateConsequence } from "../src/anticipate/consequence_estimator.js";

test("EXTERNALITY: an action that reaches the outside world is irreversible", () => {
  const e = estimateConsequence({ message: "email the client the final invoice" });
  assert.equal(e.consequence, "irreversible");
  assert.ok(e.signals.some((s) => s.axis === "externality"));
});

test("RECOVERABILITY: a local, revert-safe edit is reversible", () => {
  const e = estimateConsequence({ message: "rename a variable in my draft" });
  assert.equal(e.consequence, "reversible");
  assert.ok(e.signals.some((s) => s.axis === "recoverability"));
});

test("DESTRUCTIVE + BROAD: destroying broadly is irreversible", () => {
  const e = estimateConsequence({ message: "wipe all the records" });
  assert.equal(e.consequence, "irreversible");
});

test("ABSENT signals → unknown (precautionary, not silently reversible)", () => {
  const e = estimateConsequence({ message: "hmm, not sure yet" });
  assert.equal(e.consequence, "unknown");
  assert.equal(e.signals.length, 0);
});

test("CONFLICTING signals → unknown (external reach on a draft still can't be silently assumed safe)", () => {
  // 'draft' is recoverable, but 'email' reaches the world → external wins → irreversible, not a silent proceed.
  const e = estimateConsequence({ message: "email a draft to the whole list" });
  assert.equal(e.consequence, "irreversible");
  assert.ok(e.signals.some((s) => s.axis === "externality"));
});

test("STRUCTURED TARGET composes classifyRebuild (real-work destruction)", () => {
  // No destructive verb in the text, but the target is real deployed work → the rebuild classifier flags it.
  const e = estimateConsequence({ message: "change this", target: "deployment" });
  assert.equal(e.consequence, "irreversible");
});

test("a plain reversible target stays reversible", () => {
  const e = estimateConsequence({ message: "tweak this", target: "preference" });
  assert.equal(e.consequence, "reversible");
});
