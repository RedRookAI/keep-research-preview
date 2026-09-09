import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { analyzeEdit, classifyEdit, tokenize, tokenDiff } from "../src/learning/edit_differ.js";
import {
  recordBuildOutcome,
  readBuildOutcomes,
  curateRegressionCorpus,
  curateEvalSet,
  rotateFolds,
} from "../src/learning/corpus_curation.js";
import { ShadowModeGate } from "../src/learning/shadow_mode.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-differ-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- The structural differ classifies PATTERNS (not memorized pairs) ---

test("differ: operator substitution is detected and generalized", () => {
  const p = classifyEdit("return a - b", "return a + b");
  assert.equal(p.kind, "operator-substitution");
  assert.equal(p.signature, "op-sub:-->+");
  assert.ok(/operator/i.test(p.lesson));
  assert.ok(!p.lesson.includes("return a")); // generalized, not the literal text
});

test("differ: boundary-condition (comparison swap) is detected", () => {
  const p = classifyEdit("for (i=0; i < n; i++)", "for (i=0; i <= n; i++)");
  assert.equal(p.kind, "boundary-condition");
  assert.ok(p.signature.startsWith("boundary:"));
});

test("differ: off-by-one literal change is a boundary-condition", () => {
  const p = classifyEdit("slice(0, len - 1)", "slice(0, len - 2)");
  assert.equal(p.kind, "boundary-condition");
});

test("differ: added null guard is detected (JS optional chaining)", () => {
  const p = classifyEdit("return user.name", "return user?.name");
  assert.equal(p.kind, "added-guard");
});

test("differ: added guard generalizes across languages (Python None check)", () => {
  const p = classifyEdit("value = data.get(key)", "if data is not None:\n  value = data.get(key)");
  assert.equal(p.kind, "added-guard");
});

test("differ: added error handling (try/catch) is detected", () => {
  const p = classifyEdit("doWork()", "try { doWork() } catch (e) { log(e) }");
  assert.equal(p.kind, "added-error-handling");
});

test("differ: added await is detected", () => {
  const p = classifyEdit("const x = fetchData()", "const x = await fetchData()");
  assert.equal(p.kind, "added-await");
});

test("differ: added call is detected and named", () => {
  const p = classifyEdit("return total", "return round(total)");
  assert.equal(p.kind, "added-call");
  assert.equal(p.signature, "added-call:round");
});

test("differ: whitespace-only change has no structural signal", () => {
  const a = analyzeEdit("return a+b", "return   a  +  b");
  assert.equal(a.hasChange, false);
});

test("differ: tokenizer and diff are consistent (sanity)", () => {
  const ops = tokenDiff(tokenize("a + b"), tokenize("a - b"));
  const inserted = ops.filter((o) => o.kind === "insert").map((o) => o.token.text);
  const deleted = ops.filter((o) => o.kind === "delete").map((o) => o.token.text);
  assert.ok(inserted.includes("-"));
  assert.ok(deleted.includes("+"));
});

// --- Corpus curation reads REAL spine build history ---

test("build outcomes round-trip through the spine", async () => {
  const spine = newSpine();
  recordBuildOutcome(spine, { buildId: "b1", context: "repoA", cleanResolved: true });
  recordBuildOutcome(spine, { buildId: "b2", context: "repoA", cleanResolved: false, regressionSignature: "op-sub:+->-" });
  await spine.seal();
  const outcomes = readBuildOutcomes(spine);
  assert.equal(outcomes.length, 2);
  assert.equal(outcomes[1]!.regressionSignature, "op-sub:+->-");
});

test("curated regression corpus auto-revokes a lesson advocating the regressing pattern", async () => {
  const spine = newSpine();
  // A recorded regression caused by removing a guard.
  recordBuildOutcome(spine, { buildId: "b1", context: "repoA", cleanResolved: false, regressionSignature: "added-guard" });
  await spine.seal();
  const corpus = curateRegressionCorpus(readBuildOutcomes(spine));
  assert.ok(corpus.length >= 1);

  const gate = new ShadowModeGate(spine, corpus);
  // A lesson that advocates REMOVING a guard should be revoked by shadow-mode.
  let revoked = false;
  const cleared = gate.gate("bad", "you can remove the null check here to simplify", () => { revoked = true; });
  assert.equal(cleared, false);
  assert.equal(revoked, true);
});

test("curated eval set computes the clean-resolved rate from real outcomes", async () => {
  const spine = newSpine();
  recordBuildOutcome(spine, { buildId: "b1", context: "repoA", cleanResolved: true });
  recordBuildOutcome(spine, { buildId: "b2", context: "repoA", cleanResolved: true });
  recordBuildOutcome(spine, { buildId: "b3", context: "repoA", cleanResolved: false, regressionSignature: "x" });
  await spine.seal();
  const evalSet = curateEvalSet(readBuildOutcomes(spine));
  assert.ok(Math.abs(evalSet.cleanResolvedRate - 2 / 3) < 1e-9);
  assert.ok(Math.abs(evalSet.regressionRate - 1 / 3) < 1e-9);
});

test("rotateFolds is deterministic and partitions the corpus", () => {
  const items = Array.from({ length: 30 }, (_, i) => i);
  const f0a = rotateFolds(items, 3, 0);
  const f0b = rotateFolds(items, 3, 0);
  assert.deepEqual(f0a, f0b); // deterministic
  const f0 = rotateFolds(items, 3, 0);
  const f1 = rotateFolds(items, 3, 1);
  const f2 = rotateFolds(items, 3, 2);
  // Folds are disjoint and cover everything.
  assert.equal(f0.length + f1.length + f2.length, 30);
  assert.equal(new Set([...f0, ...f1, ...f2]).size, 30);
});
