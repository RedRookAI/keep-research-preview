import { test } from "node:test";
import assert from "node:assert/strict";

import { InMemoryFileTree } from "../src/solve/patch.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { runReversibly, defaultAcceptanceTest, type EnvelopeOp, type EnvelopeDeps } from "../src/ree/reversible_envelope.js";
import type { BudgetPolicy } from "../src/budget/budget_ledger.js";
import type { FloorVerdict } from "../src/floor/structural_floor.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Build Step 2 — the budget precondition wired into the REE. An exceeded budget forces the
// cautious branch (rollback) before commit. Verify by disproof.

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "budget-spine-"))), new InProcessLock(), new SchemaRegistry());
}

const REVERSIBLE: FloorVerdict = { verdict: "reversible-execute", reasons: ["ok"] };
const tinyBytes: BudgetPolicy = { maxEdits: 100, maxBytesWritten: 5, maxFilesTouched: 100, maxFanOut: 100, maxSteps: 100 };
const roomy: BudgetPolicy = { maxEdits: 100, maxBytesWritten: 5_000_000, maxFilesTouched: 100, maxFanOut: 100, maxSteps: 100 };

function writeOp(path: string, content: string): EnvelopeOp {
  return {
    description: { kind: "file.edit", writeSet: [path], hasInverse: true },
    execute: async (t) => { await t.write(path, content); },
  };
}

function deps(policy: BudgetPolicy): EnvelopeDeps {
  return { spine: freshSpine(), actor: "test", operator: "op", sign: (p) => `sig(${p})`, budget: { policy } };
}

test("REE+BUDGET: an attempt whose fork writes exceed the byte ceiling rolls back before commit", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const before = tree.snapshot();
  // writes 20 bytes against a 5-byte ceiling → exceeded → cautious branch (rollback).
  const out = await runReversibly(writeOp("a.txt", "12345678901234567890"), REVERSIBLE, tree, defaultAcceptanceTest, deps(tinyBytes));
  assert.equal(out.outcome, "rolled-back");
  if (out.outcome === "rolled-back") assert.ok(out.reason.startsWith("budget-exceeded:bytesWritten"));
  assert.deepEqual(tree.snapshot(), before, "over-budget attempt left the real tree at pre-state");
});

test("REE+BUDGET: a within-budget attempt commits normally", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const out = await runReversibly(writeOp("a.txt", "new"), REVERSIBLE, tree, defaultAcceptanceTest, deps(roomy));
  assert.equal(out.outcome, "committed");
  assert.equal(tree.snapshot()["a.txt"], "new");
});

test("REE+BUDGET: a caller-declared fan-out over ceiling trips even when file writes are tiny", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const d: EnvelopeDeps = {
    spine: freshSpine(), actor: "t", operator: "o", sign: (p) => p,
    budget: { declared: { fanOut: 999 }, policy: roomy },
  };
  const out = await runReversibly(writeOp("a.txt", "x"), REVERSIBLE, tree, defaultAcceptanceTest, d);
  assert.equal(out.outcome, "rolled-back");
  if (out.outcome === "rolled-back") assert.ok(out.reason.includes("fanOut"));
});
