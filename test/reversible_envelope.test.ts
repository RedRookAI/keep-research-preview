import { test } from "node:test";
import assert from "node:assert/strict";

import { InMemoryFileTree } from "../src/solve/patch.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import {
  runReversibly,
  defaultAcceptanceTest,
  mrWriteSetRespected,
  mrNoCollateralChange,
  mrInverseRestores,
  type EnvelopeOp,
  type EnvelopeDeps,
  type AcceptanceTest,
} from "../src/ree/reversible_envelope.js";
import type { FloorVerdict } from "../src/floor/structural_floor.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Build Step 2 — the Reversible Execution Envelope. These prove the envelope makes a
// reversible-class op safely attemptable: commit on accept, and on ANY reject leave the
// real tree byte-identical to the pre-state. Verify by disproof.

function freshSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "ree-spine-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

function deps(): EnvelopeDeps {
  return { spine: freshSpine(), actor: "test", operator: "op", sign: (p) => `sig(${p})` };
}

const REVERSIBLE: FloorVerdict = { verdict: "reversible-execute", reasons: ["ok"] };
const GATE: FloorVerdict = { verdict: "gate", reasons: ["external-sink"] };

// An op that writes exactly its declared write-set.
function editOp(path: string, content: string): EnvelopeOp {
  return {
    description: { kind: "file.edit", writeSet: [path], hasInverse: true },
    execute: async (tree) => { await tree.write(path, content); },
  };
}

test("REE: a reversible op that PASSES acceptance is committed + sealed to spine", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const out = await runReversibly(editOp("a.txt", "new"), REVERSIBLE, tree, defaultAcceptanceTest, deps());
  assert.equal(out.outcome, "committed");
  assert.equal(tree.snapshot()["a.txt"], "new", "committed change is visible on the real tree");
});

test("REE: an op that VIOLATES a metamorphic relation rolls back — tree byte-identical to pre", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old", "other.txt": "keep" });
  // op declares it writes a.txt but actually also clobbers other.txt → collateral change → reject.
  const sneaky: EnvelopeOp = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true },
    execute: async (t) => { await t.write("a.txt", "new"); await t.write("other.txt", "CLOBBERED"); },
  };
  const before = tree.snapshot();
  const out = await runReversibly(sneaky, REVERSIBLE, tree, defaultAcceptanceTest, deps());
  assert.equal(out.outcome, "rolled-back");
  assert.deepEqual(tree.snapshot(), before, "real tree is byte-identical to the pre-state after rollback");
  assert.equal(tree.snapshot()["a.txt"], "old", "the declared write was ALSO discarded (fork thrown away whole)");
});

test("REE: a mid-execution THROW rolls back with no partial write on the real tree", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const thrower: EnvelopeOp = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true },
    execute: async (t) => { await t.write("a.txt", "half"); throw new Error("boom"); },
  };
  const before = tree.snapshot();
  const out = await runReversibly(thrower, REVERSIBLE, tree, defaultAcceptanceTest, deps());
  assert.equal(out.outcome, "rolled-back");
  assert.deepEqual(tree.snapshot(), before, "no partial 'half' write leaked to the real tree");
});

test("REE: the fork is isolated — the real tree is untouched until commit", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  let seenDuringExec: string | undefined;
  const op: EnvelopeOp = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true },
    execute: async (t) => {
      await t.write("a.txt", "new");
      seenDuringExec = tree.snapshot()["a.txt"]; // the REAL tree, mid-execution
    },
  };
  await runReversibly(op, REVERSIBLE, tree, defaultAcceptanceTest, deps());
  assert.equal(seenDuringExec, "old", "the real tree still read 'old' while the fork held 'new'");
});

test("REE: a committed outcome is a WEAK accept — explicitly labeled non-proof", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const out = await runReversibly(editOp("a.txt", "new"), REVERSIBLE, tree, defaultAcceptanceTest, deps());
  assert.equal(out.outcome, "committed");
  if (out.outcome === "committed") assert.equal(out.accept, "weak");
});

test("REE: a GATE verdict is REFUSED — only reversible-execute ops enter the envelope", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  const out = await runReversibly(editOp("a.txt", "new"), GATE, tree, defaultAcceptanceTest, deps());
  assert.equal(out.outcome, "refused");
  assert.equal(tree.snapshot()["a.txt"], "old", "a refused op never executed");
});

test("REE: default relations exist and are named (necessary conditions)", () => {
  const at: AcceptanceTest = defaultAcceptanceTest;
  assert.ok(at.relations.includes(mrWriteSetRespected));
  assert.ok(at.relations.includes(mrNoCollateralChange));
});

test("REE: mrInverseRestores rejects when the declared inverse does NOT reproduce the pre-state", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "old" });
  // a WRONG inverse (returns the post unchanged instead of restoring "old") must fail the relation.
  const wrongInverse = mrInverseRestores((post) => ({ ...post }));
  const at: AcceptanceTest = { relations: [wrongInverse] };
  const out = await runReversibly(editOp("a.txt", "new"), REVERSIBLE, tree, at, deps());
  assert.equal(out.outcome, "rolled-back", "a non-restoring inverse is a reliable reject");
  assert.equal(tree.snapshot()["a.txt"], "old");
  // and a CORRECT inverse (restores the known pre) holds:
  const good = mrInverseRestores(() => ({ "a.txt": "old" }));
  assert.equal(good.check({ "a.txt": "old" }, { "a.txt": "new" }, { kind: "file.edit" }), true);
});
