import { test } from "node:test";
import assert from "node:assert/strict";

import { InMemoryFileTree, applyEditPlan, type FileTree } from "../src/solve/patch.js";
import {
  mediatedTree,
  runMediated,
  isMediating,
  UnmediatedEffectError,
} from "../src/solve/mediated_tree.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Build Step 1 (mediation root): the mediation invariant — "no agent-originated
// effect except through a mediated chokepoint that records to the spine."
// These are the PROOF that the invariant bites, not just that it passes on clean code.

function freshLedgerAndSpine(): { ledger: RollbackLedger; spine: Spine } {
  const dir = mkdtempSync(join(tmpdir(), "keep-med-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  const ledger = new RollbackLedger(spine);
  return { ledger, spine };
}

test("MEDIATION: a bare write on a mediatedTree THROWS (the invariant bites)", async () => {
  const tree = mediatedTree(new InMemoryFileTree({ "a.txt": "hello" }));
  await assert.rejects(
    () => tree.write("a.txt", "TAMPERED"),
    (e: unknown) => e instanceof UnmediatedEffectError,
    "an unmediated write must be blocked",
  );
  // and the underlying content is unchanged — the write never happened
  assert.equal(await tree.read("a.txt"), "hello");
});

test("MEDIATION: a write INSIDE runMediated succeeds", async () => {
  const tree = mediatedTree(new InMemoryFileTree({ "a.txt": "hello" }));
  assert.equal(isMediating(), false);
  await runMediated(async () => {
    assert.equal(isMediating(), true);
    await tree.write("a.txt", "world");
  }, [{ path: "a.txt", content: "world" }]);
  assert.equal(isMediating(), false, "scope closes after runMediated");
  assert.equal(await tree.read("a.txt"), "world");
});

test("MEDIATION: applyEditPlan writes THROUGH a mediatedTree AND records to the spine", async () => {
  const { ledger, spine } = freshLedgerAndSpine();
  const inner = new InMemoryFileTree({ "src/x.ts": "const a = 1;" });
  const tree = mediatedTree(inner);

  const res = await applyEditPlan(
    {
      rationale: "test",
      edits: [{ file: "src/x.ts", search: "const a = 1;", replace: "const a = 2;", intent: "bump" }],
    },
    tree,
    ledger,
    { issueId: "T1" },
  );

  assert.equal(res.applied, true, "the mediated edit applied");
  assert.equal(await tree.read("src/x.ts"), "const a = 2;");
  // the ledger.record staged a spine event — seal it and confirm the effect is
  // coupled to a spine record (the mediation invariant's "records to the spine").
  await spine.seal();
  const events = spine.replay();
  const recorded = events.some(
    (e) => (e.payload as { event?: string })?.event === "reversible_recorded",
  );
  assert.ok(recorded, "applyEditPlan's effect produced a spine record (mediation coupling)");
});

test("MEDIATION: a BROKEN chokepoint that skips runMediated is caught RED", async () => {
  // This simulates a future refactor / bypass that writes to the agent tree WITHOUT
  // opening the mediation scope. The invariant MUST reject it. (If this test ever
  // passes-through silently, the guard has stopped biting.)
  const tree = mediatedTree(new InMemoryFileTree({ "a.txt": "hello" }));
  const brokenChokepoint = async () => {
    // note: NO runMediated(...) wrapper — the coupling to a spine record is absent
    await tree.write("a.txt", "unrecorded-effect");
  };
  await assert.rejects(brokenChokepoint, (e: unknown) => e instanceof UnmediatedEffectError);
});

test("MEDIATION: reads are never blocked (only effects are mediated)", async () => {
  const tree = mediatedTree(new InMemoryFileTree({ "a.txt": "hello" }));
  assert.equal(await tree.read("a.txt"), "hello");
  assert.equal(await tree.read("missing.txt"), undefined);
});

test("MEDIATION: a plain (unwrapped) tree is unaffected — guard is opt-in at the boundary", async () => {
  // Infra/test trees that are NOT on the agent path keep working with direct writes.
  const plain = new InMemoryFileTree({ "a.txt": "hello" });
  await plain.write("a.txt", "seeded"); // no throw
  assert.equal(await plain.read("a.txt"), "seeded");
});
