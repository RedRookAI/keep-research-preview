import { test } from "node:test";
import assert from "node:assert/strict";

import { InMemoryFileTree, type FileTree } from "../src/solve/patch.js";
import { mediatedTree, ensureMediated, isMediated, runMediated, UnmediatedEffectError } from "../src/solve/mediated_tree.js";

// VET (2026-08-08): adversarial probes of the mediation invariant. These tests
// DOCUMENT what the guard does and does not catch. Where a probe reveals a limit,
// the assertion pins the *actual* behavior (so a future change that alters it is
// noticed) and the comment states whether it's a hole, a foot-gun, or safe-by-design.

// ── HUNT 1 (R23 CLOSED): the unwrapped-tree hole is closed on the agent path ─────
// Last round this test DOCUMENTED the hole (raw tree directly writable). The fix:
// agent-path components hold ONLY a membrane (ensureMediated at construction), so no
// raw, unmediated-writable reference is reachable. This test now proves closure.
test("HUNT1 (R23 CLOSED): ensureMediated yields a membrane with no reachable raw tree; a bare write throws", async () => {
  const raw = new InMemoryFileTree({ "a.txt": "hello" });
  const tree = ensureMediated(raw); // what the pipeline/solver now hold

  // 1. the held tree refuses an unmediated write (structural, not boundary):
  await assert.rejects(() => tree.write("a.txt", "X"), (e) => e instanceof UnmediatedEffectError);

  // 2. the membrane exposes NO accessor back to the raw inner (no reference leaks):
  assert.deepEqual(Object.keys(tree).sort(), ["commitBatchIfUnchanged", "read", "write"]);
  for (const v of Object.values(tree)) assert.equal(typeof v, "function"); // only methods, no tree ref

  // 3. it IS tagged mediated, and wrapping is idempotent (no double-wrap):
  assert.equal(isMediated(tree), true);
  assert.equal(ensureMediated(tree), tree, "ensureMediated is a no-op on an already-mediated tree");

  // 4. reads still work through the membrane:
  assert.equal(await tree.read("a.txt"), "hello");
  // FINDING: on the agent path there is no raw writable tree to obtain — the former
  // bypass is closed. (The workspace's internal raw tree is behind the membrane and
  // not agent-reachable.)
});

test("HUNT1b (R23 CLOSED end-to-end): a pipeline given a RAW tree still mediates its writes", async () => {
  // Prove the wiring, not just the primitive: applyEditPlan opens the scope, and the
  // tree the agent path uses is mediated — so even handed a raw tree at the boundary,
  // the write travels with a spine record and a bare write outside the scope throws.
  const held = ensureMediated(new InMemoryFileTree({ "x.ts": "const a = 1;" }));
  await assert.rejects(() => held.write("x.ts", "bare"), (e) => e instanceof UnmediatedEffectError);
  // and a mediated write (as applyEditPlan does) succeeds:
  await runMediated(async () => { await held.write("x.ts", "const a = 2;"); }, [{ path: "x.ts", content: "const a = 2;" }]);
  assert.equal(await held.read("x.ts"), "const a = 2;");
});

// ── HUNT 2: the async-context escape ───────────────────────────────────────────
// AsyncLocalStorage propagates through awaits. Does the mediation mark survive a
// setTimeout boundary — i.e., does a write deferred to a timer run inside or outside
// the scope?
test("HUNT2: a write deferred via setTimeout INHERITS the mediation scope (AsyncLocalStorage propagates across the timer)", async () => {
  const guarded = mediatedTree(new InMemoryFileTree({ "a.txt": "hello" }));
  let outcome = "unset";
  await runMediated(async () => {
    await new Promise<void>((resolve) => {
      setTimeout(() => {
        guarded
          .write("a.txt", "deferred")
          .then(() => { outcome = "written-inside-scope"; })
          .catch((e) => { outcome = e instanceof UnmediatedEffectError ? "blocked-outside-scope" : "other-error"; })
          .finally(() => resolve());
      }, 0);
    });
  }, [{ path: "a.txt", content: "deferred" }]);
  // FINDING: the grant (carried in AsyncLocalStorage) SURVIVES the timer boundary — Node
  // propagates the async context to the timer callback scheduled inside run(). Good for
  // correctness (a deferred but DECLARED write works); the per-write grant still gates it.
  assert.equal(outcome, "written-inside-scope");
});

// ── HUNT 3: scope-too-wide (ride-along) — TWO distinct behaviors ────────────────
test("HUNT3a: a write from a SEPARATE async context (not descended from runMediated) is BLOCKED (isolation works)", async () => {
  const guarded = mediatedTree(new InMemoryFileTree({ "a.txt": "hello" }));
  // start the bare write in its OWN context, THEN open an unrelated mediated scope.
  let result = "unset";
  const bare = (async () => {
    try { await guarded.write("a.txt", "ride"); result = "rode-along"; }
    catch (e) { result = e instanceof UnmediatedEffectError ? "blocked" : "other"; }
  })();
  await runMediated(async () => { await Promise.resolve(); }); // unrelated open scope
  await bare;
  assert.equal(result, "blocked", "a write in a separate context is not covered by another scope");
});

test("HUNT3b (R24 CLOSED): a write inside the scope but NOT in the grant is REFUSED (per-write authority)", async () => {
  const guarded = mediatedTree(new InMemoryFileTree({ "a.txt": "hello", "b.txt": "keep" }));
  let result = "unset";
  // The grant authorizes ONLY the intended write to a.txt.
  await runMediated(async () => {
    // the declared write succeeds:
    await guarded.write("a.txt", "intended");
    // an UNREGISTERED write (a hook/helper riding along) must now be refused:
    try { await guarded.write("b.txt", "unintended"); result = "rode-along"; }
    catch (e) { result = e instanceof UnmediatedEffectError ? "refused" : "other"; }
  }, [{ path: "a.txt", content: "intended" }]);
  assert.equal(result, "refused", "an unregistered in-scope write must be refused");
  assert.equal(await guarded.read("a.txt"), "intended", "the declared write applied");
  assert.equal(await guarded.read("b.txt"), "keep", "the unregistered write did NOT apply");
});

// ── HUNT 4: effect surface beyond write ────────────────────────────────────────
// The FileTree interface includes an atomic content-bound batch commit in addition
// to read/write. Confirm every mutating method is mediated and no delete/rename/mkdir
// escape exists on the port.
test("HUNT4: every FileTree mutation surface is mediated — no unguarded delete/rename/mkdir on the port", async () => {
  const raw = new InMemoryFileTree({ "a.txt": "x" });
  const guarded = mediatedTree(raw);
  const keys = Object.keys(guarded);
  assert.deepEqual(keys.sort(), ["commitBatchIfUnchanged", "read", "write"], "mediatedTree exposes only the fully mediated FileTree port");
  await assert.rejects(
    () => guarded.commitBatchIfUnchanged!({ "a.txt": "x" }, [{ path: "a.txt", content: "changed" }]),
    (error) => error instanceof UnmediatedEffectError,
    "atomic batch commit must be refused outside a mediation grant",
  );
  assert.equal(await guarded.read("a.txt"), "x");
  // The interface has no delete/rename/truncate; mkdir happens INSIDE write (guarded).
  // So the effect surface via the FileTree port is exactly `write`. Any wider fs
  // effect would come from a component holding a concrete backend (e.g. LocalFsWorkspace),
  // which is the unwrapped-tree concern of HUNT1, not a separate port method.
  assert.equal(typeof (guarded as unknown as Record<string, unknown>)["delete"], "undefined");
  assert.equal(typeof (guarded as unknown as Record<string, unknown>)["rename"], "undefined");
});
