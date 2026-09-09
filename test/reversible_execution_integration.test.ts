import { test } from "node:test";
import assert from "node:assert/strict";

import { InMemoryFileTree, type FileTree } from "../src/solve/patch.js";
import { mediatedTree, WriteGrant, runMediatedWith, UnmediatedEffectError } from "../src/solve/mediated_tree.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { defaultFloorPolicy } from "../src/floor/structural_floor.js";
import { defaultGatePolicy } from "../src/gate/composed_gate.js";
import { defaultBudgetPolicy } from "../src/budget/budget_ledger.js";
import { defaultAcceptanceTest } from "../src/ree/reversible_envelope.js";
import { executeReversibly, type ReversibleIntent, type IntegrationDeps, type IntegrationPolicies } from "../src/integrate/reversible_execution.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Build Step 2 close-out — the live-integration pass. These prove the reversible path flows
// through the composed chain (floor → gate → envelope), the human-hold path never executes, and
// mediation (R23/R24) is preserved on the integrated path. Verify by disproof.

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "integ-spine-"))), new InProcessLock(), new SchemaRegistry());
}

const policies: IntegrationPolicies = {
  floor: defaultFloorPolicy("repo"),
  gate: defaultGatePolicy(),
  budget: defaultBudgetPolicy(),
  acceptance: defaultAcceptanceTest,
};

function deps(tree: FileTree, spine: Spine, envelopeEnabled = true): IntegrationDeps {
  return { spine, actor: "t", operator: "o", sign: (p) => `sig(${p})`, tree, ownerPresent: true, envelopeEnabled };
}

// A reversible edit intent writing exactly its declared write-set.
function editIntent(path: string, content: string): ReversibleIntent {
  return {
    description: { kind: "file.edit", writeSet: [path], hasInverse: true, raw: content },
    apply: async (t) => { await t.write(path, content); },
    actionTier: "reversible-internal",
  };
}

test("INTEGRATION: an auto-proceed reversible op flows THROUGH the envelope (spine gains blocks)", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  const spine = freshSpine();
  const before = spine.replay().length;
  const res = await executeReversibly(editIntent("a.txt", "new"), policies, deps(tree, spine));
  assert.equal(res.path, "envelope");
  if (res.path === "envelope") assert.equal(res.outcome.outcome, "committed");
  assert.equal(await tree.read("a.txt"), "new", "committed through the mediated tree");
  assert.ok(spine.replay().length > before, "the envelope checkpointed + sealed to the spine");
});

test("INTEGRATION: a human-hold op NEVER executes (tree untouched)", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  const spine = freshSpine();
  // An irreversible-tier intent → gate holds → no execution.
  const held: ReversibleIntent = { ...editIntent("a.txt", "new"), actionTier: "irreversible" };
  const res = await executeReversibly(held, policies, deps(tree, spine));
  assert.equal(res.path, "human-hold");
  assert.equal(await tree.read("a.txt"), "old", "a held op never touched the tree");
});

test("INTEGRATION: mediation (R23/R24) is preserved — commit goes through the grant, only declared writes", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old", "b.txt": "keep" });
  const tree = mediatedTree(inner);
  const spine = freshSpine();
  // sneaky intent: declares a.txt but its apply also writes b.txt. The DIGITAL TWIN now previews this
  // over-scope and the gate holds it BEFORE execution (earlier than the envelope's acceptance test,
  // which is the commit-time backstop). Either way the collateral write never reaches the tree.
  const sneaky: ReversibleIntent = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "new" },
    apply: async (t) => { await t.write("a.txt", "new"); await t.write("b.txt", "CLOB"); },
    actionTier: "reversible-internal",
  };
  const res = await executeReversibly(sneaky, policies, deps(tree, spine));
  assert.equal(res.path, "human-hold", "the twin caught the undeclared write at preview → gate held it");
  assert.equal(await tree.read("a.txt"), "old", "no partial commit");
  assert.equal(await tree.read("b.txt"), "keep", "collateral file untouched");
});

test("INTEGRATION: the mediated tree STILL throws on an unmediated write (membrane intact)", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  // a bare write with no grant in scope must throw — the integrated path did not weaken the membrane.
  await assert.rejects(() => tree.write("a.txt", "x"), (e) => e instanceof UnmediatedEffectError);
  // and a write NOT in the grant is refused (R24) even inside a grant scope.
  const grant = new WriteGrant([{ path: "a.txt", content: "granted" }]);
  await runMediatedWith(grant, async () => {
    await tree.write("a.txt", "granted"); // ok
    await assert.rejects(() => tree.write("a.txt", "other"), (e) => e instanceof UnmediatedEffectError);
  });
});

test("INTEGRATION: feature-guard disabled falls back to DIRECT apply (old path)", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  const spine = freshSpine();
  const before = spine.replay().length;
  const res = await executeReversibly(editIntent("a.txt", "new"), policies, deps(tree, spine, /*envelopeEnabled*/ false));
  assert.equal(res.path, "direct-apply-fallback");
  assert.equal(await tree.read("a.txt"), "new", "direct apply still committed through the mediated tree");
  assert.equal(spine.replay().length, before, "the fallback did NOT run the envelope (no checkpoint/seal)");
});

test("INTEGRATION: envelope and fallback reach the SAME final state for an accepted op (equivalence)", async () => {
  const mk = () => mediatedTree(new InMemoryFileTree({ "a.txt": "old" }));
  const viaEnvelope = mk();
  const viaDirect = mk();
  await executeReversibly(editIntent("a.txt", "final"), policies, deps(viaEnvelope, freshSpine(), true));
  await executeReversibly(editIntent("a.txt", "final"), policies, deps(viaDirect, freshSpine(), false));
  assert.equal(await viaEnvelope.read("a.txt"), await viaDirect.read("a.txt"), "both paths yield the same state");
});
