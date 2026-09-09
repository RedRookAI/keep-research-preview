import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryFileTree, canApply } from "../src/solve/patch.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { HierarchicalLocalizer, type RepoFile } from "../src/solve/localize.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";

/**
 * R13 — ASSERTED REVERSIBILITY (round 32).
 *
 * `solve_pipeline.ts` hardcoded `hasInverse: true` in the intent handed to the structural floor.
 * `inverseConstructible` returns `op.hasInverse === true`, and it is a NECESSARY condition for
 * the reversible class — so the floor could never refuse an irreversible op on that path. It was
 * always told an inverse existed.
 *
 * The fix computes it with `canApply`, which already existed and is tested: every edit's search
 * block must match EXACTLY ONCE. That is precisely the condition under which a search/replace
 * edit can be unambiguously reversed — if the block appears twice, you cannot know which
 * occurrence to restore.
 *
 * CONSERVATIVE ON PURPOSE. Reversibility is undecidable in general, so the predicate answers
 * "provably invertible" or "unknown ⇒ gate" rather than attempting exactness.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r13-"))), new InProcessLock(), new SchemaRegistry());
}

class PlanModel implements ModelProvider {
  readonly name = "plan-model";
  readonly isLocal = true;
  constructor(private readonly planJson: string) {}
  async generate(_r: GenerateRequest): Promise<GenerateResult> {
    return { text: this.planJson, model: this.name, tokensIn: 1, tokensOut: 1 };
  }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

const runner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

test("R13: an AMBIGUOUS edit is NOT provably invertible — canApply refuses it", async () => {
  // "dup" appears twice, so no unique reversal exists: you cannot know which one to restore.
  const tree = new InMemoryFileTree({ "a.txt": "dup\nmiddle\ndup\n" });
  const plan = { edits: [{ file: "a.txt", search: "dup", replace: "changed" }] } as never;

  assert.equal(
    await canApply(plan, tree), false,
    "a search block matching twice is not unambiguously reversible",
  );
});

test("R13: a UNIQUE edit IS provably invertible", async () => {
  const tree = new InMemoryFileTree({ "a.txt": "only-once\nother\n" });
  const plan = { edits: [{ file: "a.txt", search: "only-once", replace: "changed" }] } as never;

  assert.equal(await canApply(plan, tree), true, "a uniquely-matching edit is reversible");
});

test("R13: the floor GATES an ambiguous plan through the composed pipeline", async () => {
  // The disproof that matters: the intent now carries hasInverse=false for this plan, so
  // `inverseConstructible` fails and the floor gates. With the old hardcoded `true`, the floor
  // was told an inverse existed and this same plan proceeded.
  const files: RepoFile[] = [
    { path: "src/calc.ts", content: "const x = 1;\nconst y = 2;\nconst x = 1;\n" },
  ];
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const spine = freshSpine();
  const pipeline = new SolvePipeline({
    spine,
    ledger: new RollbackLedger(spine),
    tree,
    runner,
    localizer: new HierarchicalLocalizer(),
    model: new PlanModel(JSON.stringify({
      rationale: "ambiguous on purpose",
      edits: [{ file: "src/calc.ts", search: "const x = 1;", replace: "const x = 2;", intent: "dup" }],
    })),
    reversibleEnvelope: true,
  } as never);

  const issue: Issue = { id: "R13-1", text: "duplicate declaration in calc.ts", repoRef: "repo" };
  await pipeline.run(issue, files);

  // Assert on the EFFECT (Z108): the ambiguous edit must not have landed.
  const after = await tree.read("src/calc.ts");
  assert.equal(after, files[0]!.content, "an ambiguous, non-invertible edit must not change the tree");
});
