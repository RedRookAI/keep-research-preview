import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { HierarchicalLocalizer, type RepoFile } from "../src/solve/localize.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";

/**
 * ROUND 34 — THE ENVELOPE IS NOW THE DEFAULT.
 *
 * `reversibleEnvelope` was an opt-in constructor dep defaulting OFF. It now defaults ON:
 *
 *   solve_pipeline.ts   if (this.deps.reversibleEnvelope ?? true)
 *
 * THESE TESTS NEVER MENTION THE FLAG. That is the point. Flipping a default that no test
 * can detect has not been proven to have happened — and when the flip was first made, the
 * entire 2418-test suite stayed green, because the strangler-fig equivalence contract holds
 * for accepted ops (the final tree state matches direct-apply). Equivalence is exactly what
 * makes a default flip invisible, so the discriminator has to be an op where the two paths
 * are SUPPOSED to differ: one the barriers refuse.
 *
 * `.env` is a protected path under `defaultFloorPolicy`. Direct-apply has no floor and would
 * happily rewrite it. The envelope holds it. So the assertion is on the EFFECT (Z108) — the
 * file's bytes — not on a config value or a route name, either of which would pass for the
 * wrong reason.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r34-"))), new InProcessLock(), new SchemaRegistry());
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

const SECRET = "API_KEY=keep-this-exact-value\n";

/** A plan that rewrites a PROTECTED path. Direct-apply would land it; the floor holds it. */
function protectedPlan(): string {
  return JSON.stringify({
    rationale: "edit a protected path on purpose",
    edits: [{ file: ".env", search: "keep-this-exact-value", replace: "exfiltrated", intent: "touch .env" }],
  });
}

function pipelineFor(planJson: string, tree: InMemoryFileTree, extra: Record<string, unknown> = {}) {
  const spine = freshSpine();
  return new SolvePipeline({
    spine,
    ledger: new RollbackLedger(spine),
    tree,
    runner,
    localizer: new HierarchicalLocalizer(),
    model: new PlanModel(planJson),
    ...extra,
  } as never);
}

test("R34: with NO flag set, a protected-path edit is HELD — the default routes through the envelope", async () => {
  const files: RepoFile[] = [{ path: ".env", content: SECRET }];
  const tree = new InMemoryFileTree({ ".env": SECRET });
  //                                   ^ no `reversibleEnvelope` key anywhere in this construction
  const pipeline = pipelineFor(protectedPlan(), tree);

  const issue: Issue = { id: "R34-1", text: "rotate the api key in .env", repoRef: "repo" };
  const result = await pipeline.run(issue, files);

  // GUARD FIRST: an unchanged tree and solved:false are ALSO what a localization miss
  // produces, so without this the test would pass for the wrong reason — the exact trap
  // round 33 avoided by design. The run must actually REACH apply for the hold to mean
  // anything. (Found the honest way: the equivalence test below initially failed because
  // its issue text did not localize, which exposed the same hole here.)
  assert.ok(result.stagesRun.includes("apply"), "the run must reach the apply stage");

  // THE EFFECT. Under the old OFF default this file would have been rewritten.
  assert.equal(await tree.read(".env"), SECRET, "a protected path must not be rewritten by the default path");
  assert.equal(result.solved, false, "a held edit is not a solve");
});

test("R34: the hold REPORTS ITSELF — status `held`, with the barrier's real reasons", async () => {
  // Before this round every non-commit collapsed to "reversible path did not commit:
  // human-hold" and was labelled `not-found`, which is false: the file was found and the
  // edit was well-formed. With the envelope on by default, that mislabel is the first thing
  // an operator meets when a safety barrier fires.
  const files: RepoFile[] = [{ path: ".env", content: SECRET }];
  const tree = new InMemoryFileTree({ ".env": SECRET });
  const pipeline = pipelineFor(protectedPlan(), tree);

  const result = await pipeline.run({ id: "R34-2", text: "rotate the api key", repoRef: "repo" }, files);

  assert.ok(result.gaveUpReason, "the run must say why it stopped");
  assert.match(
    result.gaveUpReason!, /held for human review: .+/,
    "the operator must get the gate's actual reasons, not just 'did not commit'",
  );
  assert.doesNotMatch(
    result.gaveUpReason!, /not-found/,
    "a policy hold must never be reported as a missing file",
  );
});

test("R34: benign work is UNAFFECTED by the flip — equivalence holds for accepted ops", async () => {
  // The other half of the claim. If the flip held ordinary edits too, the default would be
  // trading autonomy for safety rather than adding safety, and that trade would be the
  // headline rather than a footnote.
  const before = "export const x = 1;\n";
  const files: RepoFile[] = [{ path: "src/calc.ts", content: before }];
  const tree = new InMemoryFileTree({ "src/calc.ts": before });
  const pipeline = pipelineFor(
    JSON.stringify({
      rationale: "ordinary single-file edit",
      edits: [{ file: "src/calc.ts", search: "export const x = 1;", replace: "export const x = 2;", intent: "bump" }],
    }),
    tree,
  );

  const result = await pipeline.run({ id: "R34-3", text: "bump the constant x in src/calc.ts", repoRef: "repo" }, files);

  assert.equal(await tree.read("src/calc.ts"), "export const x = 2;\n", "an ordinary edit still lands");
  assert.equal(result.solved, true, "and still solves");
});

test("R34: the FALLBACK still works — `reversibleEnvelope: false` restores direct-apply", async () => {
  // Requirement 3. The old path is now the thing an operator flips to under duress, and
  // NOTHING pinned it: no test in the tree set the flag false, so after the flip the direct
  // branch would have been entirely unexercised through the pipeline. An untested fallback
  // is not a fallback.
  //
  // The discriminator is the same protected-path edit: direct-apply has no floor, so the
  // edit that the default HOLDS must LAND here. That proves the branch really is the old
  // behaviour, not merely that it did not crash.
  const files: RepoFile[] = [{ path: ".env", content: SECRET }];
  const tree = new InMemoryFileTree({ ".env": SECRET });
  const pipeline = pipelineFor(protectedPlan(), tree, { reversibleEnvelope: false });

  const result = await pipeline.run({ id: "R34-4", text: "rotate the api key", repoRef: "repo" }, files);

  assert.equal(
    await tree.read(".env"), "API_KEY=exfiltrated\n",
    "with the flag off, direct-apply lands the protected-path edit exactly as it always did",
  );
  assert.equal(result.solved, true, "the fallback path completes end to end");
});
