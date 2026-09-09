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
import { structuralFloor, defaultFloorPolicy } from "../src/floor/structural_floor.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

/**
 * ROUND 38 — AUTHORIZING THE DECLARATION.
 *
 * Every enforcement Keep had validated an effect against a DECLARATION. Nothing validated the
 * declaration against an AUTHORITY:
 *
 *   mediated_tree.ts:63    exact (path, content) match vs the DECLARED write-set
 *   solve_pipeline.ts      writeSet: plan.edits.map((e) => e.file)   ← the declaration IS
 *                                                                     the model's edit plan
 *
 * `FloorPolicy.allowedPaths` is that authority. It lives in the floor because `FloorPolicy` is
 * already "pre-committed policy (config data, never model output)" — which is precisely what an
 * authority has to be — and because putting it in the identity scope instead would have created
 * a SECOND path-authority mechanism able to disagree with this one. Round 37 declined to wire
 * `authorizeEffect` into the write path for exactly that reason; doing it here in the other
 * direction would have been the same mistake.
 *
 * SCOPE OF THE CLAIM: this constrains a CONFUSED agent, not a COMPROMISED one. The plan and the
 * allowlist live in the same process (R35-narrow). It is a blast-radius control.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r38-"))), new InProcessLock(), new SchemaRegistry());
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

const BEFORE = "export const x = 1;\n";
const AFTER = "export const x = 2;\n";

/** An edit that is ordinary in every way EXCEPT the directory it names. */
function planFor(file: string): string {
  return JSON.stringify({
    rationale: "ordinary single-file edit",
    edits: [{ file, search: "export const x = 1;", replace: "export const x = 2;", intent: "bump" }],
  });
}

function scenario(file: string, extra: Record<string, unknown>) {
  const files: RepoFile[] = [{ path: file, content: BEFORE }];
  const tree = new InMemoryFileTree({ [file]: BEFORE });
  const spine = freshSpine();
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner,
    localizer: new HierarchicalLocalizer(), model: new PlanModel(planFor(file)),
    ...extra,
  } as never);
  return { tree, pipeline, files };
}

test("R38: a declaration naming a file OUTSIDE the allowlist is refused, and the tree is untouched", async () => {
  const { tree, pipeline, files } = scenario("tools/gen.ts", { allowedPaths: ["src"] });
  const result = await pipeline.run(
    { id: "R38-1", text: "bump the constant x in tools/gen.ts", repoRef: "repo" }, files,
  );

  assert.ok(result.stagesRun.includes("apply"), "the run must reach apply, or an unchanged tree proves nothing");
  assert.equal(await tree.read("tools/gen.ts"), BEFORE, "an out-of-scope declaration must not land");
  assert.equal(result.solved, false);
});

test("R38: the refusal NAMES the offending path", async () => {
  // Z133: an operator who is told only 'out of scope' has to guess which file, and a control
  // that cannot be diagnosed is a control that gets switched off (Z135).
  const { pipeline, files } = scenario("tools/gen.ts", { allowedPaths: ["src"] });
  const result = await pipeline.run(
    { id: "R38-2", text: "bump the constant x in tools/gen.ts", repoRef: "repo" }, files,
  );

  assert.match(
    result.gaveUpReason ?? "", /write-set-outside-allowed-scope:tools\/gen\.ts/,
    "the reason must name the path that was out of scope",
  );
});

test("R38: the SAME plan proceeds when the allowlist covers it — the allowlist is the only variable", async () => {
  const { tree, pipeline, files } = scenario("src/calc.ts", { allowedPaths: ["src"] });
  const result = await pipeline.run(
    { id: "R38-3", text: "bump the constant x in src/calc.ts", repoRef: "repo" }, files,
  );

  assert.equal(await tree.read("src/calc.ts"), AFTER, "in-scope work is untouched by the control");
  assert.equal(result.solved, true);
});

test("R38: omitting allowedPaths is provably INERT — the same out-of-scope file lands", async () => {
  // Requirement 1 and disproof (c). The file that test 1 refuses must land when no allowlist is
  // set, or the control would be changing behaviour for every existing caller.
  const { tree, pipeline, files } = scenario("tools/gen.ts", {});
  const result = await pipeline.run(
    { id: "R38-4", text: "bump the constant x in tools/gen.ts", repoRef: "repo" }, files,
  );

  assert.equal(await tree.read("tools/gen.ts"), AFTER, "no allowlist ⇒ no constraint ⇒ unchanged behaviour");
  assert.equal(result.solved, true);
});

test("R38: the allowlist is canonicalising — traversal cannot smuggle a path in", () => {
  // The predicate is shared with the identity scope (round 37), so this inherits the
  // canonicalise-then-compare order rather than re-implementing it. Asserted at the floor,
  // because a second implementation is exactly what this round refused to write.
  const policy = defaultFloorPolicy("repo", ["src"]);
  const op = (writeSet: string[]) => ({ kind: "file.edit", writeSet, targets: writeSet, hasInverse: true, raw: "x" });

  assert.equal(structuralFloor(op(["src/a.ts"]), policy).verdict, "reversible-execute");
  assert.equal(structuralFloor(op(["src/../.env"]), policy).verdict, "gate", "traversal is refused");
  assert.equal(structuralFloor(op(["tools/x.ts"]), policy).verdict, "gate", "a sibling directory is refused");
});

test("R38: an EMPTY allowlist admits nothing, and is distinct from omission", () => {
  // `[]` is a configured authority that happens to permit nothing — a meaningful, fail-safe
  // state. Omission is 'no authority stated'. Conflating them would let a config bug that
  // produced an empty array silently mean 'unconstrained', which is the dangerous direction.
  const op = { kind: "file.edit", writeSet: ["src/a.ts"], targets: ["src/a.ts"], hasInverse: true, raw: "x" };

  assert.equal(structuralFloor(op, defaultFloorPolicy("repo", [])).verdict, "gate", "[] permits nothing");
  assert.equal(structuralFloor(op, defaultFloorPolicy("repo")).verdict, "reversible-execute", "omitted is unconstrained");
  assert.equal(structuralFloor(op, defaultFloorPolicy("repo", ["*"])).verdict, "reversible-execute", "['*'] is explicit");
});

test("R38: an UNDECLARED write-set is refused under an allowlist — unknown resolves to caution", () => {
  // Matching `writeSetBounded` rather than inventing a second convention for the same unknown.
  const policy = defaultFloorPolicy("repo", ["src"]);
  const v = structuralFloor({ kind: "file.edit", hasInverse: true, raw: "x" }, policy);

  assert.equal(v.verdict, "gate");
  assert.ok(
    v.reasons.some((r) => r.includes("write-set-outside-allowed-scope:<undeclared-write-set>")),
    "an undeclared write-set cannot be shown to be in scope, so it is not",
  );
});
