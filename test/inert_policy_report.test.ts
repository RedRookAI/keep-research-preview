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
import { inertFloorInputs, defaultFloorPolicy, structuralFloor } from "../src/floor/structural_floor.js";
import { inertBudgetInputs, defaultBudgetPolicy, checkBudget } from "../src/budget/budget_ledger.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

/**
 * ROUND 40 — REPORTING A CONTROL THAT IS NOT DOING ANYTHING.
 *
 * Every report Keep had fires on REFUSAL: the floor's reasons, the gate's route reasons, the
 * pipeline's `held` status. A barrier configured into silence never refuses, so it is
 * structurally invisible to all of them — and the audit record of such a run is indistinguishable
 * from a correctly-constrained one.
 *
 * THE FAMILY, established by sweeping every policy input rather than patching the known case.
 * The fail-safe direction depends on the SHAPE of the input:
 *
 *   ALLOWLIST emptied → admits nothing → refuses everything → LOUD
 *   DENYLIST  emptied → denies nothing → refuses nothing    → SILENT
 *   CEILING   raised  → never trips    → refuses nothing    → SILENT
 *
 * Measured: `protectedMatchers: []` stops refusing a `.env` write; budget ceilings at `Infinity`
 * report `within-budget` for a million edits and a terabyte written. Neither said anything.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r40-"))), new InProcessLock(), new SchemaRegistry());
}

class PlanModel implements ModelProvider {
  readonly name = "plan-model";
  readonly isLocal = true;
  async generate(_r: GenerateRequest): Promise<GenerateResult> {
    return {
      text: JSON.stringify({ rationale: "r", edits: [{ file: "src/calc.ts", search: "export const x = 1;", replace: "export const x = 2;", intent: "bump" }] }),
      model: this.name, tokensIn: 1, tokensOut: 1,
    };
  }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

const runner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };
const BEFORE = "export const x = 1;\n";

/** Run the pipeline and return the operator-visible narration recorded to the spine. */
async function narrationFor(extra: Record<string, unknown>): Promise<string[]> {
  const spine = freshSpine();
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BEFORE }];
  const tree = new InMemoryFileTree({ "src/calc.ts": BEFORE });
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner,
    localizer: new HierarchicalLocalizer(), model: new PlanModel(), ...extra,
  } as never);
  await pipeline.run({ id: "R40", text: "bump the constant x in src/calc.ts", repoRef: "repo" }, files);
  return spine.currentEvents()
    .map((e) => e.payload as Record<string, unknown>)
    .filter((p) => p["event"] === "progress.narrated" && p["stage"] === "policy")
    .map((p) => String(p["detail"] ?? p["headline"] ?? ""));
}

test("R40: a self-contradictory allowlist is REPORTED to the operator, on a run that succeeds", async () => {
  // The whole point: this run PASSES. Nothing is refused, so no existing mechanism would say a
  // word — and the operator's scope is inert. Asserted on the observable (Z108): what actually
  // reached the operator's feed and the spine, not an internal field.
  const said = await narrationFor({ allowedPaths: ["src", "*"] });

  assert.equal(said.length, 1, "exactly one finding");
  assert.match(said[0]!, /bare "\*"/, "names the cause");
  assert.match(said[0]!, /admits everything/, "and says what it means");
});

test("R40: legitimate configurations stay SILENT — the noise case the research predicts", async () => {
  // The policy-linting literature warns that flagging syntactic permissiveness produces alerts
  // that get muted, and the muting habit then hides the real case. So a plain ["*"], an omitted
  // scope, and a genuinely narrow scope must produce NOTHING.
  assert.deepEqual(await narrationFor({}), [], "omitted scope is silent");
  assert.deepEqual(await narrationFor({ allowedPaths: ["*"] }), [], "an honest ['*'] is silent");
  assert.deepEqual(await narrationFor({ allowedPaths: ["src", "test"] }), [], "a real scope is silent");
});

test("R40 SWEEP: an emptied DENYLIST is silently disabled — and is now reported", () => {
  // Measured, not assumed: with protectedMatchers emptied, a .env write is no longer refused.
  const op = { kind: "file.edit", writeSet: [".env"], targets: [".env"], hasInverse: true, raw: "x" };

  const guarded = defaultFloorPolicy("repo");
  const disabled = { ...guarded, protectedMatchers: [] };

  assert.equal(structuralFloor(op, guarded).verdict, "gate", "normally refused");
  assert.equal(structuralFloor(op, disabled).verdict, "reversible-execute", "and silently permitted when emptied");

  assert.deepEqual(inertFloorInputs(guarded), [], "a real denylist is not flagged");
  assert.match(inertFloorInputs(disabled)[0] ?? "", /protectedMatchers is empty/, "the emptied one is");
});

test("R40 SWEEP: an unreachable CEILING is silently disabled — and is now reported", () => {
  const huge = { edits: 1e6, filesTouched: 1e6, bytesWritten: 1e12, fanOut: 1e6, steps: 1e6 };
  const unbounded = { maxEdits: Infinity, maxBytesWritten: Infinity, maxFilesTouched: Infinity, maxFanOut: Infinity, maxSteps: Infinity };

  assert.equal(checkBudget(huge, defaultBudgetPolicy()).verdict, "exceeded", "normally trips");
  assert.equal(checkBudget(huge, unbounded).verdict, "within-budget", "and silently passes when unbounded");

  assert.deepEqual(inertBudgetInputs(defaultBudgetPolicy()), [], "finite ceilings are not flagged");
  assert.match(inertBudgetInputs(unbounded)[0] ?? "", /can never trip/, "unbounded ones are");
});

test("R40: a ceiling of ZERO is not reported — that is the loud direction", () => {
  // It trips on everything, so the operator discovers it on the first run. Reporting it would be
  // the noise the disconfirming case warns about.
  const zero = { maxEdits: 0, maxBytesWritten: 0, maxFilesTouched: 0, maxFanOut: 0, maxSteps: 0 };
  assert.deepEqual(inertBudgetInputs(zero), [], "a zero ceiling is loud, not silent");
});

test("R40: an emptied ALLOWLIST is not reported either — emptying it fails SAFE", () => {
  // The other half of the family characterisation. `[]` admits nothing, so it refuses everything
  // and announces itself immediately. Only the fail-OPEN shapes need this channel.
  assert.deepEqual(inertFloorInputs(defaultFloorPolicy("repo", [])), [], "[] is loud, not silent");
});
