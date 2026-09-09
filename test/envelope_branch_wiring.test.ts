import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { HierarchicalLocalizer, type RepoFile } from "../src/solve/localize.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import { IdentityRegistry } from "../src/identity/agent_identity.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";

/**
 * ENVELOPE BRANCH WIRING (round 30).
 *
 * The pipeline's `reversibleEnvelope` branch had NEVER EXECUTED. Thirteen SolvePipeline
 * instances across the suite and not one set the flag, so `executeReversibly` — and with it the
 * identity kill switch — was unreachable from the pipeline. Separately, the call site passed no
 * `identityRegistry`, so even with the flag on, `identityLive` stayed `undefined` and the gate
 * treated it as "not assessed (no veto)". The switch could not fire.
 *
 * CONTRACT TESTS, NOT CHARACTERIZATION — deliberately. Characterization "claims the system
 * behaves the way it currently behaves" and "the captured behavior includes the bugs", justified
 * because "users depend on the way it works". Nobody depends on this branch; it has never run.
 * So these assert the DOCUMENTED contract, and a divergence is a finding, not a baseline.
 */

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-envelope-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

class PlanModel implements ModelProvider {
  readonly name = "plan-model";
  readonly isLocal = true;
  constructor(private readonly planJson: string) {}
  async generate(_req: GenerateRequest): Promise<GenerateResult> {
    return { text: this.planJson, model: this.name, tokensIn: 1, tokensOut: 1 };
  }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

const issue: Issue = { id: "ENV-1", text: "add() subtracts instead of adding in calc.ts", repoRef: "repo" };
const files: RepoFile[] = [
  { path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" },
  { path: "src/util.ts", content: "export function noop() {}" },
];

function calcRunner(tree: InMemoryFileTree): TestRunner {
  return {
    async run(): Promise<TestRunResult> {
      const content = (await tree.read("src/calc.ts")) ?? "";
      const correct = content.includes("a + b");
      return { results: [{ name: "add(2,3)==5", passed: correct, ...(correct ? {} : { output: "expected 5, got -1" }) }] };
    },
  };
}

const PLAN = JSON.stringify({
  rationale: "the operator was inverted",
  edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "use + not -" }],
});

/** Build a pipeline with the envelope branch ENABLED — the branch that had never run. */
function envelopePipeline(extra: Record<string, unknown>) {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const pipeline = new SolvePipeline({
    spine,
    ledger: new RollbackLedger(spine),
    tree,
    runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(),
    model: new PlanModel(PLAN),
    reversibleEnvelope: true,
    ...extra,
  } as never);
  return { spine, tree, pipeline };
}

test("WIRING: a KILLED identity is refused on the COMPOSED path (not by calling the module)", async () => {
  const registry = new IdentityRegistry();
  const identity = registry.mint("solver-killed", ["*"]);
  registry.kill("solver-killed", "round-30 disproof");

  const { pipeline, tree } = envelopePipeline({ identity, identityRegistry: registry });
  const result = await pipeline.run(issue, files);

  // CONTRACT: a killed identity is a deny-capable gate input, so the patch must NOT land.
  // Asserting on the TREE is the strongest available evidence — it is the actual effect the
  // kill switch exists to prevent, and it cannot be satisfied by a passing module-level test.
  assert.equal(
    await tree.read("src/calc.ts"),
    "export function add(a, b) { return a - b; }",
    "a killed identity must not be able to change the tree",
  );
  assert.equal(result.solved, false, "a killed identity must not produce a solved run");
});

test("WIRING: a LIVE identity does not trip the identity veto", async () => {
  const registry = new IdentityRegistry();
  const identity = registry.mint("solver-live", ["*"]);

  const { pipeline } = envelopePipeline({ identity, identityRegistry: registry });
  const result = await pipeline.run(issue, files);

  assert.ok(
    !JSON.stringify(result).includes("killed-or-unknown-identity"),
    "a live identity must not produce the identity veto",
  );
});

test("WIRING: the envelope branch runs with no identity supplied (n=1 contract, unchanged)", async () => {
  const { pipeline } = envelopePipeline({});
  const result = await pipeline.run(issue, files);

  // DECIDED AND STATED for n=1: with no identity supplied, `identityLive` stays `undefined`,
  // which `composed_gate.ts` documents as "not assessed (no veto)". This round does NOT change
  // that contract. A solo operator who never mints an identity is not vetoed by the identity
  // barrier — the other barriers (floor, budget, twin, BOM) still apply. What must never happen
  // is a KILLED identity proceeding, which the first test covers.
  assert.ok(Array.isArray(result.stagesRun), "the pipeline completes with the envelope enabled");
});
