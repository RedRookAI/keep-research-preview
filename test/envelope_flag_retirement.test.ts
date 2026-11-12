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
import {
  SolvePipeline,
  REVERSIBLE_ENVELOPE_STABILIZATION,
  reversibleEnvelopeStabilizationFact,
  type StabilizationRecord,
} from "../src/solve/solve_pipeline.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";

/**
 * The compatibility flag retains a recorded rationale while defaulting to the
 * governed path. Tests inspect the emitted event and actual file effects, enforce
 * nonempty rationale, and retain explicit legacy behavior plus default refusal.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "z126-"))), new InProcessLock(), new SchemaRegistry());
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

/** A plan that rewrites a PROTECTED path. Direct-apply lands it; the envelope holds it. */
function protectedPlan(): string {
  return JSON.stringify({
    rationale: "edit a protected path on purpose",
    edits: [{ file: ".env", search: "keep-this-exact-value", replace: "exfiltrated", intent: "touch .env" }],
  });
}

/** An ordinary, accepted single-file edit — both paths agree on this one (equivalence). */
function benignPlan(): string {
  return JSON.stringify({
    rationale: "ordinary single-file edit",
    edits: [{ file: "src/calc.ts", search: "export const x = 1;", replace: "export const x = 2;", intent: "bump" }],
  });
}

function pipelineFor(planJson: string, tree: InMemoryFileTree, spine: Spine, extra: Record<string, unknown> = {}) {
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

// ── (a) the documented reason is REQUIRED — a keep with no recorded criterion is drift ──

test("2.5(a): the KEEP record names a SPECIFIC unmet criterion AND a revisit condition", () => {
  const fact = reversibleEnvelopeStabilizationFact();
  assert.equal(fact.disposition, "kept", "the flag is kept this round");
  assert.ok(fact.unmetCriterion.trim().length > 0, "a kept flag must name the specific unmet criterion");
  assert.ok(fact.revisitWhen.trim().length > 0, "a kept flag must name the revisit condition");
  assert.match(fact.unmetCriterion, /compatibility|legacy/i, "the criterion identifies the current compatibility contract");
  assert.match(fact.revisitWhen, /release.*configuration contract/i, "retirement requires an explicit compatibility change");
  assert.doesNotMatch(fact.unmetCriterion, /never executed|BUILD-ORDER|userless|Phase 4/i);
});

test("2.5(a): reversibleEnvelopeStabilizationFact is FAIL-CLOSED — a hollow keep throws", () => {
  // A keep with an empty criterion or no revisit condition is not a governed decision; it is a
  // silent permanent border. The helper must refuse it rather than audit a hollow 'keep'.
  assert.throws(
    () => reversibleEnvelopeStabilizationFact({ ...REVERSIBLE_ENVELOPE_STABILIZATION, unmetCriterion: "   " }),
    /undocumented|unmet stabilization criterion/i,
    "an empty unmet-criterion must throw (no silent keep)",
  );
  assert.throws(
    () => reversibleEnvelopeStabilizationFact({ ...REVERSIBLE_ENVELOPE_STABILIZATION, revisitWhen: "" }),
    /undocumented|revisit/i,
    "an empty revisit condition must throw (no drift into a permanent border)",
  );
});

// ── wiring (ledger 298): the kept default RECORDS the reason where an auditor reads it ──

test("2.5 WIRING: a default (kept) run records the kept-cutover reason to the spine", async () => {
  const before = "export const x = 1;\n";
  const files: RepoFile[] = [{ path: "src/calc.ts", content: before }];
  const tree = new InMemoryFileTree({ "src/calc.ts": before });
  const spine = freshSpine();
  const pipeline = pipelineFor(benignPlan(), tree, spine); // NO flag set ⇒ kept default

  const result = await pipeline.run({ id: "Z126-W", text: "bump the constant x in src/calc.ts", repoRef: "repo" }, files);

  // GUARD: the run must actually reach apply, or the absence of the fact would be vacuous.
  assert.ok(result.stagesRun.includes("apply"), "the run must reach the apply stage");

  const facts = spine
    .currentEvents()
    .map((e) => (e.payload as Record<string, unknown>)["keptCutoverFlag"])
    .filter(Boolean) as StabilizationRecord[];
  assert.equal(facts.length >= 1, true, "the kept-default apply must record the cutover-flag reason to the spine");
  assert.ok(facts[0]!.unmetCriterion.length > 0, "the recorded reason must carry the specific unmet criterion");
  assert.ok(facts[0]!.revisitWhen.length > 0, "the recorded reason must carry the revisit condition");
});

// ── (b) the honest revert: `reversibleEnvelope: false` STILL restores direct-apply ──

test("2.5(b): `reversibleEnvelope: false` still restores direct-apply — the revert is real", async () => {
  const files: RepoFile[] = [{ path: ".env", content: SECRET }];
  const tree = new InMemoryFileTree({ ".env": SECRET });
  const pipeline = pipelineFor(protectedPlan(), tree, freshSpine(), { reversibleEnvelope: false });

  const result = await pipeline.run({ id: "Z126-B", text: "rotate the api key", repoRef: "repo" }, files);

  assert.equal(
    await tree.read(".env"), "API_KEY=exfiltrated\n",
    "with the flag off, direct-apply lands the protected-path edit exactly as it always did",
  );
  assert.equal(result.solved, true, "the fallback path completes end to end");
});

// ── (c) the default is STILL ON: omitting the flag routes through the envelope ──

test("2.5(c): the default is STILL ON — a protected-path edit is HELD when no flag is set", async () => {
  const files: RepoFile[] = [{ path: ".env", content: SECRET }];
  const tree = new InMemoryFileTree({ ".env": SECRET });
  const pipeline = pipelineFor(protectedPlan(), tree, freshSpine()); // NO flag ⇒ kept default (ON)

  const result = await pipeline.run({ id: "Z126-C", text: "rotate the api key in .env", repoRef: "repo" }, files);

  assert.ok(result.stagesRun.includes("apply"), "the run must reach the apply stage");
  assert.equal(await tree.read(".env"), SECRET, "the default path must hold a protected edit (envelope ON)");
  assert.equal(result.solved, false, "a held edit is not a solve");
});
