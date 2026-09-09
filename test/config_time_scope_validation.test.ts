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
import { assessDeclaredScope } from "../src/floor/structural_floor.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

/**
 * BUILD-ORDER 2.1 (Z170) — CONFIG-TIME SCOPE VALIDATION.
 *
 * MEASURED (.round-artifacts/CONFIG-TIME-SCOPE-VALIDATION/measurement.txt): the operator's declared
 * `allowedPaths` was validated ONLY at RUN time — a per-run report that is deliberately silent on a
 * plain `["*"]`, and `unsupportedScopePatterns` reached only inside `structuralFloor` (per-op). So a
 * malformed declared scope surfaced LATE (the first run gating every plan) and an all-permitting
 * `["*"]` surfaced NEVER. There was NO check at the moment the scope was DECLARED.
 *
 * DECISION (ADD, evidence-bound): a config-time surfacing bound at the declaration/threading seam —
 * the SolvePipeline constructor, which runs ONCE, before any run(). When the operator DECLARES an
 * over-broad or malformed scope, it is recorded to the spine as an auditable CONSCIOUS-GRANT fact.
 * Observe-only: it never refuses, never narrows, never runs per-op. Composed over the existing floor
 * scope semantics (`assessDeclaredScope` reuses `unsupportedScopePatterns` + the self-contradiction
 * predicate), not a re-derivation of the floor.
 *
 * Front-of-house preserved: an OMITTED scope declares nothing → records nothing → byte-identical; a
 * plain `["*"]` run still proceeds — the only delta is one set-time audit record, not a per-run alert.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "z170-"))), new InProcessLock(), new SchemaRegistry());
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
  return { tree, pipeline, files, spine };
}

/** Every `scope.declared` config-time record on the spine (staged or sealed). */
function scopeDeclarations(spine: Spine): Array<Record<string, unknown>> {
  return spine.currentEvents()
    .filter((e) => (e.payload as { event?: string }).event === "scope.declared")
    .map((e) => e.payload as Record<string, unknown>);
}

// ── The pure config-time assessor: composed over the existing floor scope semantics ──

test("Z170: assessDeclaredScope classifies each shape; only a DECLARED over-broad/malformed scope is worthRecording", () => {
  // omitted ⇒ nothing declared ⇒ admits everything but NOT recorded (front-of-house default).
  const omitted = assessDeclaredScope(undefined);
  assert.equal(omitted.admitsEverything, true);
  assert.equal(omitted.disposition, "unconstrained");
  assert.equal(omitted.worthRecording, false, "an omitted scope declared nothing to audit");

  // a plain ["*"] ⇒ DECLARED unconstrained ⇒ recorded as a conscious grant.
  const star = assessDeclaredScope(["*"]);
  assert.equal(star.admitsEverything, true);
  assert.equal(star.disposition, "unconstrained");
  assert.equal(star.worthRecording, true, "a DECLARED ['*'] is a conscious grant worth auditing");

  // a clean narrow scope ⇒ nothing to surface (no config-time noise).
  const narrow = assessDeclaredScope(["src", "test"]);
  assert.equal(narrow.admitsEverything, false);
  assert.equal(narrow.disposition, "constrained");
  assert.equal(narrow.worthRecording, false, "a clean narrow scope must not add config-time noise");

  // self-contradictory ⇒ admits everything AND carries the finding.
  const contra = assessDeclaredScope(["*", "src"]);
  assert.equal(contra.admitsEverything, true);
  assert.equal(contra.disposition, "self-contradictory");
  assert.ok(contra.findings.some((f) => f.includes('bare "*"')), "the self-contradiction is named");
  assert.equal(contra.worthRecording, true);

  // malformed ⇒ COMPOSED with unsupportedScopePatterns, surfaced as the operator's bug.
  const bad = assessDeclaredScope(["src/**/*.ts"]);
  assert.equal(bad.disposition, "malformed");
  assert.ok(bad.findings.some((f) => f.startsWith("unsupported-scope-pattern:")), "the malformed pattern is named");
  assert.equal(bad.worthRecording, true);

  // Honesty: the declared scope is carried VERBATIM, never narrowed.
  assert.deepEqual(bad.declared, ["src/**/*.ts"], "the assessor never rewrites what the operator declared");
});

// ── Config-time surfacing at the DECLARATION seam (the SolvePipeline ctor) ──

test("Z170 (a): a DECLARED all-permitting ['*'] scope is SURFACED at config time — before any run", () => {
  const { spine } = scenario("src/calc.ts", { allowedPaths: ["*"] });
  // No run() has been called — the record exists purely from CONSTRUCTION (config time).
  const decls = scopeDeclarations(spine);
  assert.equal(decls.length, 1, "constructing with a declared ['*'] must record exactly one conscious-grant fact");
  const d = decls[0]!;
  assert.equal(d.admitsEverything, true, "the record states plainly that the scope admits everything");
  assert.equal(d.disposition, "unconstrained");
  assert.deepEqual(d.declared, ["*"], "the record carries the declared scope verbatim");
  // Honesty bound: the record attests what the scope ADMITS and explicitly DISCLAIMS any safety claim.
  assert.match(String(d.note ?? ""), /not a claim.*safe/i, "the record must disclaim safety, never assert a wide scope is safe");
});

test("Z170 (a): a DECLARED malformed scope is surfaced at config time — composed with unsupportedScopePatterns", () => {
  const { spine } = scenario("src/calc.ts", { allowedPaths: ["src/**/*.ts"] });
  const decls = scopeDeclarations(spine);
  assert.equal(decls.length, 1);
  const d = decls[0]!;
  assert.equal(d.disposition, "malformed");
  assert.ok(
    (d.findings as string[]).some((f) => f.includes("unsupported-scope-pattern:src/**/*.ts")),
    "the malformed declaration is surfaced at set-time, not left for the first run to gate everything",
  );
});

test("Z170 (b) FRONT-OF-HOUSE: omitting allowedPaths records NOTHING at config time AND refuses nothing", async () => {
  const { tree, pipeline, files, spine } = scenario("src/calc.ts", {});
  assert.equal(scopeDeclarations(spine).length, 0, "an omitted scope declared nothing — no config-time record, byte-identical");

  const result = await pipeline.run({ id: "Z170-omit", text: "bump x in src/calc.ts", repoRef: "repo" }, files);
  assert.equal(await tree.read("src/calc.ts"), AFTER, "the unconstrained default still lands its edit");
  assert.equal(result.solved, true, "a config-time validator must never turn the sanctioned default into a refusal");
});

test("Z170 (b) FRONT-OF-HOUSE: a plain ['*'] run still PROCEEDS — surfacing is observe-only, never a refusal", async () => {
  const { tree, pipeline, files } = scenario("src/calc.ts", { allowedPaths: ["*"] });
  const result = await pipeline.run({ id: "Z170-star", text: "bump x in src/calc.ts", repoRef: "repo" }, files);
  assert.equal(await tree.read("src/calc.ts"), AFTER, "['*'] admits everything inside the root — the edit lands");
  assert.equal(result.solved, true, "the config-time surfacing changes no route — the ['*'] run proceeds exactly as today");
});

test("Z170 WIRING (ledger 298): the declaration seam routes the ACTUAL declared scope through the validator", () => {
  // If the ctor stopped threading `deps.allowedPaths` into assessDeclaredScope (e.g. passed a
  // constant, or dropped the call), a declared over-broad scope would leave NO config-time record.
  // These two shapes prove the seam carries the operator's real declaration, not a fixed value.
  const wide = scenario("src/calc.ts", { allowedPaths: ["*"] });
  const narrow = scenario("src/calc.ts", { allowedPaths: ["src"] });
  assert.equal(scopeDeclarations(wide.spine).length, 1, "a declared wide scope must reach the validator and be recorded");
  assert.equal(scopeDeclarations(narrow.spine).length, 0, "a declared narrow scope proves the record tracks the ACTUAL scope, not a constant");
});
