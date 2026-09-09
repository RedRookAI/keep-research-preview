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
import { IdentityRegistry } from "../src/identity/agent_identity.js";
import { structuralFloor, defaultFloorPolicy, type FloorPolicy } from "../src/floor/structural_floor.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";

/**
 * BUILD-ORDER 2.2 (AUTHORIZE-THE-DECLARATION) — Z156.
 *
 * Round 38 authorized the DECLARATION against the OPERATOR's global `allowedPaths`. But that
 * allowlist is IDENTICAL for every agent, issue and operator. The acting agent already carries a
 * narrow, per-task `identity.scope` with ATTENUATING delegation (a child scope is the intersection
 * with its parent) — yet on the solve path that scope reached the floor NOT AT ALL. An agent's
 * effective write authority was "what the agent alone can declare for itself", not "the
 * INTERSECTION of what BOTH the agent and the requesting operator are permitted to do" — the
 * confused-deputy shape.
 *
 * This round composes the agent's scope into the floor as a SECOND authority, via the SAME
 * `withinScope` predicate (not a second path-authority mechanism — round 37 refused that in the
 * other direction). A declared write must be within BOTH `allowedPaths` AND `agentScope`.
 *
 * The tests are split into two layers, each paired with an isolating neuter recorded in the round
 * artifacts:
 *   - FLOOR (unit): the intersection is computed and NAMED at the floor.
 *   - WIRING (pipeline, ledger 298): the solve seam actually ROUTES `identity.scope` into the floor
 *     authorization — a green floor with a dead wire would be a control that never runs.
 */

// ── FLOOR (unit): the per-agent conjunct is computed and named ────────────────────────────────

const op = (writeSet: string[]) => ({ kind: "file.edit", writeSet, targets: writeSet, hasInverse: true, raw: "x" });

/** A policy that permits `src` for the operator and (optionally) narrows the acting agent further. */
function policy(allowedPaths: string[], agentScope?: string[]): FloorPolicy {
  const base = defaultFloorPolicy("repo", allowedPaths);
  return agentScope === undefined ? base : { ...base, agentScope };
}

test("2.2 (a): a write inside allowedPaths but OUTSIDE the agent scope is REFUSED, and the path is NAMED", () => {
  // Disproof (a): the intersection is the control. `src/calc.ts` is inside the operator allowlist
  // (`src`) but outside the acting agent's scope (`src/feature`), so the agent's OWN authority — not
  // the operator's — must exclude it. Neuter: drop the agent-scope conjunct in the floor -> this
  // reddens (RED-a).
  const v = structuralFloor(op(["src/calc.ts"]), policy(["src"], ["src/feature"]));
  assert.equal(v.verdict, "gate", "an out-of-agent-scope write must not be reversible-class");
  assert.ok(
    v.reasons.some((r) => r.includes("write-set-outside-agent-scope:src/calc.ts")),
    `the refusal must NAME the path and the agent authority; got ${JSON.stringify(v.reasons)}`,
  );
  // HONEST: it must say the AGENT scope excluded it, distinct from the operator allowlist, so the
  // operator widens the right boundary (Z133). The operator-allowlist reason must NOT fire here.
  assert.ok(!v.reasons.some((r) => r.includes("write-set-outside-allowed-scope")), "the operator allowlist did permit it — only the agent scope refused");
});

test("2.2: a write inside BOTH the operator allowlist AND the agent scope is reversible-class", () => {
  // The intersection only NARROWS; a write both parties permit still proceeds. The intersection is
  // the sole variable between this and the previous test.
  const v = structuralFloor(op(["src/feature/x.ts"]), policy(["src"], ["src/feature"]));
  assert.equal(v.verdict, "reversible-execute");
});

test("2.2: omitting agentScope is provably INERT at the floor — the SAME op is reversible-class", () => {
  // Disproof (b), floor half. The exact op that gates under an agent scope must proceed when no
  // agent scope is present — or the control would change behaviour for every no-identity caller.
  const withScope = structuralFloor(op(["src/calc.ts"]), policy(["src"], ["src/feature"]));
  const withoutScope = structuralFloor(op(["src/calc.ts"]), policy(["src"]));
  assert.equal(withScope.verdict, "gate", "with the agent scope: refused");
  assert.equal(withoutScope.verdict, "reversible-execute", "omitted agent scope: unconstrained, byte-identical to R38");
});

test("2.2: the agent scope can only NARROW — a wide agent scope cannot re-admit an out-of-allowlist write", () => {
  // The disconfirming case made concrete: authority is the INTERSECTION, attenuating only. An agent
  // scope of ["*"] cannot widen the operator's `src`-only allowlist to admit a `tools/` write.
  const v = structuralFloor(op(["tools/gen.ts"]), policy(["src"], ["*"]));
  assert.equal(v.verdict, "gate", "a wide agent scope must not widen the operator allowlist");
  assert.ok(v.reasons.some((r) => r.includes("write-set-outside-allowed-scope:tools/gen.ts")), "the operator allowlist still refuses it");
});

test("2.2: an UNDECLARED write-set is refused under an agent scope — unknown resolves to caution", () => {
  // Mirrors `firstPathOutsideAllowedScope` rather than inventing a second convention for the unknown.
  const v = structuralFloor({ kind: "file.edit", hasInverse: true, raw: "x" }, policy(["src"], ["src/feature"]));
  assert.equal(v.verdict, "gate");
  assert.ok(v.reasons.some((r) => r.includes("write-set-outside-agent-scope:<undeclared-write-set>")));
});

test("2.2: a MALFORMED agent scope is reported loudly, not silently refusing everything (Z135 parity)", () => {
  // Parity with `allowedPaths`: `src/*.ts` (slash + `*`) is unsupported; left silent it matches
  // nothing via `withinScope` and refuses every write for that agent, reading as "the control is
  // broken". It must be named as the operator's bug instead.
  const v = structuralFloor(op(["src/a.ts"]), policy(["src"], ["src/*.ts"]));
  assert.equal(v.verdict, "gate");
  assert.ok(
    v.reasons.some((r) => r.includes("unsupported-agent-scope-pattern:src/*.ts")),
    `a malformed agent scope must be named; got ${JSON.stringify(v.reasons)}`,
  );
});

// ── WIRING (pipeline, ledger 298): the solve seam routes identity.scope into the floor ─────────

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r-authz-decl-"))), new InProcessLock(), new SchemaRegistry());
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

const ISSUE: Issue = { id: "AUTHZ-DECL-1", text: "add() subtracts instead of adding in calc.ts", repoRef: "repo" };
const FILES: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
const PLAN = JSON.stringify({
  rationale: "the operator was inverted",
  edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "use + not -" }],
});
const FIXED = "export function add(a, b) { return a + b; }";
const BROKEN = "export function add(a, b) { return a - b; }";

function calcRunner(tree: InMemoryFileTree): TestRunner {
  return {
    async run(): Promise<TestRunResult> {
      const content = (await tree.read("src/calc.ts")) ?? "";
      const correct = content.includes("a + b");
      return { results: [{ name: "add(2,3)==5", passed: correct, ...(correct ? {} : { output: "expected 5, got -1" }) }] };
    },
  };
}

/** A pipeline on the ENVELOPE branch (where `executeReversibly` — and the identity wire — runs). */
function envelopePipeline(extra: Record<string, unknown>) {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(FILES.map((f) => [f.path, f.content])));
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model: new PlanModel(PLAN),
    reversibleEnvelope: true, ...extra,
  } as never);
  return { tree, pipeline };
}

test("2.2 WIRING: an acting identity whose scope EXCLUDES the file refuses on the COMPOSED path, tree untouched", async () => {
  // The wiring neuter target (ledger 298). The operator allowlist (`src`) PERMITS src/calc.ts; only
  // the acting agent's identity.scope (`src/feature`) excludes it. If the seam stops routing
  // `identity.scope` into the floor, the file lands and this reddens (RED-c). Asserting on the TREE
  // is the strongest evidence — it is the actual effect the control exists to bound.
  const registry = new IdentityRegistry();
  const identity = registry.mint("narrow-agent", ["src/feature"]);
  const { pipeline, tree } = envelopePipeline({ identity, identityRegistry: registry, allowedPaths: ["src"] });

  const result = await pipeline.run(ISSUE, FILES);

  assert.equal(await tree.read("src/calc.ts"), BROKEN, "a write outside the acting agent's scope must not land");
  assert.equal(result.solved, false, "an out-of-agent-scope write must not produce a solved run");
  assert.match(
    result.gaveUpReason ?? "", /write-set-outside-agent-scope:src\/calc\.ts/,
    "the operator must learn the ACTING AGENT's scope refused it, and which file",
  );
});

test("2.2 WIRING front-of-house: a NO-IDENTITY run with the same allowlist lands the file (byte-identical)", async () => {
  // Disproof (b), wiring half. With no identity supplied the agent-scope conjunct is absent, so the
  // same in-allowlist edit that the previous test refused now lands. Neuter the wiring to apply an
  // agent scope even without an identity and this reddens (RED-b).
  const { pipeline, tree } = envelopePipeline({ allowedPaths: ["src"] });

  const result = await pipeline.run(ISSUE, FILES);

  assert.equal(await tree.read("src/calc.ts"), FIXED, "no identity ⇒ no per-agent constraint ⇒ unchanged behaviour");
  assert.equal(result.solved, true);
});

test("2.2 WIRING: the SAME plan proceeds when the agent scope COVERS the file — identity is the only variable", async () => {
  // The identity is the sole difference from the refusing test: same operator allowlist, same plan,
  // an identity scope that includes `src`. In-scope work is untouched by the control.
  const registry = new IdentityRegistry();
  const identity = registry.mint("covering-agent", ["src"]);
  const { pipeline, tree } = envelopePipeline({ identity, identityRegistry: registry, allowedPaths: ["src"] });

  const result = await pipeline.run(ISSUE, FILES);

  assert.equal(await tree.read("src/calc.ts"), FIXED, "an in-scope write is untouched by the per-agent control");
  assert.equal(result.solved, true);
});

test("2.2 WIRING: a DELEGATED identity carries its ATTENUATED scope to the floor", async () => {
  // Delegation attenuates: a child of a parent scoped to `src` that requests `["src/feature",
  // "tools"]` receives only `["src/feature"]` — the `tools` request is dropped (not within the
  // parent) and the intersection narrows to the sub-tree. That attenuated scope must be what reaches
  // the floor, so the child cannot touch src/calc.ts even though the operator allowlist permits it.
  const registry = new IdentityRegistry();
  const parent = registry.mint("parent-agent", ["src"]);
  const child = registry.delegate(parent, "child-agent", ["src/feature", "tools"]);
  assert.ok(child, "delegation from a live parent must succeed");
  assert.deepEqual(child!.scope, ["src/feature"], "the child scope is the attenuated intersection (tools dropped)");

  const { pipeline, tree } = envelopePipeline({ identity: child, identityRegistry: registry, allowedPaths: ["src"] });
  const result = await pipeline.run(ISSUE, FILES);

  assert.equal(await tree.read("src/calc.ts"), BROKEN, "the attenuated child scope must bound the declared write");
  assert.equal(result.solved, false);
});
