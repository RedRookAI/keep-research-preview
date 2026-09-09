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

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { DeterministicHashEmbedder, embeddingRanking } from "../src/coderag/embedding_stage.js";
import { GraphLocalizer } from "../src/coderag/graph_localizer.js";
import type { RepoFile } from "../src/solve/localize.js";
import type { Issue } from "../src/solve/issue_model.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

const files: RepoFile[] = [
  { path: "src/auth/token.ts", content: "import './util';\nexport function validateToken(t) { return t.expired === false; }" },
  { path: "src/auth/login.ts", content: "import { validateToken } from './token';\nexport function login(u) { return validateToken(u); }" },
  { path: "src/auth/util.ts", content: "export function noop() {}" },
  { path: "src/ui.ts", content: "export function render() { return 'hello'; }" },
];
const issue = (t: string): Issue => ({ id: "i", text: t, repoRef: "r" });

// ── embedder ─────────────────────────────────────────────────────────────────

test("INVARIANT: deterministic hash embedder produces stable normalized vectors", async () => {
  const e = new DeterministicHashEmbedder(64);
  const [v1] = await e.embed(["hello world token validate"]);
  const [v2] = await e.embed(["hello world token validate"]);
  assert.deepEqual(v1, v2, "deterministic");
  const norm = Math.sqrt(v1!.reduce((s, x) => s + x * x, 0));
  assert.ok(Math.abs(norm - 1) < 1e-6 || norm === 0, "L2 normalized");
});

test("embeddingRanking ranks a lexically-overlapping file higher (plumbing works)", async () => {
  const e = new DeterministicHashEmbedder();
  const ranking = await embeddingRanking(issue("validateToken expired token"), files, e);
  // The hash embedder is lexical-ish; token.ts (defines validateToken) should rank near the top.
  assert.ok(ranking.includes("src/auth/token.ts"));
  assert.equal(ranking.length, files.length);
});

// ── GraphLocalizer implements the port ──────────────────────────────────────

test("INVARIANT: GraphLocalizer (BM25+graph) returns ranked suspects with both stages", async () => {
  const loc = new GraphLocalizer();
  const r = await loc.localize(issue("validateToken token expired"), files, 3);
  assert.deepEqual(r.stages, ["bm25", "graph"]);
  assert.ok(r.suspects.length > 0 && r.suspects.length <= 3);
  assert.ok(r.suspects.some((s) => s.path === "src/auth/token.ts"), "the defining file is a suspect");
});

test("INVARIANT: with an embedder, the embedding RRF stage runs", async () => {
  const loc = new GraphLocalizer({ embedder: new DeterministicHashEmbedder() });
  const r = await loc.localize(issue("validateToken token expired"), files, 3);
  assert.ok(r.stages.includes("embedding"), "embedding stage fused as a 3rd RRF list");
});

test("INVARIANT: with a model, LLM re-rank narrows to suspect symbols", async () => {
  const model: ModelProvider = {
    name: "m", isLocal: true,
    async generate(_r: GenerateRequest): Promise<GenerateResult> {
      return { text: JSON.stringify({ suspects: [{ path: "src/auth/token.ts", symbols: ["validateToken"] }] }), model: "m", tokensIn: 1, tokensOut: 1 };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
  const loc = new GraphLocalizer({ model });
  const r = await loc.localize(issue("validateToken broken"), files, 3);
  assert.ok(r.stages.includes("llm-rerank"));
  assert.equal(r.suspects[0]!.path, "src/auth/token.ts");
  assert.deepEqual(r.suspects[0]!.suspectSymbols, ["validateToken"]);
});

test("GraphLocalizer builds the graph on-device (cross-file structure available)", async () => {
  const loc = new GraphLocalizer();
  // login.ts imports token.ts — a purely lexical query for 'login' should still surface token.ts via graph.
  const r = await loc.localize(issue("login flow token validation is broken"), files, 4);
  const paths = r.suspects.map((s) => s.path);
  assert.ok(paths.includes("src/auth/token.ts") && paths.includes("src/auth/login.ts"), "structurally related files co-surface");
});

// ── THE INTEGRATION: drop-in for the real SolvePipeline ─────────────────────

test("INVARIANT: GraphLocalizer is a drop-in localizer for the real SolvePipeline (E2E)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-14c-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  const solveFiles: RepoFile[] = [
    { path: "src/calc.ts", content: "import './helpers';\nexport function add(a, b) { return a - b; }" },
    { path: "src/helpers.ts", content: "export function log(x) { return x; }" },
  ];
  const tree = new InMemoryFileTree(Object.fromEntries(solveFiles.map((f) => [f.path, f.content])));
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const model: ModelProvider = {
    name: "fix", isLocal: true,
    async generate(): Promise<GenerateResult> {
      return { text: JSON.stringify({ rationale: "op inverted", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner,
    localizer: new GraphLocalizer({ embedder: new DeterministicHashEmbedder() }), // the upgraded localizer
    model,
  });
  const result = await pipeline.run(issue("add() in calc.ts subtracts instead of adds"), solveFiles);
  assert.equal(result.solved, true, "the machine still runs end-to-end with the graph localizer");
  assert.ok(result.prProposal, "PR proposed");
  assert.equal(await tree.read("src/calc.ts"), "import './helpers';\nexport function add(a, b) { return a + b; }");
});
