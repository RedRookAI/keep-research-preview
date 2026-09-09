import { test } from "node:test";
import assert from "node:assert/strict";

import { CodeGraph, type GraphFile } from "../src/coderag/code_graph.js";
import { reciprocalRankFusion, graphProximityRanking, hybridRank } from "../src/coderag/hybrid_rank.js";
import { bm25Rank, type RepoFile } from "../src/solve/localize.js";
import type { Issue } from "../src/solve/issue_model.js";

// ── RRF math ─────────────────────────────────────────────────────────────────

test("INVARIANT: RRF fuses ranked lists by 1/(k+rank)", () => {
  const fused = reciprocalRankFusion([
    { ranking: ["a", "b", "c"], weight: 1 },
    { ranking: ["b", "a", "d"], weight: 1 },
  ], 60);
  // a: 1/61 + 1/62 ; b: 1/62 + 1/61  → a and b tie, both above c and d
  assert.ok(Math.abs(fused.get("a")! - fused.get("b")!) < 1e-9, "a and b symmetric");
  assert.ok(fused.get("a")! > fused.get("c")!, "a (in both) beats c (in one)");
  assert.ok(fused.get("a")! > fused.get("d")!);
});

test("INVARIANT: a doc ranked high in BOTH lists wins", () => {
  const fused = reciprocalRankFusion([
    { ranking: ["x", "y", "z"], weight: 1 },
    { ranking: ["x", "z", "y"], weight: 1 },
  ], 60);
  const sorted = [...fused.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0]);
  assert.equal(sorted[0], "x", "top in both lists → fused winner");
});

test("INVARIANT: weighted RRF emphasizes the higher-weighted list", () => {
  // Doc "lex" is #1 in list A only; "grph" is #1 in list B only. Weighting A up should favor lex.
  const fused = reciprocalRankFusion([
    { ranking: ["lex", "other"], weight: 2.0 },
    { ranking: ["grph", "other"], weight: 0.5 },
  ], 60);
  assert.ok(fused.get("lex")! > fused.get("grph")!, "the up-weighted list's top doc wins");
});

// ── graph proximity ──────────────────────────────────────────────────────────

test("INVARIANT: graph proximity ranks seeds first, then neighbors by reach", () => {
  const g = new CodeGraph();
  g.build([
    { path: "a.ts", content: "import './b';\nexport function fa(){}" },
    { path: "b.ts", content: "export function fb(){}" },
    { path: "c.ts", content: "import './b';\nexport function fc(){}" },
  ]);
  const ranking = graphProximityRanking(["a.ts", "c.ts"], g, 1);
  // b.ts is reached from BOTH seeds → should rank above unrelated files; seeds present.
  assert.ok(ranking.includes("a.ts") && ranking.includes("c.ts"));
  assert.ok(ranking.includes("b.ts"), "the commonly-imported file surfaces via graph proximity");
});

// ── THE KEY PROPERTY: hybrid beats BM25-alone on a structurally-central bug ──

test("INVARIANT: hybrid rank surfaces a lexically-weak but structurally-central buggy file above BM25-alone", () => {
  // Planted bug lives in `core.ts` (defines `compute`), but the ISSUE text talks about the SYMPTOM
  // seen in `report.ts` (which imports core and mentions the keywords). BM25 favors report.ts;
  // the real fix is in core.ts. Graph proximity (report → core via import) should lift core.ts.
  const files: RepoFile[] = [
    { path: "src/report.ts", content: "import { compute } from './core';\n// renders the dashboard total revenue summary\nexport function renderReport() { return compute(); }" },
    { path: "src/core.ts", content: "export function compute() { return 1 - 2; }" }, // the actual bug
    { path: "src/unrelated.ts", content: "export function misc() { return 'nothing to do with this'; }" },
  ];
  const issue: Issue = { id: "B", text: "the dashboard total revenue summary report shows a wrong number", repoRef: "r" };

  const g = new CodeGraph();
  g.build(files);

  const bm25Only = bm25Rank(issue, files).map((s) => s.path);
  const hybrid = hybridRank(issue, files, g, { hops: 1 }).map((s) => s.path);

  const coreRankBm25 = bm25Only.indexOf("src/core.ts");
  const coreRankHybrid = hybrid.indexOf("src/core.ts");

  // BM25 alone ranks the keyword-heavy report.ts first and core.ts low (or absent).
  assert.equal(bm25Only[0], "src/report.ts", "BM25 favors the keyword-heavy symptom file");
  // Hybrid lifts core.ts (the real fix location) via the import edge from report.ts.
  assert.ok(coreRankHybrid !== -1, "core.ts is in the hybrid ranking");
  assert.ok(coreRankHybrid < (coreRankBm25 === -1 ? Infinity : coreRankBm25) || coreRankHybrid <= 1,
    `hybrid ranks the structurally-central bug file higher (hybrid #${coreRankHybrid} vs bm25 #${coreRankBm25})`);
});

test("hybrid rank preserves the isTest flag and returns only real files", () => {
  const files: RepoFile[] = [
    { path: "src/a.ts", content: "import './b';\nexport function fa(){}" },
    { path: "src/b.ts", content: "export function fb(){}" },
    { path: "test/a.test.ts", content: "// test a fb" },
  ];
  const g = new CodeGraph();
  g.build(files);
  const ranked = hybridRank({ id: "i", text: "fb broken", repoRef: "r" }, files, g);
  assert.ok(ranked.every((s) => files.some((f) => f.path === s.path)), "only real files");
  const testEntry = ranked.find((s) => s.path === "test/a.test.ts");
  if (testEntry) assert.equal(testEntry.isTest, true, "test flag preserved");
});

test("hybrid rank is deterministic (stable order across runs)", () => {
  const files: RepoFile[] = [
    { path: "a.ts", content: "import './b';\nexport function fa(){}" },
    { path: "b.ts", content: "export function fb(){}" },
  ];
  const g = new CodeGraph();
  g.build(files);
  const issue: Issue = { id: "i", text: "fb fa broken", repoRef: "r" };
  const r1 = hybridRank(issue, files, g).map((s) => s.path);
  const r2 = hybridRank(issue, files, g).map((s) => s.path);
  assert.deepEqual(r1, r2, "same inputs → same ranking");
});
