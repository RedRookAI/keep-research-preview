import { test } from "node:test";
import assert from "node:assert/strict";

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { HierarchicalLocalizer, bm25Rank, isTestFile, extractSymbols, type RepoFile } from "../src/solve/localize.js";
import { planEdits, parseEditPlan } from "../src/solve/edit_planner.js";
import type { Issue } from "../src/solve/issue_model.js";

const issue = (text: string): Issue => ({ id: "i1", text, repoRef: "r" });

const files: RepoFile[] = [
  { path: "src/auth/login.ts", content: "export function login(user) { return validateToken(user); }" },
  { path: "src/auth/token.ts", content: "export function validateToken(t) { return t.expired === false; }" },
  { path: "src/ui/button.ts", content: "export function Button() { return render(); }" },
  { path: "test/login.test.ts", content: "test('login validateToken token expired user', () => {});" },
];

// A fake model that returns whatever text is configured (stands in for the replay provider).
class ScriptedModel implements ModelProvider {
  readonly name = "scripted";
  readonly isLocal = true;
  constructor(private readonly text: string) {}
  async generate(_req: GenerateRequest): Promise<GenerateResult> { return { text: this.text, model: this.name, tokensIn: 1, tokensOut: 1 }; }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}
class FailingModel implements ModelProvider {
  readonly name = "failing";
  readonly isLocal = true;
  async generate(): Promise<GenerateResult> { throw new Error("model down"); }
  async embed(): Promise<Embedding[]> { return []; }
}

// ── Stage 1: BM25 ────────────────────────────────────────────────────────────

test("INVARIANT: BM25 ranks the file matching the issue keywords first", () => {
  const ranked = bm25Rank(issue("validateToken returns wrong value when token expired"), files);
  assert.equal(ranked[0]!.path, "src/auth/token.ts", "the file defining validateToken ranks first");
});

test("INVARIANT: test files are down-weighted (avoid test-file over-prediction)", () => {
  // The test file is keyword-dense but must not outrank the real source file.
  const ranked = bm25Rank(issue("validateToken token expired user"), files);
  const testIdx = ranked.findIndex((s) => s.path === "test/login.test.ts");
  const srcIdx = ranked.findIndex((s) => s.path === "src/auth/token.ts");
  assert.ok(srcIdx < testIdx || testIdx === -1, "source file outranks the keyword-dense test file");
});

test("INVARIANT: an explicit filename mention boosts that file", () => {
  const ranked = bm25Rank(issue("the bug is in button.ts somewhere"), files);
  assert.equal(ranked[0]!.path, "src/ui/button.ts", "filename mention wins");
});

test("isTestFile detects common test path/name conventions", () => {
  assert.equal(isTestFile("test/login.test.ts"), true);
  assert.equal(isTestFile("src/foo_test.py"), true);
  assert.equal(isTestFile("tests/thing.spec.js"), true);
  assert.equal(isTestFile("src/auth/login.ts"), false);
});

// ── Localizer modes ──────────────────────────────────────────────────────────

test("INVARIANT: deterministic mode (no model) returns the BM25 top-K", async () => {
  const loc = new HierarchicalLocalizer(); // no model
  const r = await loc.localize(issue("validateToken token expired"), files, 2);
  assert.equal(r.stages.length, 1);
  assert.equal(r.stages[0], "bm25");
  assert.equal(r.suspects.length, 2, "top-K, ranked");
  assert.equal(r.suspects[0]!.path, "src/auth/token.ts");
});

test("INVARIANT: LLM re-rank narrows to suspect symbols", async () => {
  const model = new ScriptedModel(JSON.stringify({ suspects: [{ path: "src/auth/token.ts", symbols: ["validateToken"] }] }));
  const loc = new HierarchicalLocalizer(model);
  const r = await loc.localize(issue("validateToken token expired"), files, 3);
  assert.ok(r.stages.includes("llm-rerank"));
  assert.equal(r.suspects[0]!.path, "src/auth/token.ts");
  assert.deepEqual(r.suspects[0]!.suspectSymbols, ["validateToken"], "narrowed to the suspect function");
});

test("INVARIANT: graceful fallback to BM25 when the model fails", async () => {
  const loc = new HierarchicalLocalizer(new FailingModel());
  const r = await loc.localize(issue("validateToken token expired"), files, 2);
  assert.equal(r.suspects[0]!.path, "src/auth/token.ts", "BM25 floor holds when the model throws");
});

test("INVARIANT: LLM selection is constrained to the candidate set (no hallucinated paths)", async () => {
  const model = new ScriptedModel(JSON.stringify({ suspects: [{ path: "nonexistent/hallucinated.ts" }, { path: "src/auth/token.ts" }] }));
  const loc = new HierarchicalLocalizer(model);
  const r = await loc.localize(issue("validateToken"), files, 3);
  assert.ok(r.suspects.every((s) => files.some((f) => f.path === s.path)), "only real candidate paths survive");
});

test("extractSymbols finds functions and classes", () => {
  const syms = extractSymbols("function foo() {}\nclass Bar {}\nconst baz = () => {}");
  assert.ok(syms.includes("foo"));
  assert.ok(syms.includes("Bar"));
  assert.ok(syms.includes("baz"));
});

// ── Edit planner ─────────────────────────────────────────────────────────────

test("INVARIANT: parseEditPlan parses strict JSON into typed edits", () => {
  const allowed = new Set(["src/auth/token.ts"]);
  const plan = parseEditPlan(JSON.stringify({
    rationale: "fix the comparison",
    edits: [{ file: "src/auth/token.ts", search: "t.expired === false", replace: "t.expired !== true", intent: "fix" }],
  }), allowed);
  assert.equal(plan.edits.length, 1);
  assert.equal(plan.edits[0]!.search, "t.expired === false");
  assert.equal(plan.rationale, "fix the comparison");
});

test("INVARIANT: edits outside the localized files are rejected", () => {
  const allowed = new Set(["src/auth/token.ts"]);
  const plan = parseEditPlan(JSON.stringify({
    edits: [{ file: "src/evil/other.ts", search: "x", replace: "y", intent: "sneaky" }],
  }), allowed);
  assert.equal(plan.edits.length, 0, "never edit outside the localized set");
});

test("INVARIANT: empty-search edits are rejected (would match everything)", () => {
  const allowed = new Set(["a.ts"]);
  const plan = parseEditPlan(JSON.stringify({ edits: [{ file: "a.ts", search: "", replace: "y", intent: "x" }] }), allowed);
  assert.equal(plan.edits.length, 0);
});

test("INVARIANT: malformed model output yields an empty plan (graceful, no throw)", () => {
  const allowed = new Set(["a.ts"]);
  assert.equal(parseEditPlan("this is not json at all", allowed).edits.length, 0);
  assert.equal(parseEditPlan("{ broken json", allowed).edits.length, 0);
});

test("planEdits threads localized files + repair context and returns typed edits", async () => {
  const model = new ScriptedModel("```json\n" + JSON.stringify({
    rationale: "r",
    edits: [{ file: "src/auth/token.ts", search: "t.expired === false", replace: "t.expired !== true", intent: "fix" }],
  }) + "\n```");
  const localization = { suspects: [{ path: "src/auth/token.ts", score: 5, isTest: false }], stages: ["bm25" as const] };
  const plan = await planEdits(issue("token check inverted"), localization, files, model, { repairContext: "AssertionError: expected true" });
  assert.equal(plan.edits.length, 1, "parses even with markdown fences around JSON");
  assert.equal(plan.edits[0]!.file, "src/auth/token.ts");
});
