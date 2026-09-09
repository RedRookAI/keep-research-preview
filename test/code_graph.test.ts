import { test } from "node:test";
import assert from "node:assert/strict";
import { CodeGraph, type GraphFile } from "../src/coderag/code_graph.js";

const repo: GraphFile[] = [
  { path: "src/auth/token.ts", content: "export function validateToken(t) { return t.expired === false; }" },
  { path: "src/auth/login.ts", content: "import { validateToken } from './token';\nexport function login(u) { return validateToken(u); }" },
  { path: "src/base.ts", content: "export class Base { greet() {} }" },
  { path: "src/derived.ts", content: "import { Base } from './base';\nexport class Derived extends Base { hi() {} }" },
  { path: "src/ui.py", content: "from src.auth.token import validateToken\ndef render():\n    return validateToken(1)" },
];

test("INVARIANT: import edges resolve relative specifiers to real files", () => {
  const g = new CodeGraph();
  g.build(repo);
  const edges = g.allEdges().filter((e) => e.kind === "imports");
  assert.ok(edges.some((e) => e.from === "src/auth/login.ts" && e.to === "src/auth/token.ts"), "login imports token resolved");
});

test("INVARIANT: containment edges link a file to its defined symbols", () => {
  const g = new CodeGraph();
  g.build(repo);
  const contains = g.allEdges().filter((e) => e.kind === "contains" && e.from === "src/auth/token.ts");
  assert.ok(contains.some((e) => e.to === "src/auth/token.ts#validateToken"));
  assert.deepEqual(g.symbolsOf("src/auth/token.ts").map((s) => s.name), ["validateToken"]);
});

test("INVARIANT: cross-file reference edges link a mentioning file to the defining file", () => {
  const g = new CodeGraph();
  g.build(repo);
  const refs = g.allEdges().filter((e) => e.kind === "references");
  assert.ok(refs.some((e) => e.from === "src/auth/login.ts" && e.to === "src/auth/token.ts"), "login references validateToken's file");
});

test("INVARIANT: inheritance edges link a subclass file to the parent's file", () => {
  const g = new CodeGraph();
  g.build(repo);
  const inh = g.allEdges().filter((e) => e.kind === "inherits");
  assert.ok(inh.some((e) => e.from === "src/derived.ts" && e.to === "src/base.ts"), "Derived extends Base resolved cross-file");
});

test("INVARIANT: Python import edges resolve (from X import Y)", () => {
  const g = new CodeGraph();
  g.build(repo);
  const edges = g.allEdges().filter((e) => e.kind === "imports" && e.from === "src/ui.py");
  assert.ok(edges.some((e) => e.to === "src/auth/token.ts"), "python module import resolved to the file");
});

test("INVARIANT: neighbors() does bounded-hop traversal", () => {
  const g = new CodeGraph();
  g.build(repo);
  const oneHop = g.neighbors("src/auth/login.ts", 1);
  assert.ok(oneHop.has("src/auth/token.ts"), "one hop reaches the imported file");
  assert.ok(!oneHop.has("src/auth/login.ts"), "the seed itself is excluded");
});

test("INVARIANT: incremental update() only re-indexes dirty files", () => {
  const g = new CodeGraph();
  g.build(repo);
  // Re-run with identical content → nothing dirty.
  const noChange = g.update(repo);
  assert.equal(noChange.length, 0, "unchanged files are skipped");
  // Change one file → only it is dirty.
  const changed = repo.map((f) => f.path === "src/auth/token.ts" ? { ...f, content: f.content + "\nexport function extra() {}" } : f);
  const dirty = g.update(changed);
  assert.deepEqual(dirty, ["src/auth/token.ts"], "only the changed file re-indexed");
  assert.ok(g.symbolsOf("src/auth/token.ts").some((s) => s.name === "extra"), "new symbol picked up");
});

test("INVARIANT: update() drops files that disappeared", () => {
  const g = new CodeGraph();
  g.build(repo);
  const fewer = repo.filter((f) => f.path !== "src/derived.ts");
  const dirty = g.update(fewer);
  assert.ok(dirty.includes("src/derived.ts"), "removed file reported dirty");
  assert.equal(g.symbolsOf("src/derived.ts").length, 0, "removed file's symbols gone");
});

test("a file in an unparseable language is handled gracefully", () => {
  const g = new CodeGraph();
  g.build([{ path: "notes.md", content: "# just markdown, no code" }, ...repo]);
  assert.equal(g.symbolsOf("notes.md").length, 0, "no symbols, no crash");
  assert.ok(g.fileCount >= repo.length);
});
