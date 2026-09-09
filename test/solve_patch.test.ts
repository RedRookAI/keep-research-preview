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

import { InMemoryFileTree, applyEditPlan, canApply } from "../src/solve/patch.js";
import type { EditPlan } from "../src/solve/issue_model.js";

function newLedger(): RollbackLedger {
  const dir = mkdtempSync(join(tmpdir(), "keep-patch-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  return new RollbackLedger(spine);
}

function plan(edits: EditPlan["edits"]): EditPlan {
  return { edits, rationale: "test" };
}

test("INVARIANT: an exact, unique search block applies and changes content", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "function f() { return 1; }" });
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "return 1;", replace: "return 2;", intent: "fix" }]),
    tree, newLedger(), { issueId: "i1" },
  );
  assert.equal(r.applied, true);
  assert.equal((await tree.read("a.ts")), "function f() { return 2; }");
});

test("INVARIANT: a not-found search block is rejected (plan not applied)", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "return 1;" });
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "does not exist", replace: "x", intent: "fix" }]),
    tree, newLedger(), { issueId: "i2" },
  );
  assert.equal(r.applied, false);
  assert.equal(r.perEdit[0]!.status, "not-found");
  assert.equal(await tree.read("a.ts"), "return 1;", "file untouched");
});

test("INVARIANT: an ambiguous (2+ match) search block is rejected — never a wrong apply", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "x = 1; y = 1;" });
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "1", replace: "2", intent: "fix" }]),
    tree, newLedger(), { issueId: "i3" },
  );
  assert.equal(r.applied, false);
  assert.equal(r.perEdit[0]!.status, "ambiguous");
  assert.equal(await tree.read("a.ts"), "x = 1; y = 1;", "file untouched on ambiguity");
});

test("INVARIANT: all-or-nothing — a failing edit means NO file is modified", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "aaa", "b.ts": "bbb" });
  const r = await applyEditPlan(
    plan([
      { file: "a.ts", search: "aaa", replace: "AAA", intent: "ok" },
      { file: "b.ts", search: "not-there", replace: "X", intent: "fails" },
    ]),
    tree, newLedger(), { issueId: "i4" },
  );
  assert.equal(r.applied, false);
  assert.equal(await tree.read("a.ts"), "aaa", "first file NOT modified despite being valid (all-or-nothing)");
  assert.equal(await tree.read("b.ts"), "bbb");
});

test("commit failure after an earlier member restores the whole edit batch", async () => {
  const files = new Map([["a.ts", "aaa"], ["b.ts", "bbb"]]);
  let failed = false;
  const tree = {
    async read(path: string) { return files.get(path); },
    async write(path: string, content: string) {
      if (path === "b.ts" && !failed) { failed = true; throw new Error("injected second-write failure"); }
      files.set(path, content);
    },
  };
  await assert.rejects(applyEditPlan(plan([
    { file: "a.ts", search: "aaa", replace: "AAA", intent: "first" },
    { file: "b.ts", search: "bbb", replace: "BBB", intent: "second" },
  ]), tree, newLedger(), { issueId: "commit-failure" }), /injected second-write failure/);
  assert.equal(files.get("a.ts"), "aaa", "the successful first write was compensated");
  assert.equal(files.get("b.ts"), "bbb");
});

test("a write that mutates and then reports failure is also compensated", async () => {
  const files = new Map([["a.ts", "aaa"]]);
  let failed = false;
  const tree = {
    async read(path: string) { return files.get(path); },
    async write(path: string, content: string) {
      files.set(path, content);
      if (!failed) { failed = true; throw new Error("post-write durability failure"); }
    },
  };
  await assert.rejects(applyEditPlan(plan([{ file: "a.ts", search: "aaa", replace: "AAA", intent: "write" }]), tree, newLedger(), { issueId: "write-then-throw" }), /post-write durability failure/);
  assert.equal(files.get("a.ts"), "aaa");
});

test("multiple edits to the same file apply sequentially", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "const x = 1; const y = 2;" });
  const r = await applyEditPlan(
    plan([
      { file: "a.ts", search: "const x = 1;", replace: "const x = 10;", intent: "e1" },
      { file: "a.ts", search: "const y = 2;", replace: "const y = 20;", intent: "e2" },
    ]),
    tree, newLedger(), { issueId: "i5" },
  );
  assert.equal(r.applied, true);
  assert.equal(await tree.read("a.ts"), "const x = 10; const y = 20;");
});

test("INVARIANT: RollbackLedger undo restores the exact original content", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "original", "b.ts": "keep" });
  const ledger = newLedger();
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "original", replace: "modified", intent: "fix" }]),
    tree, ledger, { issueId: "i6" },
  );
  assert.equal(r.applied, true);
  assert.equal(await tree.read("a.ts"), "modified");
  await ledger.rollback(1, "test rollback");
  assert.equal(await tree.read("a.ts"), "original", "undo restored original content exactly");
  assert.equal(await tree.read("b.ts"), "keep", "untouched file unaffected");
});

test("canApply dry-run predicts applicability", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "hello world" });
  assert.equal(await canApply(plan([{ file: "a.ts", search: "hello", replace: "hi", intent: "x" }]), tree), true);
  assert.equal(await canApply(plan([{ file: "a.ts", search: "nope", replace: "x", intent: "x" }]), tree), false);
});

// ── Whitespace-tolerant fuzzy fallback (SOTA hardening — CodeStruct/Hermes-agent 2026) ──

import { fuzzyFind, reindent } from "../src/solve/patch.js";

test("INVARIANT: exact-only by default — a whitespace-mismatched edit is REJECTED without fuzzyFallback", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "function f() {\n\treturn 1;\n}" }); // tab indent
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "    return 1;", replace: "    return 2;", intent: "fix" }]), // spaces
    tree, newLedger(), { issueId: "ws1" }, // no fuzzyFallback
  );
  assert.equal(r.applied, false, "default posture stays strict exact-match");
});

test("INVARIANT: fuzzyFallback applies a tab/space-mismatched edit with correct reindentation", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "function f() {\n\treturn 1;\n}" }); // tab
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "    return 1;", replace: "    return 2;", intent: "fix" }]), // spaces
    tree, newLedger(), { issueId: "ws2", fuzzyFallback: true },
  );
  assert.equal(r.applied, true, "fuzzy fallback matched across the whitespace difference");
  const content = await tree.read("a.ts");
  assert.equal(content, "function f() {\n\treturn 2;\n}", "replacement re-indented to the file's tab base");
});

test("INVARIANT: fuzzy fallback still REFUSES an ambiguous match (never-wrong-apply preserved)", async () => {
  const tree = new InMemoryFileTree({ "a.ts": "\treturn 1;\n\treturn 1;" }); // two tab-indented matches
  const r = await applyEditPlan(
    plan([{ file: "a.ts", search: "return 1;", replace: "return 2;", intent: "fix" }]),
    tree, newLedger(), { issueId: "ws3", fuzzyFallback: true },
  );
  assert.equal(r.applied, false, "ambiguous fuzzy match is refused, not guessed");
});

test("fuzzyFind returns null for absent or ambiguous, a match for unique", () => {
  assert.equal(fuzzyFind("a\nb\nc", "zzz"), null, "absent → null");
  assert.equal(fuzzyFind("\tx = 1;\n\tx = 1;", "x = 1;"), null, "ambiguous → null");
  const m = fuzzyFind("class C {\n        method() {}\n}", "  method() {}");
  assert.ok(m, "unique whitespace-diff match found");
});

test("reindent shifts a zero-indent replacement to the file's indent base", () => {
  const out = reindent("return 2;", "        ", ""); // model sent 0 indent; file has 8 spaces
  assert.equal(out, "        return 2;");
});
