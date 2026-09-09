/**
 * Local decontaminated eval suite (Increment 4.2) — self-authored, NOVEL bug instances written for this repo, never
 * drawn from GitHub or any public benchmark, and dated after any plausible model cutoff. They therefore pass the
 * decontamination gates by construction (no temporal/solution/known-eval leakage), which lets us produce a REAL
 * resolved-rate here without contamination confounds.
 *
 * This is NOT the official SWE-bench Verified set (that needs the real dataset + a frontier model + Docker-at-scale —
 * the remaining VERIFIED-SEAM). It is a genuine, contamination-controlled micro-suite that exercises the SAME oracle
 * (FAIL_TO_PASS flips + PASS_TO_PASS holds) and the SAME harness that a full run would.
 *
 * Each instance ships the buggy tree, the GOLD-patched tree (for harness validation / oracle runs — never shown to the
 * solver), and node:test files whose test names match the failToPass / passToPass identifiers so per-test TAP parsing
 * can judge resolution exactly.
 */

import type { EvalTask } from "./swebench_task.js";

export interface LocalEvalInstance {
  readonly task: EvalTask;
  /** Buggy repo files (path → content) — the pre-fix tree the solver sees. */
  readonly files: Readonly<Record<string, string>>;
  /** Gold-patched files (only the changed ones) — applied by an oracle run to validate the harness. */
  readonly goldFiles: Readonly<Record<string, string>>;
}

const CREATED = "2026-07-01"; // after any plausible in-repo model cutoff → passes temporal decontamination

function f2p(name: string, body: string): string {
  return `import { test } from "node:test";\nimport assert from "node:assert/strict";\n${body.replace("__NAME__", name)}\n`;
}

export const LOCAL_SUITE: readonly LocalEvalInstance[] = [
  // 1) Wrong operator: add subtracts.
  {
    task: {
      instanceId: "local__add-operator", repo: "local/mathkit", baseCommit: "base",
      problemStatement: "add(a, b) returns the difference instead of the sum. It should return a + b.",
      failToPass: ["add_returns_sum"], passToPass: ["add_is_callable"],
      goldPatch: "--- a/src/math.mjs\n+++ b/src/math.mjs\n@@\n-export const add = (a, b) => a - b;\n+export const add = (a, b) => a + b;\n",
      createdAt: CREATED,
    },
    files: {
      "src/math.mjs": "export const add = (a, b) => a - b;\n",
      "tests/f2p.test.mjs": `import { test } from "node:test";\nimport assert from "node:assert/strict";\nimport { add } from "../src/math.mjs";\ntest("add_returns_sum", () => assert.equal(add(2, 3), 5));\n`,
      "tests/p2p.test.mjs": `import { test } from "node:test";\nimport assert from "node:assert/strict";\nimport { add } from "../src/math.mjs";\ntest("add_is_callable", () => assert.equal(typeof add, "function"));\n`,
    },
    goldFiles: { "src/math.mjs": "export const add = (a, b) => a + b;\n" },
  },
  // 2) Off-by-one: upto(n) omits the last element.
  {
    task: {
      instanceId: "local__upto-offbyone", repo: "local/mathkit", baseCommit: "base",
      problemStatement: "upto(n) should return [0, 1, ..., n-1] but drops the final element (off-by-one in the loop bound).",
      failToPass: ["upto_full_range"], passToPass: ["upto_empty_for_zero"],
      goldPatch: "--- a/src/range.mjs\n+++ b/src/range.mjs\n@@\n-  for (let i = 0; i < n - 1; i++) out.push(i);\n+  for (let i = 0; i < n; i++) out.push(i);\n",
      createdAt: CREATED,
    },
    files: {
      "src/range.mjs": "export const upto = (n) => {\n  const out = [];\n  for (let i = 0; i < n - 1; i++) out.push(i);\n  return out;\n};\n",
      "tests/f2p.test.mjs": `import { test } from "node:test";\nimport assert from "node:assert/strict";\nimport { upto } from "../src/range.mjs";\ntest("upto_full_range", () => assert.deepEqual(upto(3), [0, 1, 2]));\n`,
      "tests/p2p.test.mjs": `import { test } from "node:test";\nimport assert from "node:assert/strict";\nimport { upto } from "../src/range.mjs";\ntest("upto_empty_for_zero", () => assert.deepEqual(upto(0), []));\n`,
    },
    goldFiles: { "src/range.mjs": "export const upto = (n) => {\n  const out = [];\n  for (let i = 0; i < n; i++) out.push(i);\n  return out;\n};\n" },
  },
  // 3) Missing guard: first([]) throws instead of returning "".
  {
    task: {
      instanceId: "local__first-guard", repo: "local/strkit", baseCommit: "base",
      problemStatement: "first(arr) throws on an empty array. It should return an empty string when the array is empty.",
      failToPass: ["first_handles_empty"], passToPass: ["first_trims_value"],
      goldPatch: "--- a/src/first.mjs\n+++ b/src/first.mjs\n@@\n-export const first = (arr) => arr[0].trim();\n+export const first = (arr) => (arr.length ? arr[0].trim() : \"\");\n",
      createdAt: CREATED,
    },
    files: {
      "src/first.mjs": "export const first = (arr) => arr[0].trim();\n",
      "tests/f2p.test.mjs": `import { test } from "node:test";\nimport assert from "node:assert/strict";\nimport { first } from "../src/first.mjs";\ntest("first_handles_empty", () => assert.equal(first([]), ""));\n`,
      "tests/p2p.test.mjs": `import { test } from "node:test";\nimport assert from "node:assert/strict";\nimport { first } from "../src/first.mjs";\ntest("first_trims_value", () => assert.equal(first([" hi "]), "hi"));\n`,
    },
    goldFiles: { "src/first.mjs": "export const first = (arr) => (arr.length ? arr[0].trim() : \"\");\n" },
  },
];
