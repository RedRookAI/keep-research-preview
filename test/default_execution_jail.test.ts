import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { execFileSync } from "node:child_process";

import { jailedTree, isJailed, isPathWithinProject } from "../src/isolation/isolated_executor.js";
import { KeepPipeline } from "../src/pipeline/keep_pipeline.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import type { FileTree } from "../src/solve/patch.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";

/**
 * BIND-DEFAULT-EXECUTION-PATH (BUILD-ORDER 1.1) — the execution boundary is REAL on the DEFAULT path.
 *
 * The R43 measurement (declared_vs_actual_isolation.test.ts) recorded that the default
 * `ProcessIsolationExecutor` validates the `repoRef` PATH ARGUMENT but does NOT confine the byte-level
 * FileTree write surface — a write OUTSIDE the project dir landed. This round binds a realpath project
 * jail to the DEFAULT path (`KeepPipeline.executionTree` ⇒ `jailedTree` ⇒ the same `resolvedWithinProject`
 * the executor uses on `repoRef` — one boundary), so with NO configuration a solve/apply cannot read or
 * write outside the project dir, and the refusal is asserted on REAL FILESYSTEM BYTES (the file is not
 * created). Every test below pairs a green assertion with an inline NEUTER proving the jail is load-bearing.
 */

/** A raw, UNJAILED fs FileTree — the permissive fallback used to prove the RED direction on real bytes. */
function rawFsTree(root: string): FileTree {
  return {
    async read(p: string): Promise<string | undefined> {
      try { return readFileSync(resolve(root, p), "utf8"); } catch { return undefined; }
    },
    async write(p: string, content: string): Promise<void> {
      const full = resolve(root, p);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, content, "utf8");
    },
  };
}

// ── (a) DEFAULT write outside the jail is REFUSED on the filesystem ──────────────────────────────────
test("(a) a DEFAULT out-of-jail write is REFUSED — the file is never created on disk", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-jail-a-"));
  const outside = mkdtempSync(join(tmpdir(), "keep-outside-a-"));
  const target = join(outside, "escape.txt"); // absolute path, unambiguously outside `base`

  const jailed = jailedTree(rawFsTree(base), base);
  await assert.rejects(() => jailed.write(target, "PWNED"), /project-jail refused write/);
  assert.equal(existsSync(target), false, "the jailed write created no byte outside the project dir");

  // NEUTER — fall back to the permissive (raw) executor tree: the SAME write now LANDS. The jail is
  // what refuses it; without it the escape is real on the filesystem.
  await rawFsTree(base).write(target, "PWNED");
  assert.equal(existsSync(target), true, "neutered (no jail) → the out-of-jail write lands — RED");
  assert.equal(readFileSync(target, "utf8"), "PWNED");
});

// ── (b) DEFAULT in-project write lands normally (no false containment) ────────────────────────────────
test("(b) a DEFAULT in-project write lands normally — the jail is not a blanket refusal", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-jail-b-"));
  const jailed = jailedTree(rawFsTree(base), base);

  await jailed.write("src/ok.txt", "hello");
  assert.equal(readFileSync(join(base, "src", "ok.txt"), "utf8"), "hello", "an in-project write is committed to real bytes");
  assert.equal(await jailed.read("src/ok.txt"), "hello", "and an in-project read passes through");
});

test("(b') repository control data is outside the model-facing edit surface even though it is physically in-project", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-jail-git-control-"));
  mkdirSync(join(base, ".git/hooks"), { recursive: true });
  const jailed = jailedTree(rawFsTree(base), base);
  await assert.rejects(() => jailed.write(".git/hooks/post-merge", "#!/bin/sh\nexit 0\n"), /project-jail refused write/);
  assert.equal(await jailed.read(".git/config"), undefined, "Git control data is neither readable nor writable through the jail");
  assert.equal(existsSync(join(base, ".git/hooks/post-merge")), false);
});

// ── (c) a symlink-out / absolute / `..` escape is refused by the REALPATH jail ────────────────────────
test("(c) a symlink-out escape from inside the project is refused by the REALPATH jail (byte-level)", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-jail-c-"));
  const outside = mkdtempSync(join(tmpdir(), "keep-outside-c-"));
  symlinkSync(outside, join(base, "escape")); // a link INSIDE the project pointing OUT
  const viaLink = "escape/pwned.txt"; // note: contains no "..", so a STRING-only check would admit it

  const jailed = jailedTree(rawFsTree(base), base);
  await assert.rejects(() => jailed.write(viaLink, "PWNED"), /project-jail refused write/);
  assert.equal(existsSync(join(outside, "pwned.txt")), false, "the symlinked-out write created no byte outside the jail");

  // NEUTER — canonicalisation removed (a string-only check): the string guard MISSES the symlink escape.
  assert.equal(isPathWithinProject(base, viaLink), true, "a string-only check ADMITS the symlink escape — realpath is load-bearing");
  // and the raw (unjailed) tree writes straight through the link — RED direction, on real bytes.
  await rawFsTree(base).write(viaLink, "PWNED");
  assert.equal(existsSync(join(outside, "pwned.txt")), true, "without the realpath jail the symlink-out write lands — RED");
});

test("(c') a `..` traversal and an absolute path are both refused before any byte is written", async () => {
  // Nest `base` inside a UNIQUE root so a `..` escape resolves to a unique path (never shared /tmp) —
  // otherwise a neuter run that lets the write land would pollute a fixed path across runs.
  const root = mkdtempSync(join(tmpdir(), "keep-jail-cp-"));
  const base = join(root, "proj");
  mkdirSync(base, { recursive: true });
  const absTarget = join(root, "abs-escape.txt");
  const jailed = jailedTree(rawFsTree(base), base);
  await assert.rejects(() => jailed.write("../sibling-escape.txt", "PWNED"), /project-jail refused write/);
  await assert.rejects(() => jailed.write(absTarget, "PWNED"), /project-jail refused write/);
  assert.equal(existsSync(join(root, "sibling-escape.txt")), false);
  assert.equal(existsSync(absTarget), false);
});

// ── WIRING (ledger 298): the PIPELINE binds the jail as the default execution tree ───────────────────
const noopModel: ModelProvider = {
  name: "noop", isLocal: true,
  async generate(): Promise<GenerateResult> { return { text: "{}", model: "noop", tokensIn: 0, tokensOut: 0 }; },
  async embed(): Promise<Embedding[]> { return []; },
};
const noopRunner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

test("WIRING: with NO configuration the pipeline selects the realpath jail, not the raw operator tree", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-jail-w-"));
  const outside = mkdtempSync(join(tmpdir(), "keep-outside-w-"));
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-jail-ws-"))), new InProcessLock(), new SchemaRegistry());
  const pipeline = new KeepPipeline({ spine, tree: rawFsTree(base), runner: noopRunner, model: noopModel } as never);

  const tree = pipeline.executionTree(base);
  assert.equal(isJailed(tree), true, "the DEFAULT execution tree is the project jail — the enforcing tree, not the raw operator tree");
  const target = join(outside, "x.txt");
  await assert.rejects(() => tree.write(target, "PWNED"), /project-jail refused write/);
  assert.equal(existsSync(target), false, "a write outside the jail via the pipeline's default tree creates no byte");

  // NEUTER — a pipeline that selected the raw operator tree (`this.deps.tree`) instead: the escape lands.
  await rawFsTree(base).write(target, "PWNED");
  assert.equal(existsSync(target), true, "selecting the raw tree (the neuter) lets the escape land — the binding is load-bearing");
});

// ── END-TO-END: a DEFAULT solve applies a legitimate in-project edit on REAL BYTES (no false containment) ─
const BROKEN = "export function add(a, b) { return a - b; }\n";
const fixModel: ModelProvider = {
  name: "fix", isLocal: true,
  async generate(): Promise<GenerateResult> {
    return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
  },
  async embed(): Promise<Embedding[]> { return []; },
};

function setupRealRepo(): string {
  const root = mkdtempSync(join(tmpdir(), "keep-jail-e2e-"));
  const bare = join(root, "o.git"), work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  mkdirSync(join(work, "src"), { recursive: true });
  writeFileSync(join(work, "src", "calc.ts"), BROKEN, "utf8");
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  return work;
}

test("END-TO-END: a DEFAULT solveIssueToPR applies the in-project fix on the real filesystem", async () => {
  const work = setupRealRepo();
  // This journey reaches consequential effect admission, which requires actual
  // durable event confirmation; the default non-fsync store is not that contract.
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-jail-e2es-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  assert.equal(spine.durableStorage(), true);
  const tree = rawFsTree(work); // the operator's tree IS the real working tree; the pipeline jails it by default
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];

  const r = await new KeepPipeline({ spine, tree, runner, model: fixModel } as never).solveIssueToPR(
    { id: "JAIL-E2E", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator", projectDir: work },
  );

  assert.equal(r.solveResult.solved, true, "the default (jailed) path still solves the issue");
  assert.equal(readFileSync(join(work, "src", "calc.ts"), "utf8"), "export function add(a, b) { return a + b; }\n",
    "the legitimate in-project fix landed on real bytes through the default jailed tree — no false containment");
});
