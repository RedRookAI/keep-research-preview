import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  InstalledEffectAdmission,
  INSTALLED_EFFECT_OWNERS,
  UnknownEffectOwnerError,
  type InstalledEffectAdmissionRecord,
} from "../src/control/installed_effect_admission.js";
import { LocalFsWorkspace } from "../src/solve/workspace.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { ProcessIsolationAdapter, type IsolatedRunResult } from "../src/infra/process_isolation.js";
import { GitAdapter } from "../src/infra/git_adapter.js";
import { publishSolveAsPr } from "../src/git/pr_publisher.js";
import type { SolveResult } from "../src/solve/issue_model.js";

test("SAFE-02: unknown owners hold and every declared effect family has an owner", () => {
  const gate = new InstalledEffectAdmission();
  assert.throws(() => gate.admit("plugin.unregistered-effect"), UnknownEffectOwnerError);
  assert.deepEqual(new Set(gate.inventory().map((record) => record.kind)), new Set(["file", "process", "network", "git", "publication"]));
});

test("SAFE-02: real workspace, process, git, and publication owners cross admission before effects", async () => {
  const records: InstalledEffectAdmissionRecord[] = [];
  const gate = new InstalledEffectAdmission((record) => records.push(record));
  const base = mkdtempSync(join(tmpdir(), "keep-effect-admission-"));
  const repo = join(base, "repo");
  mkdirSync(repo);
  writeFileSync(join(repo, "a.ts"), "export const a = 1;\n");

  const workspace = new LocalFsWorkspace(base, [".ts"], gate);
  await workspace.files("repo");
  await workspace.tree("repo").read("a.ts");
  await workspace.tree("repo").write("b.ts", "export const b = 2;\n");

  let processCalled = false;
  const adapter = new ProcessIsolationAdapter();
  (adapter as unknown as { run: () => Promise<IsolatedRunResult> }).run = async () => {
    processCalled = true;
    return { code: 0, signal: null, stdout: "ok 1 - admitted\n", stderr: "", timedOut: false, truncated: false, durationMs: 1 };
  };
  await new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir: repo, namespaceJail: false, adapter, effectAdmission: gate }).run(".");
  assert.equal(processCalled, true);

  await new GitAdapter(repo, gate).git(["init"]);

  const solved: SolveResult = {
    issueId: "SAFE-02", solved: true, stagesRun: ["done"], repairRounds: 0,
    prProposal: { title: "safe", body: "**Issue:** safe", branch: "keep/safe-02", edits: [], testsPassed: true },
  };
  const stopAtPublication = new InstalledEffectAdmission((record) => {
    records.push(record);
    if (record.id === INSTALLED_EFFECT_OWNERS.proposalPublication.id) throw new Error("publication admitted before downstream effect");
  });
  await assert.rejects(
    () => publishSolveAsPr(solved, { git: new GitAdapter(repo, gate), remote: {} as never, prPort: {} as never, baseBranch: "main", effectAdmission: stopAtPublication }),
    /publication admitted before downstream effect/,
  );

  const ids = new Set(records.map((record) => record.id));
  assert.ok(ids.has(INSTALLED_EFFECT_OWNERS.workspaceRead.id));
  assert.ok(ids.has(INSTALLED_EFFECT_OWNERS.workspaceWrite.id));
  assert.ok(ids.has(INSTALLED_EFFECT_OWNERS.testProcess.id));
  assert.ok(ids.has(INSTALLED_EFFECT_OWNERS.gitCommand.id));
  assert.ok(ids.has(INSTALLED_EFFECT_OWNERS.proposalPublication.id));
});

test("SAFE-02: a holding boundary prevents the underlying process adapter from running", async () => {
  const repo = mkdtempSync(join(tmpdir(), "keep-effect-hold-"));
  let processCalled = false;
  const adapter = new ProcessIsolationAdapter();
  (adapter as unknown as { run: () => Promise<IsolatedRunResult> }).run = async () => {
    processCalled = true;
    throw new Error("must not execute");
  };
  const holding = new InstalledEffectAdmission(() => { throw new Error("held by admission"); });
  const runner = new SandboxedCommandRunner({ command: "node", args: [], projectDir: repo, adapter, effectAdmission: holding });
  await assert.rejects(() => runner.run("."), /held by admission/);
  assert.equal(processCalled, false);
});

