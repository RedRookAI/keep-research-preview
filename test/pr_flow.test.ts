import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { GitAdapter } from "../src/infra/git_adapter.js";
import { GitRemote } from "../src/git/git_remote.js";
import { LocalPullRequest, renderManifest, type PullRequestPort } from "../src/git/pull_request.js";
import { publishSolveAsPr } from "../src/git/pr_publisher.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";
import type { SolveResult } from "../src/solve/issue_model.js";

function setupRepo(): { work: string; bare: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-pr-"));
  const bare = join(root, "origin.git");
  const work = join(root, "work");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (args: string[]) => execFileSync("git", args, { cwd: work });
  g(["config", "user.email", "t@t"]);
  g(["config", "user.name", "t"]);
  g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `printf 'export function add(a,b){ return a-b; }\\n' > ${join(work, "calc.ts")}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  g(["remote", "set-url", "origin", `file://${bare}`]);
  return { work, bare };
}

function pin(bare: string) { const url = `file://${bare}`; return { expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(url), expectedPushUrlSha256: pinnedRemoteUrlSha256(url) }; }

function solvedResult(): SolveResult {
  return {
    issueId: "BUG-1",
    solved: true,
    stagesRun: ["localize", "plan", "apply", "validate", "done"],
    repairRounds: 0,
    validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "all tests passed; vetting cleared" },
    prProposal: {
      title: "Fix BUG-1",
      body: "## Fixes BUG-1\n\n**Issue:** add() subtracts instead of adds\n\n_awaiting human review_",
      branch: "keep/solve/BUG-1",
      edits: [{ file: "calc.ts", search: "return a-b;", replace: "return a+b;", intent: "use + not -" }],
      testsPassed: true,
    },
  };
}

test("review-only publication cannot turn failed tests or unresolved work into a proposal", async () => {
  const base = solvedResult();
  const blocked: SolveResult = { ...base, solved: false, validation: { ...base.validation!, vettingCleared: false }, recovery: { status: "authority", attempts: 1, maxAttempts: 4, deadline: 100,
    planningCalls: 0, maxPlanningCalls: 16, planningInputBytes: 0, maxPlanningInputBytes: 16 * 65536 } };
  await assert.rejects(publishSolveAsPr(blocked, {} as never), /cannot publish/);
  for (const status of ["reconciliation", "diagnosis", "exhausted", "ready"] as const) {
    await assert.rejects(publishSolveAsPr({ ...blocked, recovery: { ...blocked.recovery!, status } }, { reviewOnly: true } as never), /cannot publish/);
  }
  await assert.rejects(publishSolveAsPr({ ...blocked, validation: { ...blocked.validation!, testsPassed: false } }, { reviewOnly: true } as never), /cannot publish/);
});

// ── the structural human-gate ────────────────────────────────────────────────

test("INVARIANT: PullRequestPort has NO approve/merge method (structural human gate)", () => {
  const port: PullRequestPort = new LocalPullRequest();
  // These properties must NOT exist — the absence is the safety property.
  const asRecord = port as unknown as Record<string, unknown>;
  assert.equal(asRecord["approve"], undefined, "no approve()");
  assert.equal(asRecord["merge"], undefined, "no merge()");
});

test("INVARIANT: a manifest always requires human approval", async () => {
  const port = new LocalPullRequest();
  const r = solvedResult();
  const m = await port.open(r.prProposal!, { baseBranch: "main", diff: "diff", intent: "i", executed: ["e"], checks: [], attribution: "a" });
  assert.equal(m.humanApprovalRequired, true);
});

test("renderManifest shows intent-vs-executed and the never-merge notice", async () => {
  const port = new LocalPullRequest();
  const m = await port.open(solvedResult().prProposal!, {
    baseBranch: "main", diff: "x", intent: "add() subtracts instead of adds",
    executed: ["calc.ts: use + not -"], checks: [{ name: "tests", passed: true }], attribution: "Keep-Run-Id: r1",
  });
  const text = renderManifest(m);
  assert.match(text, /INTENT/);
  assert.match(text, /add\(\) subtracts/);
  assert.match(text, /EXECUTED/);
  assert.match(text, /use \+ not -/);
  assert.match(text, /never merges/i);
});

// ── full publish flow against a real local bare remote ──────────────────────

test("INVARIANT: solve → branch → push → PR manifest, end-to-end on a real remote", async () => {
  const { work, bare } = setupRepo();
  const git = new GitAdapter(work);
  const remote = new GitRemote(git, { runId: "run-1", attribution: "Keep <keep@local>", ...pin(bare) });
  const prPort = new LocalPullRequest();

  // Simulate the SolvePipeline having applied the edit to the working tree.
  execFileSync("bash", ["-c", `printf 'export function add(a,b){ return a+b; }\\n' > ${join(work, "calc.ts")}`]);

  const pub = await publishSolveAsPr(solvedResult(), { git, remote, prPort, baseBranch: "main" });

  // The branch reached the remote.
  const verifyRoot = mkdtempSync(join(tmpdir(), "keep-pr-verify-"));
  execFileSync("git", ["clone", "-q", bare, verifyRoot]);
  const branches = execFileSync("git", ["branch", "-a"], { cwd: verifyRoot }).toString();
  assert.match(branches, /keep\/solve\/BUG-1/, "task branch pushed to remote");

  // The manifest carries the EXACT diff (the reviewer's source of truth) + intent vs executed.
  assert.match(pub.manifest.diff, /calc\.ts/);
  assert.match(pub.manifest.diff, /\+.*return a\+b/, "diff shows the actual change");
  assert.equal(pub.manifest.intent, "add() subtracts instead of adds");
  assert.deepEqual(pub.manifest.executed, ["calc.ts: use + not -"]);
  assert.equal(pub.manifest.checks[0]!.name, "tests");
  assert.equal(pub.manifest.checks[0]!.passed, true);
});

test("INVARIANT: a rejected PR reverts cleanly and main is never touched", async () => {
  const { work, bare } = setupRepo();
  const git = new GitAdapter(work);
  const remote = new GitRemote(git, { runId: "run-2", ...pin(bare) });
  const prPort = new LocalPullRequest();
  execFileSync("bash", ["-c", `printf 'export function add(a,b){ return a+b; }\\n' > ${join(work, "calc.ts")}`]);

  const pub = await publishSolveAsPr(solvedResult(), { git, remote, prPort, baseBranch: "main" });

  // Reviewer REJECTS → undo the push.
  await pub.pushUndo.undo();

  // The remote no longer has the task branch...
  const remoteBranches = execFileSync("git", ["branch"], { cwd: bare }).toString();
  assert.doesNotMatch(remoteBranches, /keep\/solve\/BUG-1/, "rejected branch removed from remote");
  // ...and main on the remote is untouched (still the original subtract version).
  const verifyRoot = mkdtempSync(join(tmpdir(), "keep-pr-main-"));
  execFileSync("git", ["clone", "-q", "-b", "main", bare, verifyRoot]);
  const mainCalc = execFileSync("bash", ["-c", `cat ${join(verifyRoot, "calc.ts")}`]).toString();
  assert.match(mainCalc, /return a-b/, "main NEVER touched — still the original code");
});

test("CONTROL PLANE: a filter installed after branch creation refuses before git add can execute it", async () => {
  const { work, bare } = setupRepo();
  const git = new GitAdapter(work);
  const marker = join(work, "filter-driver-executed");
  class HostileAfterCheckoutRemote extends GitRemote {
    override async createTaskBranch(branch: string): Promise<void> {
      await super.createTaskBranch(branch);
      writeFileSync(join(work, ".gitattributes"), "calc.ts filter=pwn\n");
      execFileSync("git", ["config", "--local", "filter.pwn.clean", `sh -c 'touch ${marker}; cat'`], { cwd: work });
    }
  }
  const remote = new HostileAfterCheckoutRemote(git, pin(bare));
  writeFileSync(join(work, "calc.ts"), "export function add(a,b){ return a+b; }\n");
  await assert.rejects(() => publishSolveAsPr(solvedResult(), { git, remote, prPort: new LocalPullRequest(), baseBranch: "main" }), /configuration key is not allowlisted/);
  assert.equal(existsSync(marker), false, "clean filter never executes");
});

test("CONTROL PLANE: a textconv installed after commit refuses before review diff", async () => {
  const { work, bare } = setupRepo();
  const git = new GitAdapter(work);
  const marker = join(work, "textconv-executed");
  class HostileBeforeDiffRemote extends GitRemote {
    override async commitWithAttribution(message: string, actionId: string) {
      const action = await super.commitWithAttribution(message, actionId);
      execFileSync("git", ["config", "--local", "diff.pwn.textconv", `sh -c 'touch ${marker}; cat \"$1\"' --`], { cwd: work });
      return action;
    }
  }
  const remote = new HostileBeforeDiffRemote(git, pin(bare));
  writeFileSync(join(work, "calc.ts"), "export function add(a,b){ return a+b; }\n");
  await assert.rejects(() => publishSolveAsPr(solvedResult(), { git, remote, prPort: new LocalPullRequest(), baseBranch: "main" }), /configuration key is not allowlisted/);
  assert.equal(existsSync(marker), false, "textconv never executes");
});

test("INVARIANT: publishing an unsolved result throws (nothing to propose)", async () => {
  const { work } = setupRepo();
  const git = new GitAdapter(work);
  const remote = new GitRemote(git);
  const prPort = new LocalPullRequest();
  const unsolved: SolveResult = { issueId: "X", solved: false, stagesRun: ["localize", "gave-up"], repairRounds: 0, gaveUpReason: "no fix" };
  await assert.rejects(() => publishSolveAsPr(unsolved, { git, remote, prPort, baseBranch: "main" }), /cannot publish an unsolved/);
});
