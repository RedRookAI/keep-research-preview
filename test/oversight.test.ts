import { test } from "node:test";
import { NotificationRouter } from "../src/notify/notification_router.js";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { PrRiskAssessor } from "../src/oversight/pr_risk.js";
import { OversightRouter } from "../src/oversight/oversight_router.js";
import { GitAdapter } from "../src/infra/git_adapter.js";
import { GitRemote } from "../src/git/git_remote.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";
import { LocalPullRequest } from "../src/git/pull_request.js";
import { publishSolveAsPr } from "../src/git/pr_publisher.js";
import type { SolveResult, PrProposal } from "../src/solve/issue_model.js";

function proposal(edits: PrProposal["edits"], testsPassed = true): PrProposal {
  return { title: "t", body: "**Issue:** x", branch: "keep/solve/X", edits, testsPassed };
}
function result(p: PrProposal, over: Partial<SolveResult> = {}): SolveResult {
  return {
    issueId: "X", solved: true, stagesRun: ["done"], repairRounds: 0,
    validation: { testsPassed: p.testsPassed, failures: [], vettingCleared: true, detail: "ok" },
    prProposal: p, ...over,
  };
}

// ── risk assessor ────────────────────────────────────────────────────────────

test("INVARIANT: a clean 1-file revert-safe fix scores LOW", () => {
  const p = proposal([{ file: "src/calc.ts", search: "a-b", replace: "a+b", intent: "fix" }]);
  const r = new PrRiskAssessor().assess({ proposal: p, result: result(p) });
  assert.equal(r.band, "low", `expected low, got ${r.band} (score ${r.score})`);
  assert.equal(r.forcedGate, false);
});

test("INVARIANT: a failing-tests multi-file change scores riskier", () => {
  const p = proposal([
    { file: "src/a.ts", search: "x", replace: "y".repeat(700), intent: "big" },
    { file: "src/b.ts", search: "p", replace: "q", intent: "b" },
    { file: "src/c.ts", search: "m", replace: "n", intent: "c" },
  ], false);
  const r = new PrRiskAssessor().assess({ proposal: p, result: result(p, { validation: { testsPassed: false, failures: ["t1"], vettingCleared: false, detail: "fail" } }) });
  assert.notEqual(r.band, "low", "failing tests + multi-file + large should not be low");
});

test("INVARIANT: an auth/migration path FORCES a gate regardless of confidence", () => {
  const p = proposal([{ file: "src/auth/login.ts", search: "a", replace: "b", intent: "clean fix" }]);
  const r = new PrRiskAssessor().assess({ proposal: p, result: result(p) }); // tests pass, clean
  assert.equal(r.forcedGate, true, "sensitive path forces gate");
  assert.equal(r.band, "high", "forced gate is high band");
});

test("migration + sql paths also force a gate", () => {
  for (const f of ["db/migrations/001.ts", "schema/tables.sql"]) {
    const p = proposal([{ file: f, search: "a", replace: "b", intent: "x" }]);
    const r = new PrRiskAssessor().assess({ proposal: p, result: result(p) });
    assert.equal(r.forcedGate, true, `${f} should force a gate`);
  }
});

// ── router ───────────────────────────────────────────────────────────────────

const lowRisk = { band: "low" as const, score: 0.1, reasons: [], forcedGate: false, consequenceBand: "low" as const };
const medRisk = { band: "medium" as const, score: 0.45, reasons: [], forcedGate: false, consequenceBand: "medium" as const };
const highRisk = { band: "high" as const, score: 0.8, reasons: [], forcedGate: false, consequenceBand: "high" as const };
const forced = { band: "high" as const, score: 0.2, reasons: [], forcedGate: true, consequenceBand: "high" as const };

test("INVARIANT: high risk is NEVER auto-approved at any autonomy level", () => {
  for (const level of ["observer", "approver", "collaborator", "operator", "delegator"] as const) {
    const d = new OversightRouter({ autonomyLevel: level }).route(highRisk);
    assert.equal(d.disposition, "human-approval-required", `high must gate at ${level}`);
    assert.equal(d.requiresImmediateAttention, true);
  }
});

test("INVARIANT: a rule-forced gate always blocks for approval, overriding autonomy", () => {
  const d = new OversightRouter({ autonomyLevel: "delegator" }).route(forced);
  assert.equal(d.disposition, "human-approval-required");
  assert.equal(d.mode, "block-until-approved");
});

test("INVARIANT: low risk + collaborator auto-approves silently (no interrupt)", () => {
  const d = new OversightRouter({ autonomyLevel: "collaborator" }).route(lowRisk);
  assert.equal(d.disposition, "auto-approved");
  assert.equal(d.mode, "silent-auto");
  assert.equal(d.requiresImmediateAttention, false);
});

test("INVARIANT: medium risk + operator auto-approves with async notify (cancellable, non-blocking)", () => {
  const d = new OversightRouter({ autonomyLevel: "operator" }).route(medRisk);
  assert.equal(d.disposition, "auto-approved");
  assert.equal(d.mode, "notify-async");
  assert.equal(d.requiresImmediateAttention, false);
});

test("INVARIANT: observer/approver ask about everything (even low risk)", () => {
  for (const level of ["observer", "approver"] as const) {
    const d = new OversightRouter({ autonomyLevel: level }).route(lowRisk);
    assert.equal(d.disposition, "human-approval-required", `${level} gates even low risk`);
  }
});

test("INVARIANT: deny-by-default — a timed-out blocking gate resolves to BLOCKED, never proceeds", () => {
  const router = new OversightRouter({ autonomyLevel: "observer" });
  const d = router.route(highRisk); // block-until-approved
  assert.equal(router.resolveTimeout(d), "blocked", "unanswered high-risk gate denies by default");
});

// ── review batching via the composed NotificationRouter (supersedes the retired ReviewBatch) ──

test("SECURITY (approval-fatigue exploitation defense): a high-risk PR is NEVER batched — it escalates urgent", () => {
  const router = new NotificationRouter();
  const medium = { id: "PR-1", title: "t", branch: "keep/solve/X", baseBranch: "main", oversight: { disposition: "auto-approved", mode: "notify-async", band: "medium", reasons: [], requiresImmediateAttention: false } } as never;
  const highImmediate = { id: "PR-2", title: "t", branch: "keep/solve/Y", baseBranch: "main", oversight: { disposition: "human-approval-required", mode: "block-until-approved", band: "high", reasons: [], requiresImmediateAttention: true } } as never;
  assert.equal(router.notify(medium), "digest", "a routine medium change batches");
  assert.equal(router.notify(highImmediate), "urgent", "a high-risk immediate change escalates NOW — never hidden inside a benign batch under bulk approval");
  assert.equal(router.pendingDigestCount(), 1, "only the benign item is in the batch");
});

test("count-based digest trigger (10-50 HITL SOTA) + flush clears", () => {
  const router = new NotificationRouter();
  const m = (id: string) => ({ id, title: "t", branch: "keep/solve/" + id, baseBranch: "main", oversight: { disposition: "auto-approved", mode: "notify-async", band: "medium", reasons: ["r"], requiresImmediateAttention: false } } as never);
  router.notify(m("A")); router.notify(m("B"));
  assert.ok(router.digestReady(2), "ready at the count threshold");
  const digest = router.flushDigest();
  assert.equal(digest?.total, 2);
  assert.equal(router.pendingDigestCount(), 0, "flush clears");
});

// ── THE MERGE-GATE INVARIANT ────────────────────────────────────────────────

test("INVARIANT: the oversight layer NEVER merges and NEVER removes the gate", async () => {
  // auto-approved is the most permissive outcome — prove it still doesn't merge.
  const root = mkdtempSync(join(tmpdir(), "keep-ov-"));
  const bare = join(root, "o.git"); const work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `echo 'export const x=1-1;' > ${join(work, "m.ts")}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  g(["remote", "set-url", "origin", `file://${bare}`]);
  execFileSync("bash", ["-c", `echo 'export const x=1+1;' > ${join(work, "m.ts")}`]);

  const git = new GitAdapter(work);
  const remoteUrl = `file://${bare}`;
  const remote = new GitRemote(git, { runId: "r", expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(remoteUrl), expectedPushUrlSha256: pinnedRemoteUrlSha256(remoteUrl) });
  const prPort = new LocalPullRequest();
  const p: PrProposal = { title: "t", body: "**Issue:** x", branch: "keep/solve/OV", edits: [{ file: "m.ts", search: "1-1", replace: "1+1", intent: "fix" }], testsPassed: true };
  const res = result(p);

  const pub = await publishSolveAsPr(res, {
    git, remote, prPort, baseBranch: "main",
    oversight: { assessor: new PrRiskAssessor(), router: new OversightRouter({ autonomyLevel: "operator" }) },
  });

  // The oversight decision is attached...
  assert.ok(pub.manifest.oversight, "oversight decision attached to manifest");
  // ...but the manifest STILL requires human approval, and main on the remote is untouched.
  assert.equal(pub.manifest.humanApprovalRequired, true, "gate never removed, even when auto-approved");
  const verify = mkdtempSync(join(tmpdir(), "keep-ov-v-"));
  execFileSync("git", ["clone", "-q", "-b", "main", bare, verify]);
  const mainCode = execFileSync("bash", ["-c", `cat ${join(verify, "m.ts")}`]).toString();
  assert.match(mainCode, /1-1/, "main NEVER merged — still original despite auto-approved disposition");
});

test("RED-TEAM REGRESSION: underscore/plural sensitive paths cannot dodge the always-gate", () => {
  const a = new PrRiskAssessor();
  const mk = (file: string) => ({
    proposal: { title: "t", body: "b", branch: "keep/x", edits: [{ file, search: "a", replace: "b", intent: "i" }], testsPassed: true },
    result: { issueId: "x", solved: true, stagesRun: ["done"], repairRounds: 0, validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "" } } as never,
  });
  for (const f of ["secret_keys.ts", "api_secrets.ts", "user_credentials.py", "oauth_token.ts", "secrets.ts", "credentials.json"]) {
    assert.equal(a.assess(mk(f)).forcedGate, true, `${f} must force a gate (red-team regression)`);
  }
  // benign stays benign
  for (const f of ["src/calc.ts", "components/Button.tsx", "README.md"]) {
    assert.equal(a.assess(mk(f)).forcedGate, false, `${f} must NOT force a gate`);
  }
});

// ─── F2: the router consumes a human-authorized reduced-escalation policy (governed, revocable) ───

test("F2 router: an authorized class auto-approves in the low/medium reversible band (was gated at approver)", () => {
  const gated = new OversightRouter({ autonomyLevel: "approver" });
  assert.equal(gated.route(lowRisk).disposition, "human-approval-required"); // default: gated
  const withPolicy = new OversightRouter({ autonomyLevel: "approver", reducedEscalationClasses: new Set(["low"]) });
  const d = withPolicy.route(lowRisk, { classKey: "low" });
  assert.equal(d.disposition, "auto-approved");
  assert.match(d.reasons.join(" "), /authorized calibration policy/);
});

test("F2 router INVARIANT: an authorized policy NEVER auto-approves high risk", () => {
  const r = new OversightRouter({ autonomyLevel: "approver", reducedEscalationClasses: new Set(["high"]) });
  assert.equal(r.route(highRisk, { classKey: "high" }).disposition, "human-approval-required");
});

test("F2 router INVARIANT: an authorized policy NEVER overrides a rule-forced gate", () => {
  const forced = { band: "low" as const, score: 0.1, reasons: [], forcedGate: true, consequenceBand: "low" as const };
  const r = new OversightRouter({ autonomyLevel: "approver", reducedEscalationClasses: new Set(["low"]) });
  const d = r.route(forced, { classKey: "low" });
  assert.equal(d.disposition, "human-approval-required");
  assert.equal(d.requiresImmediateAttention, true);
});

test("F2 router: N=1 safe-by-default — with NO policies, behavior is unchanged (everything gated at approver)", () => {
  const r = new OversightRouter({ autonomyLevel: "approver" });
  assert.equal(r.route(lowRisk).disposition, "human-approval-required");
  assert.equal(r.route(medRisk).disposition, "human-approval-required");
});
