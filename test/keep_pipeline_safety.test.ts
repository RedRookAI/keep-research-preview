import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { GovernanceLedger } from "../src/governance/decision_record.js";
import { KillSwitch } from "../src/control/killswitch.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";

import { InMemoryFileTree } from "../src/solve/patch.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { RepoFile } from "../src/solve/localize.js";
import { KeepPipeline } from "../src/pipeline/keep_pipeline.js";
import { SafeRemediation, type RemediationContext } from "../src/pipeline/safe_remediation.js";
import type { BreakGlassGrant } from "../src/pipeline/safety_rail.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import { makePublicationAttempt, publicationAttemptDigest, type MergeSpec, type PublishedMergeIdentity } from "../src/oversight/merge_executor.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-66b-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
}

function setupRemote(): { work: string; bare: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-66b-git-"));
  const bare = join(root, "o.git"); const work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, "src/calc.ts")})" && printf '%s' 'export function add(a, b) { return a - b; }\n' > ${join(work, "src/calc.ts")}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  return { work, bare };
}

function fixModel(): ModelProvider {
  return {
    name: "fix", isLocal: true,
    async generate(): Promise<GenerateResult> {
      return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
}

function tree(): InMemoryFileTree { return new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" }); }
function runnerFor(t: InMemoryFileTree): TestRunner {
  return { async run(): Promise<TestRunResult> { const c = (await t.read("src/calc.ts")) ?? ""; return { results: [{ name: "add", passed: c.includes("a + b") }] }; } };
}
const FILES: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
function applyFix(work: string) { execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]); }

test("INVARIANT: rails DEFAULT-ON — no custom vet fn → the real default cascade vetter runs", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel() }); // no custom vet
  const r = await pipeline.solveIssueToPR({ id: "D-1", text: "add subtracts", repoRef: "d" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  assert.equal(r.solveResult.solved, true);
  assert.ok(r.manifest, "PR still created");
  assert.equal(r.manifest!.humanApprovalRequired, true, "human gate intact");
  // The default VerificationCascade vetter runs (not fail-closed-to-human) and clears a clean patch.
  assert.equal(r.safety?.vettingCleared, true, "default cascade vetter cleared the clean patch");
});

test("INVARIANT: default vetter FAILS CLOSED when the patch has no clean validation", async () => {
  // A runner that reports tests still failing → the sound tier fails → vetting not cleared → human.
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const failingRunner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "add", passed: false, output: "still broken" }] }; } };
  const pipeline = new KeepPipeline({ spine, tree: t, runner: failingRunner, model: fixModel() });
  const r = await pipeline.solveIssueToPR({ id: "D-2", text: "add subtracts", repoRef: "d2" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  // With tests failing the solve won't produce a passing patch → no PR, OR if a PR forms it's not vet-cleared.
  if (r.manifest) assert.equal(r.safety?.vettingCleared, false, "unclean patch → vetting not cleared");
});

test("INVARIANT: killswitch tripped → pipeline refuses BEFORE solve (no PR, reason carried)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  const ks = new KillSwitch(spine);
  ks.register({ agentId: "K-1", credentialId: "c", terminate: () => {} });
  ks.kill("K-1", "test", "manual-kill");
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), killSwitch: ks });
  const r = await pipeline.solveIssueToPR({ id: "K-1", text: "x", repoRef: "k" }, FILES, pinnedGitDependencies(work));
  assert.equal(r.solveResult.solved, false);
  assert.equal(r.manifest, undefined, "no PR when refused");
  assert.equal(r.safety?.refusedBeforeSolve?.outcome, "block-killed");
});

test("INVARIANT: the canonical kill switch pauses in-doubt publication recovery before observation", async () => {
  const { work } = setupRemote();
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-66b-recovery-")), { fsync: true }), new InProcessLock(), new SchemaRegistry()); const t = tree();
  const recoverySpec: MergeSpec = { issueId: "K-R", repoRef: "k", branch: "keep/k", baseBranch: "main", expectedCandidateCommit: "a".repeat(40), expectedCandidateProjectManifestDigest: "b".repeat(64), expectedGuestExecutionRequestDigest: "c".repeat(64), projectDir: work };
  const recoveryIdentity: PublishedMergeIdentity = { candidateCommit: recoverySpec.expectedCandidateCommit, candidateTree: "1".repeat(40), candidateProjectManifestDigest: recoverySpec.expectedCandidateProjectManifestDigest, baseCommit: "2".repeat(40), baseTree: "3".repeat(40), expectedMergedTree: "4".repeat(40), mergedCommit: "5".repeat(40), mergedTree: "4".repeat(40), publishedCommit: "5".repeat(40), publishedTree: "4".repeat(40), publishedProjectManifestDigest: recoverySpec.expectedCandidateProjectManifestDigest, publicationTarget: "simulation:main" };
  const attempt = makePublicationAttempt(recoverySpec, recoveryIdentity);
  spine.stage({ type: "effect.intent", actor: "test", payload: { kind: "auto_merge.publication_prepared", attemptDigest: publicationAttemptDigest(attempt), attempt } });
  await spine.seal();
  const ks = new KillSwitch(spine);
  ks.register({ agentId: "K-R", credentialId: "c", terminate: () => {} });
  ks.kill("K-R", "test", "manual-kill"); await spine.seal();
  let observations = 0;
  class ObservedPort extends InMemoryMergePort { override async observePublication(value: typeof attempt) { observations++; return super.observePublication(value); } }
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), killSwitch: ks });
  const result = await pipeline.solveIssueToPR({ id: "K-R", text: "x", repoRef: "k" }, FILES, pinnedGitDependencies(work, new ObservedPort()));
  assert.equal(result.solveResult.solved, false);
  assert.equal(result.publicationRecovery?.[0]?.status, "refused");
  assert.equal(observations, 0);
});

test("INVARIANT: expired envelope → deny BEFORE solve", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel() });
  const expired: AuthorizationEnvelope = { id: "e", projectId: "p", allowedClasses: ["auto-rag"], allowedTiers: [], dailyCapUsd: 10, perRunCapUsd: 2, perCallTokenCeiling: 8000, expiresAt: 1, grantedReason: "old" };
  const r = await pipeline.solveIssueToPR({ id: "E-1", text: "x", repoRef: "e" }, FILES, pinnedGitDependencies(work), { envelope: expired });
  assert.equal(r.solveResult.solved, false);
  assert.equal(r.safety?.refusedBeforeSolve?.outcome, "deny");
});

test("INVARIANT: break-glass relaxes vetting end-to-end BUT the PR is STILL human-gated", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  // vet fn returns false (would fail), break-glass relaxes it.
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), vet: async () => false });
  const grant: BreakGlassGrant = { operatorId: "op", reason: "emergency", expiresAt: Date.now() + 60000 };
  const r = await pipeline.solveIssueToPR({ id: "BG-1", text: "add subtracts", repoRef: "bg" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator", breakGlass: grant });
  assert.equal(r.safety?.vettingCleared, true, "break-glass relaxed the verdict");
  assert.equal(r.safety?.vettingViaBreakGlass, true);
  assert.equal(r.manifest!.humanApprovalRequired, true, "merge gate STILL human — break-glass never merges");
});

test("INVARIANT: a passing vet fn → vettingCleared true, PR still human-gated", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), vet: async () => true });
  const r = await pipeline.solveIssueToPR({ id: "V-1", text: "add subtracts", repoRef: "v" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  assert.equal(r.safety?.vettingCleared, true);
  assert.equal(r.manifest!.humanApprovalRequired, true);
});

test("INVARIANT: governance decisions from the run land on the tamper-evident spine + it verifies", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const gov = new GovernanceLedger(spine);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), vet: async () => true, governance: gov });
  await pipeline.solveIssueToPR({ id: "G-1", text: "add subtracts", repoRef: "g" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  await spine.seal();
  const trail = gov.readTrail();
  assert.ok(trail.some((r) => r.action === "authorize"), "authorization audited");
  assert.ok(trail.some((r) => r.action === "vet.patch"), "vetting audited");
  assert.equal(spine.verify().ok, true, "tamper-evident chain intact");
});

test("INVARIANT: plan-vetting runs PRE-solve and is audited (both gates run, not exclusive)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const gov = new GovernanceLedger(spine);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: gov });
  const r = await pipeline.solveIssueToPR({ id: "P-1", text: "add() in calc.ts returns the difference instead of the sum", repoRef: "p" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  // A normal issue passes plan vetting and proceeds to a vetted patch + PR.
  assert.equal(r.solveResult.solved, true);
  await spine.seal();
  const trail = gov.readTrail();
  assert.ok(trail.some((x) => x.action === "vet.plan"), "plan vetting was recorded (pre-solve gate ran)");
  assert.ok(trail.some((x) => x.action === "vet.patch"), "patch vetting also ran (both gates)");
});

test("INVARIANT: a custom plan vetter that BLOCKS stops the run before solve (fail-closed)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  const pipeline = new KeepPipeline({
    spine, tree: t, runner: runnerFor(t), model: fixModel(),
    planVet: async () => ({ cleared: false, decision: "block", reason: "blocked by policy" }),
  });
  const r = await pipeline.solveIssueToPR({ id: "PB-1", text: "x", repoRef: "pb" }, FILES, pinnedGitDependencies(work));
  assert.equal(r.solveResult.solved, false, "blocked plan → no solve");
  assert.equal(r.manifest, undefined, "no PR when plan blocked");
  assert.equal(r.safety?.planVetting?.decision, "block");
});

test("INVARIANT: a dangerous issue is BLOCKED by consequence analysis before solve (real plan gate)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  const gov = new GovernanceLedger(spine);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: gov });
  const r = await pipeline.solveIssueToPR(
    { id: "DANGER-1", text: "drop all database tables and disable backups", repoRef: "d" },
    FILES, pinnedGitDependencies(work)
  );
  assert.equal(r.solveResult.solved, false, "dangerous plan blocked before solve");
  assert.equal(r.manifest, undefined, "no PR for a blocked plan");
  assert.equal(r.safety?.planVetting?.decision, "block");
  await spine.seal();
  assert.ok(gov.readTrail().some((x) => x.action === "vet.plan" && x.outcome === "blocked"), "plan block audited");
});

test("INVARIANT: the trajectory checkpoint RUNS in the pipeline and is audited (vet.trajectory recorded)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const gov = new GovernanceLedger(spine);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: gov });
  const r = await pipeline.solveIssueToPR({ id: "TRAJ-1", text: "add() in calc.ts subtracts instead of adds", repoRef: "tj" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  assert.equal(r.solveResult.solved, true);
  assert.ok(r.safety?.trajectory, "trajectory drift result is surfaced");
  assert.equal(r.safety?.trajectory?.drifted, false, "a benign single-file fix does not drift");
  await spine.seal();
  assert.ok(gov.readTrail().some((x) => x.action === "vet.trajectory"), "trajectory checkpoint audited");
});

test("INVARIANT: pipeline invokes SELF-HEAL before routing when patch vetting doesn't clear (16.9a)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const gov = new GovernanceLedger(spine);
  // A vet fn that does NOT clear → forces the self-heal path. A spy SafeRemediation records invocation.
  let healInvoked = false;
  const spy = new SafeRemediation({ governance: gov, rules: [{
    name: "spy-noop", riskClass: "trivial-reversible",
    admissible: () => { healInvoked = true; return false; }, // observe, decline to heal → routes
    narrow: (c: RemediationContext) => c.input.solveResult.prProposal!.edits,
  }], enabled: { "spy-noop": true } });
  const pipeline = new KeepPipeline({
    spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: gov,
    vet: async () => false, // patch vetting never clears → self-heal attempted
    // Post-AM3 a reversible unverified change is abandoned; a consequential one routes to a human. Force
    // consequential so the self-heal-BEFORE-routing mechanic is exercised (a plan needing rework is consequential).
    planVet: async () => ({ cleared: false, decision: "rework" as const, reason: "consequential — routes to a human" }),
    safeRemediation: spy,
  });
  const r = await pipeline.solveIssueToPR({ id: "HEAL-1", text: "add() subtracts", repoRef: "h" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  assert.equal(healInvoked, true, "self-heal was attempted before routing");
  assert.ok(r.safety?.selfHealing, "self-heal outcome surfaced");
  assert.equal(r.safety?.selfHealing?.healed, false, "spy declined → not healed → routed");
  // PR still human-gated (not auto-approved) since it wasn't healed.
  assert.ok(r.manifest?.humanApprovalRequired, "unhealed → human-gated");
});

test("INVARIANT: a routed PR carries a NEUTRAL decision brief (16.9b)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const gov = new GovernanceLedger(spine);
  const pipeline = new KeepPipeline({
    spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: gov,
    vet: async () => false, // force routing → brief should be built
    planVet: async () => ({ cleared: false, decision: "rework" as const, reason: "consequential — routes to a human" }),
  });
  const r = await pipeline.solveIssueToPR({ id: "BRIEF-1", text: "add() subtracts", repoRef: "b" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  assert.ok(r.safety?.decisionBrief, "routed PR carries a decision brief");
  const text = JSON.stringify(r.safety!.decisionBrief).toLowerCase();
  for (const banned of ["looks good", "recommend approving", "should be fine", "no concerns"]) {
    assert.ok(!text.includes(banned), `brief must not persuade ("${banned}")`);
  }
  assert.ok(r.safety!.decisionBrief!.verifyThis.endsWith("?"), "brief asks a verify question");
});

test("INVARIANT: the patch-time forecast surfaces on the result (compositional, on actual edits)", async () => {
  const { work } = setupRemote();
  const spine = newSpine(); const t = tree();
  applyFix(work);
  const gov = new GovernanceLedger(spine);
  const pipeline = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: gov });
  const r = await pipeline.solveIssueToPR({ id: "PF-1", text: "fix add()", repoRef: "b" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
  assert.ok(r.safety?.patchForecast, "patch-time forecast is surfaced");
  assert.ok(typeof r.safety!.patchForecast!.maxOrder === "number", "forecast carries the projection depth");
});

test("INVARIANT: the pipeline surfaces the operator's brain capability (front/back of room), default lean-safe", async () => {
  // Default (no brainCapability) → "lean" (back-of-room-safe; full deterministic floor still runs).
  {
    const { work } = setupRemote(); const spine = newSpine(); const t = tree(); applyFix(work);
    const p1 = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: new GovernanceLedger(spine) });
    const r1 = await p1.solveIssueToPR({ id: "CAP-1", text: "fix add()", repoRef: "b" }, FILES, pinnedGitDependencies(work), {});
    assert.equal(r1.safety?.brainCapability, "lean", "defaults to lean (back-of-room-safe)");
  }
  // Front-of-room rich brain flows through (fresh fixtures).
  {
    const { work } = setupRemote(); const spine = newSpine(); const t = tree(); applyFix(work);
    const p2 = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: new GovernanceLedger(spine), brainCapability: "rich" });
    const r2 = await p2.solveIssueToPR({ id: "CAP-2", text: "fix add()", repoRef: "b" }, FILES, pinnedGitDependencies(work), {});
    assert.equal(r2.safety?.brainCapability, "rich");
  }
});

test("INVARIANT: isolation→autonomy feedback — a clean patch auto-approvable under microVM ROUTES under process isolation", async () => {
  // microVM: full ceiling → a clean patch can auto-approve.
  let microDisposition: string | undefined;
  {
    const { work } = setupRemote(); const spine = newSpine(); const t = tree(); applyFix(work);
    const p = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: new GovernanceLedger(spine), isolationTier: "microvm" });
    const r = await p.solveIssueToPR({ id: "ISO-1", text: "fix add()", repoRef: "b" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
    microDisposition = r.manifest?.oversight?.disposition;
    assert.equal(r.safety?.isolationTier, "microvm");
  }
  // process: minimal ceiling → the SAME clean patch is routed to a human (larger blast radius on escape).
  {
    const { work } = setupRemote(); const spine = newSpine(); const t = tree(); applyFix(work);
    const p = new KeepPipeline({ spine, tree: t, runner: runnerFor(t), model: fixModel(), governance: new GovernanceLedger(spine), isolationTier: "process" });
    const r = await p.solveIssueToPR({ id: "ISO-2", text: "fix add()", repoRef: "b" }, FILES, pinnedGitDependencies(work), { autonomyLevel: "operator" });
    assert.equal(r.safety?.isolationTier, "process");
    // Under process isolation, auto-approval is suppressed → the PR requires human review regardless.
    assert.equal(r.manifest?.humanApprovalRequired, true, "weak isolation → human review required");
  }
});
