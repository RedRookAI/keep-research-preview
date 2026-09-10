import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RollbackLedger } from "../src/control/rollback.js";
import type { Embedding, GenerateRequest, GenerateResult, ModelProvider } from "../src/gateway/gateway.js";
import { GitMergePort } from "../src/git/git_merge_port.js";
import { LocalPullRequest } from "../src/git/pull_request.js";
import { publishSolveAsPr } from "../src/git/pr_publisher.js";
import { materializeRepository } from "../src/git/repository_materializer.js";
import { GitRemote } from "../src/git/git_remote.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";
import { GitAdapter } from "../src/infra/git_adapter.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../src/infra/microvm_boundary.js";
import { InProcessLock } from "../src/lock/lock.js";
import type { MergeSpec } from "../src/oversight/merge_executor.js";
import { HierarchicalLocalizer } from "../src/solve/localize.js";
import { GraphLocalizer } from "../src/coderag/graph_localizer.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import { LocalFsWorkspace } from "../src/solve/workspace.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { DEFAULT_SOLVER_IDENTITY_ID } from "../src/identity/agent_identity.js";
import { runCli, type CliIO } from "../src/cli/cli_core.js";

function g(cwd: string, ...args: string[]): string { return execFileSync("git", args, { cwd }).toString().trim(); }

class FixModel implements ModelProvider {
  readonly name = "deterministic-fix"; readonly isLocal = true;
  async generate(_req: GenerateRequest): Promise<GenerateResult> {
    if (_req.hints?.["taskRole"] === "goal_test") return {
      text: JSON.stringify({ body: "const {pathToFileURL}=await import('node:url'); const {join}=await import('node:path'); const {add}=await import(pathToFileURL(join(process.cwd(),'calc.js'))); assert.equal(add(2,3),5);" }),
      model: this.name, tokensIn: 1, tokensOut: 1,
    };
    return { text: JSON.stringify({ rationale: "replace subtraction", edits: [{ file: "calc.js", search: "return a - b", replace: "return a + b", intent: "add the operands" }] }), model: this.name, tokensIn: 1, tokensOut: 1 };
  }
  async embed(_text: readonly string[]): Promise<Embedding[]> { return []; }
}

test("R1: exact materialization → localization → patch → sandboxed tests → PR → local merge → revert", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-r1-"));
  const source = join(root, "source"); const workspaceBase = join(root, "workspace"); const state = join(root, "state");
  execFileSync("git", ["init", "-q", "-b", "main", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('adds without inherited host secrets', () => { assert.equal(process.env.HOME, undefined); assert.equal(add(2, 3), 5); });\n");
  const outsideSecret = join(root, "outside-secret.js");
  writeFileSync(outsideSecret, "DO_NOT_READ_OUTSIDE_WORKSPACE\n");
  symlinkSync(outsideSecret, join(source, "leak.js"));
  g(source, "add", "-A"); g(source, "commit", "-qm", "buggy base");
  const base = g(source, "rev-parse", "HEAD");
  const materialized = await materializeRepository({ sourceDir: source, workspaceBase, repoRef: "ticket-1", commit: base });
  const git = new GitAdapter(materialized.projectDir);
  await git.git(["config", "user.email", "keep@test"]); await git.git(["config", "user.name", "Keep"]);
  const workspace = new LocalFsWorkspace(workspaceBase);
  const spine = new Spine(new FileSpineStore(state, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const runner = new SandboxedCommandRunner({ command: process.execPath, args: ["--test", "calc.test.js"], projectDir: materialized.projectDir, namespaceJail: false });
  const issue = { id: "R1-FIX", text: "add in calc.js subtracts instead of adding", repoRef: materialized.repoRef };
  const result = await new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree: workspace.tree(materialized.repoRef), runner, localizer: new HierarchicalLocalizer(), model: new FixModel() }).run(issue, await workspace.files(materialized.repoRef));
  assert.equal(result.solved, true); assert.equal((await runner.run(".")).results.every((row) => row.passed), true);

  const sourceUrl = `file://${source}`;
  await git.git(["remote", "set-url", "origin", sourceUrl]);
  const remote = new GitRemote(git, { expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(sourceUrl), expectedPushUrlSha256: pinnedRemoteUrlSha256(sourceUrl), runId: "r1-flow" });
  const published = await publishSolveAsPr(result, { git, remote, prPort: new LocalPullRequest(), baseBranch: "main" });
  assert.match(published.manifest.diff, /return a \+ b/);

  const port = new GitMergePort(git, { publicationSpine: spine });
  const spec: MergeSpec = { issueId: issue.id, repoRef: issue.repoRef, branch: result.prProposal!.branch, baseBranch: "main", expectedCandidateCommit: await git.head(), expectedCandidateProjectManifestDigest: await computeMicrovmProjectSourceManifestSha256(materialized.projectDir), expectedGuestExecutionRequestDigest: "a".repeat(64), projectDir: materialized.projectDir };
  const preflight = await port.dryRun(spec); assert.equal(preflight.clean, true, preflight.reason);
  const merged = await port.merge(spec, preflight.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(merged.merged, true, merged.reason); assert.match(readFileSync(join(materialized.projectDir, "calc.js"), "utf8"), /a \+ b/);
  const reverted = await port.revert(merged.mergeId, spec);
  assert.equal(reverted.reverted, true, reverted.reason); assert.match(readFileSync(join(materialized.projectDir, "calc.js"), "utf8"), /a - b/);
});

test("R1 materialization refuses traversal and mutable revision names", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-r1-refuse-"));
  execFileSync("git", ["init", "-q", "-b", "main", root]);
  await assert.rejects(() => materializeRepository({ sourceDir: root, workspaceBase: join(root, "ws"), repoRef: "../escape", commit: "main" }), /escapes|exact commit/);
});

test("installed source landing on an explicit non-main branch survives restart, reverts exactly, and leaves materialization reusable", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-source-landing-"));
  const source = join(root, "source"), workspaceBase = join(root, "workspace"), dataDir = join(root, "state");
  mkdirSync(workspaceBase);
  execFileSync("git", ["init", "-q", "-b", "work/canonical", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('adds', () => assert.equal(add(2, 3), 5));\n");
  g(source, "add", "-A"); g(source, "commit", "-qm", "buggy base");
  const base = g(source, "rev-parse", "HEAD");
  const config = (commit: string) => ({ dataDir, developmentProvider: new FixModel(), sourceLanding: true,
    repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project", commit, baseBranch: "work/canonical" },
    testCommand: { command: process.execPath, args: ["--test", "calc.test.js"], timeoutMs: 30_000 },
  } as const);
  let app = composeKeep(config(base));
  const started = JSON.parse((await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer owner" }, body: JSON.stringify({ goal: "fix add in calc.js so it adds" }) }, { token: "owner" })).body) as { runId: string; proposalDigest: string };
  assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/u, "proposal leaves declared source unchanged");
  const approve = () => handleGatewayRequest(app, { method: "POST", path: "/project/merge", query: {}, headers: { authorization: "Bearer owner" }, body: JSON.stringify({ runId: started.runId, decision: "approve", proposalDigest: started.proposalDigest }) }, { token: "owner" });
  const merged = JSON.parse((await approve()).body) as { status: string; mergeId: string; reason: string };
  assert.equal(merged.status, "merged", merged.reason); assert.equal(g(source, "rev-parse", "HEAD"), merged.mergeId); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a \+ b/u);
  app = composeKeep(config(base));
  assert.equal((JSON.parse((await approve()).body) as { status: string }).status, "merged", "restart reconciles source landing");
  const reverted = JSON.parse((await handleGatewayRequest(app, { method: "POST", path: "/project/revert", query: {}, headers: { authorization: "Bearer owner" }, body: JSON.stringify({ runId: started.runId }) }, { token: "owner" })).body) as { status: string; revertCommit: string; reason: string };
  assert.equal(reverted.status, "reverted", reverted.reason); assert.equal(g(source, "rev-parse", "HEAD"), reverted.revertCommit); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/u);
  app = composeKeep(config(reverted.revertCommit));
  const second = await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer owner" }, body: JSON.stringify({ goal: "fix add in calc.js so it adds again" }) }, { token: "owner" });
  assert.equal(second.status, 200); assert.equal((JSON.parse(second.body) as { proposal: boolean }).proposal, true, "a landed-and-reverted workspace admits a second real project cycle");
});

test("INTEG-03: malformed forge authority is refused before a workspace is materialized", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-integ03-pin-"));
  execFileSync("git", ["init", "-q", "-b", "main", root]); g(root, "config", "user.email", "keep@test"); g(root, "config", "user.name", "Keep");
  writeFileSync(join(root, "x"), "x"); g(root, "add", "x"); g(root, "commit", "-qm", "base");
  const workspaceBase = join(root, "workspace");
  await assert.rejects(materializeRepository({ sourceDir: root, workspaceBase, repoRef: "project", commit: g(root, "rev-parse", "HEAD"), developmentForge: { remote: "forge", fetchUrl: "file:///approved", pushUrl: "file:///approved", expectedFetchUrlSha256: "0".repeat(64), expectedPushUrlSha256: "0".repeat(64) } }), /operator-pinned digest/);
  assert.throws(() => readFileSync(join(workspaceBase, "project")), /ENOENT/u);
});

test("INTEG-03: installed project pushes, merges, and reverts on a pinned private development forge", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-integ03-"));
  const source = join(root, "source"), remote = join(root, "private.git"), workspaceBase = join(root, "workspace");
  mkdirSync(workspaceBase);
  execFileSync("git", ["init", "-q", "-b", "main", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('adds', () => assert.equal(add(2, 3), 5));\n");
  g(source, "add", "-A"); g(source, "commit", "-qm", "buggy base");
  execFileSync("git", ["init", "-q", "--bare", remote]);
  const forgeUrl = `file://${remote}`;
  g(source, "push", forgeUrl, "main:main");
  const config = {
    dataDir: join(root, "state"), developmentProvider: new FixModel(),
    repositoryMaterialization: {
      sourceDir: source, workspaceBase, repoRef: "private-project", commit: g(source, "rev-parse", "HEAD"),
      developmentForge: { remote: "private-forge", fetchUrl: forgeUrl, pushUrl: forgeUrl, expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(forgeUrl), expectedPushUrlSha256: pinnedRemoteUrlSha256(forgeUrl) },
    },
    testCommand: { command: process.execPath, args: ["--test", "calc.test.js"], timeoutMs: 30_000, cpuLimitSec: 20, maxOutputBytes: 16_384 },
  } as const;
  let app = composeKeep(config);
  const lines: string[] = [];
  assert.equal((await runCli(["project", "fix add in calc.js so it adds"], { write: (line) => lines.push(line), prompt: async () => "" }, { app })).exitCode, 0);
  const runId = /Run: ([^\s]+)/u.exec(lines.join("\n"))?.[1]; assert.ok(runId);
  const proposalDigest = /--proposal=([0-9a-f]{64})/u.exec(lines.join("\n"))?.[1]; assert.ok(proposalDigest);
  const call = (path: string, body: Record<string, unknown>) => handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer forge-token" }, body: JSON.stringify(body) }, { token: "forge-token" });
  const mergeController = app.projectMerge as unknown as { deps: { crashProbe?: (phase: string) => void } };
  mergeController.deps.crashProbe = (phase) => { if (phase === "merge.effect-completed") throw new Error("simulated forge merge completion power loss"); };
  await assert.rejects(call("/project/merge", { runId, decision: "approve", proposalDigest }), /simulated forge merge completion power loss/u);
  const remotelyMerged = g(remote, "rev-parse", "refs/heads/main");
  app = composeKeep(config);
  const merged = JSON.parse((await call("/project/merge", { runId, decision: "approve", proposalDigest })).body) as { status: string; mergeId?: string; publicationTarget?: string; reason: string };
  assert.equal(merged.status, "merged", merged.reason); assert.match(merged.publicationTarget ?? "", /^remote:private-forge:/u);
  assert.equal(g(remote, "rev-parse", "refs/heads/main"), remotelyMerged, "restart observes rather than repeats the forge merge");
  assert.equal(remotelyMerged, merged.mergeId);
  assert.match(g(remote, "show", "main:calc.js"), /a \+ b/u);
  const revertController = app.projectMerge as unknown as { deps: { crashProbe?: (phase: string) => void } };
  revertController.deps.crashProbe = (phase) => { if (phase === "revert.effect-completed") throw new Error("simulated forge revert completion power loss"); };
  await assert.rejects(call("/project/revert", { runId }), /simulated forge revert completion power loss/u);
  const remotelyReverted = g(remote, "rev-parse", "refs/heads/main");
  app = composeKeep(config);
  const reverted = JSON.parse((await call("/project/revert", { runId })).body) as { status: string; revertCommit?: string; reason: string };
  assert.equal(reverted.status, "reverted", reverted.reason);
  assert.equal(g(remote, "rev-parse", "refs/heads/main"), remotelyReverted, "restart observes rather than repeats the forge revert");
  assert.equal(remotelyReverted, reverted.revertCommit);
  assert.match(g(remote, "show", "main:calc.js"), /a - b/u);
  const effects = app.spine.replay().map((event) => event.payload as Record<string, unknown>);
  assert.equal(effects.filter((event) => event["kind"] === "local_merge.intent").length, 1);
  assert.equal(effects.filter((event) => event["kind"] === "local_merge.revert_intent").length, 1);
});

test("SOLVE-08: configured-graph CLI/API repository journey reconstructs exact project and proposal without redispatch", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-solve01-installed-"));
  const source = join(root, "source");
  const workspaceBase = join(root, "workspace");
  mkdirSync(workspaceBase);
  execFileSync("git", ["init", "-q", "-b", "main", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('adds', () => assert.equal(add(2, 3), 5));\n");
  const outsideSecret = join(root, "outside-secret.js");
  writeFileSync(outsideSecret, "DO_NOT_READ_OUTSIDE_WORKSPACE\n");
  symlinkSync(outsideSecret, join(source, "leak.js"));
  g(source, "add", "-A"); g(source, "commit", "-qm", "exact buggy base");
  const commit = g(source, "rev-parse", "HEAD");
  const config = {
    dataDir: join(root, "state"), developmentProvider: new FixModel(),
    // Named-path defaults deliberately use BM25 only. This retained graph-flow
    // case requests the actual graph implementation instead of assuming a default.
    projectLocalizer: new GraphLocalizer(),
    repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project-1", commit },
    testCommand: { command: process.execPath, args: ["--test", "calc.test.js"], timeoutMs: 30_000, cpuLimitSec: 20, maxOutputBytes: 16_384 },
  } as const;
  let app = composeKeep(config);
  const quarantinedBeforeValidRun = app.projectManager!.create({ name: "corrupt unrelated project" });
  mkdirSync(join(config.dataDir, "projects", "sessions"), { recursive: true });
  writeFileSync(join(config.dataDir, "projects", "sessions", `${quarantinedBeforeValidRun.id}.json`), "{malformed\n");
  app = composeKeep(config);
  assert.match(app.projectManager!.quarantine(quarantinedBeforeValidRun.id) ?? "", /invalid project session store/u);

  const cliLines: string[] = [];
  const cliIo: CliIO = { write: (line) => cliLines.push(line), prompt: async () => "" };
  const cliResult = await runCli(["project", "fix add in calc.js so it adds"], cliIo, { app });
  assert.equal(cliResult.exitCode, 0);
  const runId = /Run: ([^\s]+)/u.exec(cliLines.join("\n"))?.[1];
  assert.ok(runId, "the installed CLI exposes the durable run identity needed by API clients");
  const observedStart = await handleGatewayRequest(app, {
    method: "GET", path: "/project", query: { runId }, headers: { authorization: "Bearer solve-token" }, body: "",
  }, { token: "solve-token" });
  const boundaryView = JSON.parse(observedStart.body) as {
    projectId: string;
    project: { runId: string; status: string; note?: string };
    proposal: { baseRevision: string; diff: string; checks: { testsPassed: boolean; vettingCleared: boolean }; rollback: { patchSha256: string } };
  };
  const boundary = { runId, status: boundaryView.project.status, note: boundaryView.project.note ?? null };
  const state = boundaryView.project as unknown as import("../src/autonomy/project_state.js").ProjectState;

  assert.equal(observedStart.status, 200);
  assert.equal(boundary.status, "completed", boundary.note ?? undefined);
  const implementation = state.artifacts["implement"] as { issue: { repoRef: string }; solve: {
    authority: unknown;
    localization: { stages: string[]; selected: Array<{ path: string; rank: number; score: number; reason: string }> };
    proposalEvidence: { baseRevision: string; diff: string; checks: { testsPassed: boolean; vettingCleared: boolean }; consequence: { band: string; forcedGate: boolean; reasons: string[] }; rollback: { strategy: string; patchSha256: string } };
  } };
  assert.equal(implementation.issue.repoRef, "project-1");
  assert.deepEqual(implementation.solve.authority, {
    actorId: `keep-default-solver:${boundary.runId}`, parentActorId: "keep-default-solver", repository: "project-1",
    writeScope: ["."], writeGrant: "per-edit-one-shot", budgetEnvelopeId: "autonomy-default", delegation: "attenuated",
  });
  // Admission consumes the project plan's persisted localization rather than
  // rerunning repository discovery inside the solver. Inspect its owning record.
  const localized = (state.artifacts["plan"] as { localization: import("../src/autonomy/project_localization.js").ProjectLocalizationArtifact }).localization;
  assert.deepEqual(localized.stages, ["bm25", "graph"]);
  assert.equal(localized.selected[0]?.path, "calc.js");
  assert.equal(localized.selected.findIndex(row => row.path === "calc.js"), 0);
  assert.ok((localized.selected[0]?.score ?? 0) > 0);
  assert.match(localized.selected[0]?.reason ?? "", /rank 1 from bm25 \+ graph retrieval at score/);
  assert.ok(!localized.selected.some((row) => row.path === "leak.js"));
  const recovery = implementation.solve.proposalEvidence;
  assert.equal(recovery.baseRevision, commit);
  assert.match(recovery.diff, /diff --git a\/calc\.js b\/calc\.js/);
  assert.match(recovery.diff, /return a - b/);
  assert.match(recovery.diff, /return a \+ b/);
  assert.deepEqual({ testsPassed: recovery.checks.testsPassed, vettingCleared: recovery.checks.vettingCleared }, { testsPassed: true, vettingCleared: true });
  assert.equal(recovery.consequence.band, "low");
  assert.equal(recovery.consequence.forcedGate, false);
  assert.ok(recovery.consequence.reasons.some((reason) => reason.includes("revert-safe")));
  assert.equal(recovery.rollback.strategy, "git-apply-reverse");
  assert.equal(recovery.rollback.patchSha256, createHash("sha256").update(recovery.diff).digest("hex"));
  assert.equal(boundaryView.proposal.baseRevision, recovery.baseRevision, "authenticated API exposes the persisted decision base");
  assert.equal(boundaryView.proposal.diff, recovery.diff, "authenticated API exposes the exact proposal evidence");
  assert.deepEqual(boundaryView.proposal.checks, recovery.checks);
  assert.equal(boundaryView.proposal.rollback.patchSha256, recovery.rollback.patchSha256);
  const viewer = { token: "solve-token", principalFor: () => ({ id: "read-only", kind: "human" as const, role: "viewer" as const, tenant: "tenant-viewer" }) };
  assert.equal((await handleGatewayRequest(app, {
    method: "GET", path: "/project", query: { runId: boundary.runId }, headers: { authorization: "Bearer solve-token" }, body: "",
  }, viewer)).status, 404, "a later cross-tenant viewer cannot discover a personal-mode project's decision evidence");
  assert.equal((await handleGatewayRequest(app, {
    method: "POST", path: "/project/merge", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId: boundary.runId, decision: "approve", proposalDigest: recovery.rollback.patchSha256 }),
  }, viewer)).status, 404, "a cross-tenant read-only principal cannot discover or decide the personal-mode project");
  assert.equal((await handleGatewayRequest(app, {
    method: "POST", path: "/project/revert", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId: boundary.runId }),
  }, viewer)).status, 403, "read-only principal cannot recover by mutating repository state");
  const rollbackProbe = join(root, "rollback-probe");
  execFileSync("git", ["clone", "-q", source, rollbackProbe]);
  execFileSync("git", ["apply", "--binary", "-"], { cwd: rollbackProbe, input: recovery.diff });
  execFileSync("git", ["apply", "--reverse", "--binary", "-"], { cwd: rollbackProbe, input: recovery.diff });
  assert.match(readFileSync(join(rollbackProbe, "calc.js"), "utf8"), /a - b/, "the persisted reverse-diff recipe is executable from the exact base");
  const events = app.spine.currentEvents().map((event) => event.payload as Record<string, unknown>);
  const boundAt = events.findIndex((payload) => payload["event"] === "solve.authority_bound");
  const localizationAt = events.findIndex((payload) => payload["stage"] === "localize" && payload["issueId"] === boundary.runId);
  assert.ok(boundAt >= 0 && localizationAt > boundAt, "project authority is durably bound before repository localization, planning, edits, and tests");
  const isolation = events.find((payload) => payload["event"] === "isolated_execution" && payload["executed"] === true);
  assert.equal(isolation?.["tier"], "process", "the installed solve records the measured executor tier");
  assert.match(String(isolation?.["detail"]), /resource-bounded command/);
  assert.equal(events.filter((payload) => payload["event"] === "isolated_execution").length, 4,
    "baseline goal check, patched regression, patched goal check and independent verifier each execute once");
  assert.equal(g(join(workspaceBase, "project-1"), "rev-parse", "HEAD"), commit);
  assert.match(readFileSync(join(workspaceBase, "project-1", "calc.js"), "utf8"), /a \+ b/);
  assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/, "the source repository is never edited in place");
  const mergeRequest = () => handleGatewayRequest(app, {
    method: "POST", path: "/project/merge", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId: boundary.runId, decision: "approve", proposalDigest: recovery.rollback.patchSha256 }),
  }, { token: "solve-token" });
  const armCrash = (phase: string): void => {
    const controller = app.projectMerge as unknown as { deps: { crashProbe?: (observed: string) => void } };
    controller.deps.crashProbe = (observed) => { if (observed === phase) throw new Error(`simulated restart after ${phase}`); };
  };
  armCrash("merge.intent-sealed");
  await assert.rejects(mergeRequest, /simulated restart after merge\.intent-sealed/);
  assert.equal(g(join(workspaceBase, "project-1"), "rev-parse", "HEAD"), commit, "intent is durable before the first repository mutation");
  assert.equal(g(join(workspaceBase, "project-1"), "branch", "--list", "keep/*"), "");
  app = composeKeep(config);
  armCrash("merge.candidate-branch-created");
  await assert.rejects(mergeRequest, /simulated restart after merge\.candidate-branch-created/);
  assert.equal(g(join(workspaceBase, "project-1"), "rev-parse", "HEAD"), commit);
  assert.match(g(join(workspaceBase, "project-1"), "branch", "--show-current"), /^keep\//);
  app = composeKeep(config);
  armCrash("merge.candidate-committed");
  await assert.rejects(mergeRequest, /simulated restart after merge\.candidate-committed/);
  const candidateAfterRestart = g(join(workspaceBase, "project-1"), "rev-parse", "HEAD");
  assert.notEqual(candidateAfterRestart, commit);
  app = composeKeep(config);
  armCrash("merge.effect-completed");
  await assert.rejects(mergeRequest, /simulated restart after merge\.effect-completed/);
  const mergeHeadBeforeCompletion = g(join(workspaceBase, "project-1"), "rev-parse", "HEAD");
  assert.equal(app.spine.replay().some((event) => event.payload["event"] === "local_merge.merged"), false, "the test interruption precedes durable completion");
  app = composeKeep(config);
  const mergeResponse = await mergeRequest();
  const localMerge = JSON.parse(mergeResponse.body) as { status: string; reason: string; mergeId?: string };
  assert.equal(localMerge.status, "merged", localMerge.reason);
  assert.ok(localMerge.mergeId);
  assert.equal(localMerge.mergeId, mergeHeadBeforeCompletion, "restart observes the exact merge instead of dispatching another one");
  assert.equal(g(join(workspaceBase, "project-1"), "branch", "--show-current"), "main");
  assert.equal(g(join(workspaceBase, "project-1"), "rev-list", "--parents", "-n", "1", "HEAD").split(" ").length, 3, "local result is a history-preserving merge commit");
  const work = join(workspaceBase, "project-1");
  app = composeKeep(config);
  const completedReplay = JSON.parse((await mergeRequest()).body) as { status: string; mergeId?: string };
  assert.equal(completedReplay.status, "merged"); assert.equal(completedReplay.mergeId, localMerge.mergeId);
  assert.equal(g(work, "rev-parse", "HEAD"), mergeHeadBeforeCompletion, "restart after completion does not create another merge");
  const cliMergeLines: string[] = [];
  assert.equal((await runCli(["merge", boundary.runId, "approve", `--proposal=${recovery.rollback.patchSha256}`], { write: (line) => cliMergeLines.push(line), prompt: async () => "" }, { app })).exitCode, 0);
  assert.match(cliMergeLines.join("\n"), /Merge merged:.*already (?:merged|landed)/);
  assert.equal(g(work, "rev-parse", "HEAD"), mergeHeadBeforeCompletion, "CLI observes the same completed merge without redispatch");
  assert.equal(app.spine.replay().filter((event) => event.type === "effect.intent" && event.payload["kind"] === "local_merge.intent").length, 1);
  assert.equal(app.spine.replay().filter((event) => event.payload["event"] === "local_merge.merged").length, 1);
  execFileSync("git", ["commit", "--allow-empty", "-m", "intervening operator history"], { cwd: work });
  const intervening = g(work, "rev-parse", "HEAD");
  const revertRequest = () => handleGatewayRequest(app, {
    method: "POST", path: "/project/revert", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId: boundary.runId }),
  }, { token: "solve-token" });
  armCrash("revert.intent-sealed");
  await assert.rejects(revertRequest, /simulated restart after revert\.intent-sealed/);
  assert.equal(g(work, "rev-parse", "HEAD"), intervening, "revert intent is durable before repository mutation");
  app = composeKeep(config);
  armCrash("revert.effect-completed");
  await assert.rejects(revertRequest, /simulated restart after revert\.effect-completed/);
  const revertHeadBeforeCompletion = g(work, "rev-parse", "HEAD");
  assert.equal(app.spine.replay().some((event) => event.type === "effect.terminal" && event.payload["kind"] === "local_merge.revert_terminal"), false);
  app = composeKeep(config);
  const revertResponse = await revertRequest();
  const reverted = JSON.parse(revertResponse.body) as { status: string; reason: string; mergeId?: string; revertCommit?: string };
  assert.equal(reverted.status, "reverted", reverted.reason);
  assert.equal(reverted.mergeId, localMerge.mergeId);
  assert.ok(reverted.revertCommit && reverted.revertCommit !== intervening);
  assert.equal(reverted.revertCommit, revertHeadBeforeCompletion, "restart observes the exact revert instead of dispatching another one");
  assert.match(readFileSync(join(work, "calc.js"), "utf8"), /a - b/);
  const history = g(work, "log", "--format=%H");
  assert.match(history, new RegExp(localMerge.mergeId!)); assert.match(history, new RegExp(intervening));
  const headAfterRevert = g(work, "rev-parse", "HEAD");
  app = composeKeep(config);
  const repeated = JSON.parse((await revertRequest()).body) as { status: string; revertCommit?: string };
  assert.equal(repeated.status, "reverted"); assert.equal(repeated.revertCommit, reverted.revertCommit);
  const cliRevertLines: string[] = [];
  assert.equal((await runCli(["revert", boundary.runId], { write: (line) => cliRevertLines.push(line), prompt: async () => "" }, { app })).exitCode, 0);
  assert.match(cliRevertLines.join("\n"), /Revert reverted: (?:workspace )?revert already completed/);
  assert.equal(g(work, "rev-parse", "HEAD"), headAfterRevert, "repeat revert performs no second Git effect");
  assert.equal(app.spine.currentEvents().filter((event) => event.type === "effect.terminal" && (event.payload as Record<string, unknown>)["kind"] === "local_merge.revert_terminal").length, 1);
  app = composeKeep(config);
  const reconstructed = JSON.parse((await handleGatewayRequest(app, {
    method: "GET", path: "/project", query: { runId: boundary.runId }, headers: { authorization: "Bearer solve-token" }, body: "",
  }, { token: "solve-token" })).body) as {
    project: { runId: string; status: string; artifacts: Record<string, unknown> }; proposal: unknown;
    session: { record: { id: string; name: string; lifecycle: string }; history: Array<{ role: string; text: string }>; checkpoint: unknown; budget: { spentTokensToday: number } };
  };
  assert.deepEqual(reconstructed.project, state, "the installed API reconstructs the complete durable project state");
  assert.deepEqual(reconstructed.proposal, recovery, "the installed API reconstructs the same exact proposal rather than rerunning the project");
  assert.equal(reconstructed.session.record.id, boundaryView.projectId); assert.notEqual(reconstructed.session.record.id, boundary.runId);
  assert.equal(reconstructed.session.record.lifecycle, "background", "completed work may remain safely backgrounded across restart");
  assert.deepEqual(reconstructed.session.checkpoint, state);
  assert.deepEqual(reconstructed.session.history.map(({ role, text }) => ({ role, text })), [
    { role: "user", text: "fix add in calc.js so it adds" }, { role: "event", text: "Project status: completed" },
  ], "the wrapped project key decrypts the same installed session after reconstruction");
  assert.equal(reconstructed.session.budget.spentTokensToday, 4, "reconstruction retains one synthetic input/output token pair for each of the proposal and goal-test calls");
  const sessionAtRest = JSON.parse(readFileSync(join(root, "state", "projects", "sessions", `${boundaryView.projectId}.json`), "utf8")) as { history: unknown };
  assert.doesNotMatch(JSON.stringify(sessionAtRest.history), /fix add in calc\.js|Project status/, "session history payloads remain encrypted at rest on the installed path");
  const reopenedCliLines: string[] = [];
  await runCli(["projects"], { write: (line) => reopenedCliLines.push(line), prompt: async () => "" }, { app });
  assert.match(reopenedCliLines.join("\n"), /fix add in calc\.js so it adds/, "the installed CLI observes the durable project after reconstruction");
  const visible = await new LocalFsWorkspace(workspaceBase).files("project-1");
  assert.ok(!visible.some((file) => file.path === "leak.js" || file.content.includes("DO_NOT_READ_OUTSIDE_WORKSPACE")), "symlinked out-of-workspace data is never exposed to the solver");
  await assert.rejects(() => new LocalFsWorkspace(workspaceBase).tree("project-1").write("leak.js", "overwrite"), /symlink/);
});

test("SOLVE-03: installed solve refuses before test spawn when the required measured tier is unavailable", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-solve03-tier-refuse-"));
  const source = join(root, "source"); const workspaceBase = join(root, "workspace");
  mkdirSync(workspaceBase);
  execFileSync("git", ["init", "-q", "-b", "main", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "throw new Error('must never spawn below required tier');\n");
  g(source, "add", "-A"); g(source, "commit", "-qm", "buggy base");
  const app = composeKeep({
    dataDir: join(root, "state"), developmentProvider: new FixModel(),
    repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project-1", commit: g(source, "rev-parse", "HEAD") },
    testCommand: { command: process.execPath, args: ["--test", "calc.test.js"], timeoutMs: 30_000 },
    projectTestRequiredTier: "microvm",
  });

  const response = await handleGatewayRequest(app, {
    method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ goal: "fix add in calc.js so it adds", stepBudget: 50 }),
  }, { token: "solve-token" });
  const boundary = JSON.parse(response.body) as { runId: string; status: string; note: string | null };
  assert.equal(response.status, 200);
  assert.equal(boundary.status, "waiting-capability", "missing measured isolation is a resumable named capability, not a terminal failure");
  assert.match(boundary.note ?? "", /goal check did not demonstrate an executing baseline defect/);
  const isolationEvents = app.spine.currentEvents().map((event) => event.payload as Record<string, unknown>)
    .filter((payload) => payload["event"] === "isolated_execution");
  assert.equal(isolationEvents.length, 1, "an infrastructure refusal never enters the repair loop or spawns below the required tier");
  const refusal = isolationEvents.find((payload) => payload["executed"] === false);
  assert.match(String(refusal?.["detail"]), /required microvm isolation is unavailable.*refusing execution/);
  assert.equal(refusal?.["requiredTier"], "microvm");
  assert.match(String(refusal?.["detail"]), /strongest measured enforcing tier is process/);
  const mergeResponse = await handleGatewayRequest(app, {
    method: "POST", path: "/project/merge", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId: boundary.runId, decision: "approve" }),
  }, { token: "solve-token" });
  assert.equal(mergeResponse.status, 400, "a run without a verified proposal digest cannot enter merge authority");
  assert.equal(g(join(workspaceBase, "project-1"), "branch", "--show-current"), "main", "failed checks create no candidate branch or merge");
});

test("SOLVE-05: veto, stale base, and kill each refuse before local merge mutation", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-solve05-refuse-"));
  const source = join(root, "source"); const workspaceBase = join(root, "workspace");
  mkdirSync(workspaceBase);
  execFileSync("git", ["init", "-q", "-b", "main", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('adds', () => assert.equal(add(2, 3), 5));\n");
  g(source, "add", "-A"); g(source, "commit", "-qm", "base");
  const base = g(source, "rev-parse", "HEAD");
  const app = composeKeep({
    dataDir: join(root, "state"), developmentProvider: new FixModel(),
    repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project-1", commit: base },
    testCommand: { command: process.execPath, args: ["--test", "calc.test.js"], timeoutMs: 30_000 },
  });
  const project = await handleGatewayRequest(app, {
    method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ goal: "fix add in calc.js so it adds", stepBudget: 50 }),
  }, { token: "solve-token" });
  const boundary = JSON.parse(project.body) as { runId: string; proposalDigest: string };
  const runId = boundary.runId;
  const work = join(workspaceBase, "project-1");
  const decide = async (decision: "approve" | "veto") => JSON.parse((await handleGatewayRequest(app, {
    method: "POST", path: "/project/merge", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId, decision, proposalDigest: boundary.proposalDigest }),
  }, { token: "solve-token" })).body) as { status: string; reason: string };

  const env = { ...process.env, GIT_AUTHOR_NAME: "operator", GIT_AUTHOR_EMAIL: "operator@test", GIT_COMMITTER_NAME: "operator", GIT_COMMITTER_EMAIL: "operator@test" };
  const tree = g(work, "rev-parse", `${base}^{tree}`);
  const moved = execFileSync("git", ["commit-tree", tree, "-p", base, "-m", "concurrent base movement"], { cwd: work, env }).toString().trim();
  execFileSync("git", ["update-ref", "refs/heads/main", moved, base], { cwd: work });
  const stale = await decide("approve");
  assert.equal(stale.status, "refused"); assert.match(stale.reason, /stale|moved/);
  assert.equal(g(work, "branch", "--list", "keep/*"), "", "stale base is detected before candidate creation");
  execFileSync("git", ["update-ref", "refs/heads/main", base, moved], { cwd: work });

  const vetoed = await decide("veto");
  assert.equal(vetoed.status, "refused"); assert.match(vetoed.reason, /vetoed/);
  assert.equal(g(work, "rev-parse", "main"), base); assert.equal(g(work, "branch", "--show-current"), "main");
  const vetoPersists = await decide("approve");
  assert.equal(vetoPersists.status, "refused"); assert.match(vetoPersists.reason, /veto is durable/);
  assert.equal(g(work, "branch", "--list", "keep/*"), "");

  app.identityRegistry.kill(DEFAULT_SOLVER_IDENTITY_ID, "operator stop");
  const killed = await decide("approve");
  assert.equal(killed.status, "refused"); assert.match(killed.reason, /kill switch|killed-identity/);
  assert.equal(g(work, "branch", "--list", "keep/*"), "", "kill refusal creates no candidate branch");
  const noMergeRevert = JSON.parse((await handleGatewayRequest(app, {
    method: "POST", path: "/project/revert", query: {}, headers: { authorization: "Bearer solve-token" },
    body: JSON.stringify({ runId }),
  }, { token: "solve-token" })).body) as { status: string; reason: string };
  assert.equal(noMergeRevert.status, "refused"); assert.match(noMergeRevert.reason, /no accepted local merge/);
});

test("SOLVE-01: the installed path rejects mutable revisions and workspace traversal before reading a repo", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-solve01-refuse-"));
  const source = join(root, "source");
  execFileSync("git", ["init", "-q", "-b", "main", source]);
  g(source, "config", "user.email", "keep@test"); g(source, "config", "user.name", "Keep");
  writeFileSync(join(source, "calc.js"), "export const value = 1;\n");
  g(source, "add", "-A"); g(source, "commit", "-qm", "base");
  const exact = { sourceDir: source, workspaceBase: join(root, "workspace-conflict"), repoRef: "project", commit: g(source, "rev-parse", "HEAD") };
  assert.throws(() => composeKeep({ dataDir: join(root, "state-conflict"), repositoryMaterialization: exact, workspace: new LocalFsWorkspace(root) }), /repositoryMaterialization is exclusive/);
  for (const [name, repoRef, commit, pattern] of [["mutable", "project", "main", /exact commit/], ["traversal", "../escape", g(source, "rev-parse", "HEAD"), /escapes/]] as const) {
    mkdirSync(join(root, `workspace-${name}`));
    const app = composeKeep({ dataDir: join(root, `state-${name}`), developmentProvider: new FixModel(), repositoryMaterialization: { sourceDir: source, workspaceBase: join(root, `workspace-${name}`), repoRef, commit } });
    const run = await app.autonomyLoop!.runProject("fix add in calc.js so it adds", { runId: `reject-${name}`, stepBudget: 50 });
    assert.equal(run.state.status, "waiting-reconciliation", "the untyped materializer exception cannot authorize blind replay; its stage remains resumable after observation");
    assert.equal(run.state.wait?.kind, "reconciliation");
    assert.equal(existsSync(join(root, `workspace-${name}`, "project", ".git")), false, "no repository was materialized");
    assert.match(run.state.note ?? "", pattern);
  }
});

test("STATE-01: installed boot refuses malformed record, wrapped-key, and session carriers", async () => {
  const interruptedDir = mkdtempSync(join(tmpdir(), "keep-state01-interrupted-"));
  let interruptedSolveCalls = 0;
  const interruptedConfig: Parameters<typeof composeKeep>[0] = {
    dataDir: interruptedDir,
    solve: async (issue) => { interruptedSolveCalls += 1; return { solveResult: { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0 } }; },
  };
  const interruptedFirst = composeKeep(interruptedConfig);
  const interruptedRecord = interruptedFirst.autonomyLoop!.manager.create({ name: "interrupted before preflight" });
  const interruptedReopened = composeKeep(interruptedConfig);
  const recoveredRecord = interruptedReopened.projectManager!.list().find((record) => record.id === interruptedRecord.id);
  assert.ok(recoveredRecord, "a crash before run binding preserves the durable project identity");
  const recoveredSession = interruptedReopened.projectManager!.session(interruptedRecord.id);
  assert.equal(recoveredSession.boundRunId(), undefined, "cold start never fabricates an execution identity or goal");
  assert.equal(recoveredSession.lastCheckpoint(), undefined, "cold start never fabricates progress that did not occur");
  assert.equal(interruptedSolveCalls, 0, "boot recovery never starts project work");

  const seed = async (name: string): Promise<{ dir: string; runId: string; config: Parameters<typeof composeKeep>[0] }> => {
    const dir = mkdtempSync(join(tmpdir(), `keep-state01-${name}-`));
    const config: Parameters<typeof composeKeep>[0] = {
      dataDir: dir,
      solve: async (issue) => ({ solveResult: {
        issueId: issue.id, solved: true, stagesRun: ["done"], repairRounds: 0,
        validation: { testsPassed: true, vettingCleared: true, failures: [], detail: "installed carrier seed" },
      } }),
    };
    const app = composeKeep(config);
    const response = await handleGatewayRequest(app, {
      method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer state-token" },
      body: JSON.stringify({ goal: `durable ${name} project` }),
    }, { token: "state-token" });
    assert.equal(response.status, 200);
    return { dir, runId: (JSON.parse(response.body) as { runId: string }).runId, config };
  };

  const records = await seed("records");
  writeFileSync(join(records.dir, "projects", "records.json"), "{}\n");
  assert.throws(() => composeKeep(records.config), /invalid project record store|must contain an array/);

  const keys = await seed("keys");
  writeFileSync(join(keys.dir, "projects", "wrapped-keys.json"), "{}\n");
  assert.throws(() => composeKeep(keys.config), /wrapped|key persistence|invalid/i);

  const session = await seed("session");
  const sessionApp = composeKeep(session.config);
  const sessionProject = sessionApp.projectManager!.list().find((record) => sessionApp.projectManager!.session(record.id).boundRunId() === session.runId);
  assert.ok(sessionProject);
  writeFileSync(join(session.dir, "projects", "sessions", `${sessionProject.id}.json`), "{}\n");
  const quarantined = composeKeep(session.config);
  assert.match(quarantined.projectManager!.quarantine(sessionProject.id) ?? "", /invalid project session store/,
    "one malformed session is quarantined without preventing unrelated projects from booting");
  assert.throws(() => quarantined.projectManager!.session(sessionProject.id), /quarantined.*invalid project session store/);
});
