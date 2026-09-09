import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { LocalFsWorkspace } from "../src/solve/workspace.js";
import { admitTenantDeployment, TenantDeploymentAdmissionError, type TenantDeploymentRoots } from "../src/team/tenant_deployment_admission.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSoloReleaseBaselineStore, captureCanonicalSoloObservation, captureInstalledPackageSubjectDigest, captureSoloReleaseBaseline, type SoloPerformanceObservation } from "../src/release/solo_non_regression.js";
import { materializeRepository } from "../src/git/repository_materializer.js";

function git(cwd: string, ...args: string[]): string { return execFileSync("git", args, { cwd, encoding: "utf8" }).trim(); }

function roots(tenantId: string): TenantDeploymentRoots {
  const base = mkdtempSync(join(tmpdir(), `keep-tenant-roots-${tenantId}-`));
  const dataRoot = join(base, "data"), repositoryRoot = join(base, "repository"), workspaceRoot = join(base, "workspace"), witnessRoot = join(base, "witness");
  mkdirSync(dataRoot); mkdirSync(repositoryRoot); mkdirSync(workspaceRoot); mkdirSync(witnessRoot);
  return { tenantId, dataRoot, repositoryRoot, workspaceRoot, witnessRoot };
}

const soloCurrent = (): SoloPerformanceObservation => ({ startupMs: 10, p95LatencyMs: 5 });
const soloNonRegression = (baselinePath: string) => {
  const current = soloCurrent();
  const baseline = captureSoloReleaseBaseline(captureCanonicalSoloObservation(current, captureInstalledPackageSubjectDigest(process.cwd())), { startupMs: 20, p95LatencyMs: 10 });
  new FileSoloReleaseBaselineStore(baselinePath).pin(baseline);
  return { baselinePath, current, baseline };
};

test("TEAM-02 deployment admission content-binds a complete disjoint roster independent of member order", () => {
  const a = roots("alpha"), b = roots("beta"), c = roots("gamma");
  const first = admitTenantDeployment(a, [c, b]);
  const second = admitTenantDeployment(b, [a, c]);
  assert.equal(first.rosterDigest, second.rosterDigest);
  assert.equal(first.peerCount, 2);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.roots), true);
});

test("TEAM-02 deployment admission rejects duplicate tenants and every own/cross-tenant nested root", () => {
  const a = roots("alpha"), b = roots("beta");
  const nested = join(a.dataRoot, "nested");
  mkdirSync(nested);
  assert.throws(() => admitTenantDeployment(a, [{ ...b, tenantId: "alpha" }]), /duplicate tenant/);
  assert.throws(() => admitTenantDeployment({ ...a, workspaceRoot: nested }, [b]), TenantDeploymentAdmissionError);
  assert.throws(() => admitTenantDeployment(a, [{ ...b, workspaceRoot: a.repositoryRoot }]), /overlaps tenant/);
  assert.throws(() => admitTenantDeployment(a, [{ ...b, witnessRoot: a.witnessRoot! }]), /witnessRoot overlaps tenant/u);
  assert.throws(() => admitTenantDeployment(a, []), /non-empty peer roster/);
  assert.throws(() => admitTenantDeployment({ ...a, tenantId: "keep.n1.default" }, [b]), /non-reserved/u);

  const base = mkdtempSync(join(tmpdir(), "keep-tenant-intervening-sibling-"));
  const alpha = join(base, "alpha"), alphaSibling = join(base, "alpha-2"), alphaChild = join(alpha, "workspace");
  const ownRepo = join(base, "own-repo"), ownWorkspace = join(base, "own-workspace"), peerRepo = join(base, "peer-repo");
  for (const path of [alpha, alphaSibling, alphaChild, ownRepo, ownWorkspace, peerRepo]) mkdirSync(path, { recursive: true });
  assert.throws(() => admitTenantDeployment(
    { tenantId: "owner", dataRoot: alpha, repositoryRoot: ownRepo, workspaceRoot: ownWorkspace },
    [{ tenantId: "peer", dataRoot: alphaSibling, repositoryRoot: peerRepo, workspaceRoot: alphaChild }],
  ), /overlaps tenant/u, "a lexical sibling cannot hide a descendant overlap");
});

test("TEAM-02 canonical composition consumes measured roots and exposes only its immutable admission receipt", () => {
  const a = roots("alpha"), b = roots("beta");
  const solo = soloNonRegression(join(a.dataRoot, "solo-baseline.json"));
  const app = composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: a.repositoryRoot, workspace: a.workspaceRoot },
    workspace: new LocalFsWorkspace(a.workspaceRoot),
    solve: async () => ({ solveResult: {} }) as never,
    tenantDeployment: { tenantId: a.tenantId, peers: [b], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  });
  assert.equal(app.tenantDeployment?.rootAdmission.tenantId, "alpha");
  assert.equal(app.tenantDeployment?.rootAdmission.peerCount, 1);
  assert.match(app.tenantDeployment?.rootAdmission.rosterDigest ?? "", /^[0-9a-f]{64}$/u);
  assert.equal(app.tenantDeployment?.soloBaselineDigest, solo.baseline.baselineDigest);

  assert.throws(() => composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: a.repositoryRoot, workspace: a.workspaceRoot },
    workspace: new LocalFsWorkspace(a.workspaceRoot),
    store: new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-hidden-state-"))),
    tenantDeployment: { tenantId: a.tenantId, peers: [b], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  }), /backing roots of custom state adapters/);
  assert.throws(() => composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: a.repositoryRoot, workspace: a.workspaceRoot },
    workspace: new LocalFsWorkspace(b.workspaceRoot),
    tenantDeployment: { tenantId: a.tenantId, peers: [b], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  }), /does not match the measured workspace/);
  assert.throws(() => composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: a.repositoryRoot, workspace: a.workspaceRoot },
    workspace: new LocalFsWorkspace(a.workspaceRoot),
    tenantDeployment: { tenantId: a.tenantId, peers: [b], soloNonRegression: { baselinePath: solo.baselinePath, current: { ...solo.current, startupMs: 21 } } },
  }), /regresses the pinned n=1 contract.*startup/u);

  const restarted = composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: a.repositoryRoot, workspace: a.workspaceRoot },
    workspace: new LocalFsWorkspace(a.workspaceRoot),
    solve: async () => ({ solveResult: {} }) as never,
    tenantDeployment: { tenantId: a.tenantId, peers: [b], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  });
  assert.equal(restarted.tenantDeployment?.rootAdmission.rosterDigest, app.tenantDeployment?.rootAdmission.rosterDigest);
  const admissions = restarted.spine.currentEvents().filter((event) => event.actor === "tenant-deployment" && event.payload.event === "tenant_deployment.admitted");
  assert.equal(admissions.length, 1, "restart reuses one durable admission rather than self-attesting repeatedly");

  const c = roots("gamma");
  assert.throws(() => composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: a.repositoryRoot, workspace: a.workspaceRoot },
    workspace: new LocalFsWorkspace(a.workspaceRoot),
    solve: async () => ({ solveResult: {} }) as never,
    tenantDeployment: { tenantId: a.tenantId, peers: [c], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  }), /conflicts with the durable roster/u);

  const beta = roots("replacement"), delta = roots("delta");
  assert.throws(() => composeKeep({
    dataDir: a.dataRoot,
    runtimePaths: { repository: beta.repositoryRoot, workspace: beta.workspaceRoot },
    workspace: new LocalFsWorkspace(beta.workspaceRoot),
    solve: async () => ({ solveResult: {} }) as never,
    tenantDeployment: { tenantId: beta.tenantId, peers: [delta], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  }), /conflicts with the durable roster/u, "a different tenant cannot adopt an already-admitted state root");
});

test("TEAM-02 enterprise composition reaches the exact-revision solver and governed merge through measured roots", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-tenant-repository-"));
  const dataRoot = join(base, "data"), repositoryRoot = join(base, "source"), workspaceBase = join(base, "workspaces");
  mkdirSync(dataRoot); mkdirSync(repositoryRoot); mkdirSync(workspaceBase);
  execFileSync("git", ["init", "-q", "-b", "main", repositoryRoot]);
  git(repositoryRoot, "config", "user.email", "keep@test"); git(repositoryRoot, "config", "user.name", "Keep");
  writeFileSync(join(repositoryRoot, "index.js"), "export const value = 1;\n");
  git(repositoryRoot, "add", "index.js"); git(repositoryRoot, "commit", "-qm", "base");
  const commit = git(repositoryRoot, "rev-parse", "HEAD"), repoRef = "project";
  const request = { sourceDir: repositoryRoot, workspaceBase, repoRef, commit };
  const materialized = await materializeRepository(request);
  const own: TenantDeploymentRoots = { tenantId: "enterprise", dataRoot, repositoryRoot, workspaceRoot: workspaceBase };
  const peer = roots("peer");
  const solo = soloNonRegression(join(dataRoot, "solo-baseline.json"));
  const config = {
    dataDir: dataRoot,
    runtimePaths: { repository: repositoryRoot, workspace: workspaceBase },
    workspace: new LocalFsWorkspace(workspaceBase),
    repositoryMaterialization: request,
    tenantDeployment: { tenantId: own.tenantId, peers: [peer], soloNonRegression: { baselinePath: solo.baselinePath, current: solo.current } },
  } as const;
  const app = composeKeep(config);
  assert.ok(app.autonomyLoop, "the built-in autonomous project consumer is retained in enterprise composition");
  assert.ok(app.projectMerge, "the governed merge consumer is retained in enterprise composition");
  assert.ok(app.frontDoor, "the non-engineer Front Door remains available in enterprise composition");
  const alphaDoor = app.frontDoorForSubject!("enterprise"), betaDoor = app.frontDoorForSubject!("peer");
  assert.notEqual(alphaDoor, betaDoor, "enterprise tenants never share conversational state");
  alphaDoor.greeting(); await alphaDoor.converse("Alice");
  assert.equal(betaDoor.context().humanName, undefined, "one tenant's onboarding state cannot enter another tenant's Front Door");

  git(materialized.projectDir, "config", "user.email", "keep@test"); git(materialized.projectDir, "config", "user.name", "Keep");
  writeFileSync(join(materialized.projectDir, "index.js"), "export const value = 2;\n");
  git(materialized.projectDir, "add", "index.js"); git(materialized.projectDir, "commit", "-qm", "unexpected head");
  assert.throws(() => composeKeep(config), /does not contain the exact admitted repository revision/u);
});
