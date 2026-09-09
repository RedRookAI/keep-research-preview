import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gitChildHardening } from "../src/cli/runtime_config.js";
import { materializeRepository, type MaterializationJournal, type MaterializationRecord } from "../src/git/repository_materializer.js";

test("installed help and version require no provider and create no product state", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-installed-static-"));
  const dataDir = join(root, "data");
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_")));
  try {
    for (const args of [["--version"], ["help"]]) {
      const result = spawnSync(process.execPath, [join(process.cwd(), "dist", "src", "main.js"), ...args], { cwd: root, encoding: "utf8", env: { ...inherited, KEEP_DATA_DIR: dataDir } });
      assert.equal(result.status, 0, result.stderr || result.stdout);
      assert.doesNotMatch(result.stderr, /KEEP_PROVIDER/u);
      assert.equal(existsSync(dataDir), false);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("CLI project retains held state and refuses restart authority for the opaque local fixture", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-installed-project-"));
  const repository = join(root, "source"), workspaceBase = join(root, "workspaces"), dataDir = join(root, "data");
  mkdirSync(repository); mkdirSync(workspaceBase); writeFileSync(join(repository, "README.md"), "original\n");
  const hardening = gitChildHardening(process.platform, process.env);
  const git = (args: readonly string[]) => execFileSync("git", [...hardening.configArgs, "-C", repository, ...args], { encoding: "utf8", env: hardening.env }).trim();
  git(["init", "--quiet", "--initial-branch=main"]); git(["add", "README.md"]); git(["-c", "user.name=Keep Test", "-c", "user.email=keep@example.invalid", "commit", "-m", "base", "--quiet"]);
  const revision = git(["rev-parse", "HEAD"]), sourceStatus = git(["status", "--porcelain=v1"]);
  try {
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_")));
    const result = spawnSync(process.execPath, [join(process.cwd(), "dist", "src", "main.js"), "project", "--posture=approval-required", "add a harmless marker file"], {
      cwd: root, encoding: "utf8", timeout: 30_000,
      env: { ...inherited, KEEP_PROVIDER: "local", KEEP_REPOSITORY: repository, KEEP_WORKSPACE_BASE: workspaceBase, KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.platform === "win32" ? "cmd.exe" : "/bin/true", KEEP_DATA_DIR: dataDir },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Run: [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/u);
    assert.match(result.stdout, /external effect must be reconciled/u);
    assert.match(result.stdout, /plan step implement authorizes no repository files/u);
    assert.doesNotMatch(result.stdout, /no solver configured|aren't available in this build/u);
    assert.equal(readFileSync(join(repository, "README.md"), "utf8"), "original\n");
    assert.equal(git(["status", "--porcelain=v1"]), sourceStatus);
    assert.equal(git(["rev-parse", "HEAD"]), revision);
    const runId = result.stdout.match(/Run: ([a-f0-9-]+)/u)?.[1];
    assert.ok(runId);
    const commandEnv = { ...inherited, KEEP_PROVIDER: "local", KEEP_REPOSITORY: repository, KEEP_WORKSPACE_BASE: workspaceBase, KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.platform === "win32" ? "cmd.exe" : "/bin/true", KEEP_DATA_DIR: dataDir };
    const listed = spawnSync(process.execPath, [join(process.cwd(), "dist", "src", "main.js"), "projects"], { cwd: root, encoding: "utf8", timeout: 30_000, env: commandEnv });
    assert.equal(listed.status, 0, listed.stderr || listed.stdout); assert.match(listed.stdout, new RegExp(runId)); assert.match(listed.stdout, new RegExp(`keep project resume ${runId}`));
    const checkpointDir = join(dataDir, "projects", "checkpoints");
    const checkpoints = () => readdirSync(checkpointDir).sort().map(name => [name, readFileSync(join(checkpointDir, name), "hex")]);
    const before = checkpoints();
    assert.ok(before.length > 0, "the held run must actually be persisted before testing restart");
    const resumed = spawnSync(process.execPath, [join(process.cwd(), "dist", "src", "main.js"), "project", "resume", runId], { cwd: root, encoding: "utf8", timeout: 30_000, env: commandEnv });
    // This prompt-echo fixture has no restart-stable provider descriptor. An
    // identical display name must not confer the original command's authority.
    // Positive configured-provider recovery has a separate installed journey in
    // acceptance/installed_sg31_context.mjs; this is the refusal control, not it.
    assert.equal(resumed.status, 1, resumed.stderr || resumed.stdout);
    assert.match(resumed.stdout, /status 409.*native project command unavailable: custody/u);
    assert.doesNotMatch(resumed.stdout, /materialization destination already exists/u);
    assert.deepEqual(checkpoints(), before, "failed custody must not advance or replace the unresolved run");
    assert.equal(readFileSync(join(repository, "README.md"), "utf8"), "original\n");
    assert.equal(existsSync(join(repository, "marker")), false);
    assert.equal(git(["status", "--porcelain=v1"]), sourceStatus);
    assert.equal(git(["rev-parse", "HEAD"]), revision);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("restart adoption requires sealed provenance and rejects symlink substitution", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-materialization-restart-"));
  const source = join(root, "source"), workspace = join(root, "workspace"); mkdirSync(source); mkdirSync(workspace);
  const hardening = gitChildHardening(process.platform, process.env);
  const git = (cwd: string, args: readonly string[]) => execFileSync("git", [...hardening.configArgs, "-C", cwd, ...args], { encoding: "utf8", env: hardening.env }).trim();
  git(source, ["init", "--quiet"]); git(source, ["-c", "user.name=Keep", "-c", "user.email=keep@example.invalid", "commit", "--allow-empty", "-m", "base", "--quiet"]); const revision = git(source, ["rev-parse", "HEAD"]);
  let sealed: MaterializationRecord | undefined;
  const journal: MaterializationJournal = { load: () => sealed, save: async (record) => { sealed = record; } };
  try {
    const request = { sourceDir: source, workspaceBase: workspace, repoRef: "project", commit: revision };
    await materializeRepository(request, undefined, journal);
    writeFileSync(join(workspace, "project", "proposal.txt"), "uncommitted proposal\n");
    const adopted = await materializeRepository(request, undefined, journal);
    assert.equal(adopted.commit, revision); assert.equal(readFileSync(join(adopted.projectDir, "proposal.txt"), "utf8"), "uncommitted proposal\n");
    await assert.rejects(() => materializeRepository({ ...request, baseBranch: "work/other" }, undefined, journal), /durable provenance/u);
    sealed = undefined;
    await assert.rejects(() => materializeRepository(request, undefined, journal), /durable provenance/u);
    const linkedWorkspace = join(root, "linked"); mkdirSync(linkedWorkspace); symlinkSync(source, join(linkedWorkspace, "project"), "dir");
    sealed = { sourceDir: source, workspaceBase: linkedWorkspace, repoRef: "project", commit: revision, baseBranch: "main" };
    await assert.rejects(() => materializeRepository({ ...request, workspaceBase: linkedWorkspace }, undefined, journal), /real directory/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
