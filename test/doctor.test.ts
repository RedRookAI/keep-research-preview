import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspectInstalledReadiness, renderDoctorReport } from "../src/cli/doctor.js";
import { gitChildHardening } from "../src/cli/runtime_config.js";

test("doctor inspects one captured project without provider calls or state creation", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-doctor-"));
  const repository = join(root, "source");
  const workspaceBase = join(root, "workspaces");
  const dataDir = join(root, "must-not-exist");
  const binDir = join(root, "bin");
  mkdirSync(repository); mkdirSync(workspaceBase); mkdirSync(binDir);
  const command = join(binDir, "real-test"); writeFileSync(command, "#!/bin/sh\nexit 0\n"); chmodSync(command, 0o700);
  const hardening = gitChildHardening(process.platform, process.env);
  execFileSync("git", [...hardening.configArgs, "init", "--quiet", "--initial-branch=main", repository], { env: hardening.env });
  execFileSync("git", [...hardening.configArgs, "-C", repository, "-c", "user.name=Keep Test", "-c", "user.email=keep@example.invalid", "commit", "--allow-empty", "-m", "base", "--quiet"], { env: hardening.env });
  const revision = execFileSync("git", [...hardening.configArgs, "-C", repository, "rev-parse", "HEAD"], { encoding: "utf8", env: hardening.env }).trim();
  try {
    let measurements = 0;
    const report = inspectInstalledReadiness({ KEEP_PROVIDER: "local", KEEP_REPOSITORY: repository, KEEP_WORKSPACE_BASE: workspaceBase, KEEP_REVISION: revision, KEEP_REPO_REF: "sample", KEEP_TEST_COMMAND: command, KEEP_DATA_DIR: dataDir }, { context: { cwd: root }, packageRoot: root, stdinIsTTY: true, measurePackage: () => { measurements++; return "a".repeat(64); } });
    assert.equal(report.ready, true, renderDoctorReport(report));
    assert.equal(measurements, 1);
    assert.equal(existsSync(dataDir), false, "doctor does not create KEEP_DATA_DIR");
    assert.match(renderDoctorReport(report), /READY:/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("doctor redacts credential values and refuses weak files or interactive stdin", () => {
  const revision = "a".repeat(40);
  const context = { cwd: "/", realpath: (path: string) => path, isDirectory: () => true, repositoryRoot: () => "/source", resolveCommit: () => revision, validateBranch: (_repository: string, branch: string) => branch, resolveBranchCommit: () => revision };
  const base = { KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://models.example.test", KEEP_PROVIDER_MODEL: "m", KEEP_REMOTE_PROCESSING_PURPOSE: "code", KEEP_REMOTE_PROCESSING_REGION: "eu", KEEP_RELEASE_BUNDLE: "/release.cbor", KEEP_REPOSITORY: "/source", KEEP_WORKSPACE_BASE: "/workspaces", KEEP_REVISION: revision, KEEP_REPO_REF: "sample", KEEP_TEST_COMMAND: "/bin/test" };
  const common = { context, packageRoot: "/package", measurePackage: () => "b".repeat(64), verifyRelease: () => undefined, pathEnv: "" };
  const stdin = inspectInstalledReadiness({ ...base, KEEP_PROVIDER_API_KEY_STDIN: "1" }, { ...common, stdinIsTTY: true });
  assert.equal(stdin.ready, false); assert.match(renderDoctorReport(stdin), /stdin is a terminal/u);
  const environment = inspectInstalledReadiness({ ...base, KEEP_PROVIDER_API_KEY: "never-render-this" }, { ...common, stdinIsTTY: false, stat: (() => ({ isFile: () => true, mode: 0o700 })) as never });
  assert.doesNotMatch(renderDoctorReport(environment), /never-render-this/u);
  const weakFile = inspectInstalledReadiness({ ...base, KEEP_PROVIDER_API_KEY_FILE: "/secret" }, { ...common, stdinIsTTY: false, stat: (() => ({ isFile: () => true, mode: 0o644 })) as never });
  assert.equal(weakFile.ready, false); assert.match(renderDoctorReport(weakFile), /group or other access/u);
});

test("doctor admits explicit owner external configuration without organization release infrastructure", () => {
  const revision = "a".repeat(40);
  const context = { cwd: "/", realpath: (path: string) => path, isDirectory: () => true, repositoryRoot: () => "/source", resolveCommit: () => revision, validateBranch: (_repository: string, branch: string) => branch, resolveBranchCommit: () => revision };
  const report = inspectInstalledReadiness({ KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_LOCATION: "external", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_BASE_URL: "https://models.example.test", KEEP_PROVIDER_MODEL: "m", KEEP_PROVIDER_API_KEY: "redacted", KEEP_REMOTE_PROCESSING_PURPOSE: "code", KEEP_REMOTE_PROCESSING_REGION: "eu", KEEP_REPOSITORY: "/source", KEEP_WORKSPACE_BASE: "/workspaces", KEEP_REVISION: revision, KEEP_REPO_REF: "sample", KEEP_TEST_COMMAND: "/bin/test" }, { context, packageRoot: "/package", stdinIsTTY: false, measurePackage: () => "c".repeat(64), pathEnv: "", stat: (() => ({ isFile: () => true, mode: 0o700 })) as never, verifyRelease: () => { throw new Error("organization release verifier must not run"); } });
  assert.equal(report.ready, true, renderDoctorReport(report));
  assert.match(renderDoctorReport(report), /owner\/external/u);
  assert.match(renderDoctorReport(report), /organization release signature not applicable/u);
});

test("compiled keep doctor fails before creating mutable product state", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-doctor-entry-"));
  const dataDir = join(root, "data");
  try {
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_")));
    const result = spawnSync(process.execPath, [join(process.cwd(), "dist", "src", "main.js"), "doctor"], { cwd: root, env: { ...inherited, KEEP_DATA_DIR: dataDir }, encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stdout, /missing-input\s+KEEP_PROVIDER/u);
    assert.equal(existsSync(dataDir), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
