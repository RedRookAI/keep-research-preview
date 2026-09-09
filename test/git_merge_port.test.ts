import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { GitAdapter } from "../src/infra/git_adapter.js";
import { GitMergePort, type GitMergePortOptions } from "../src/git/git_merge_port.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../src/infra/microvm_boundary.js";
import { AutonomousMergeExecutor, consumePreparedPublicationAuthority, makePublicationAttempt, publicationAttemptDigest, sealPreparedPublication, type MergeSpec, type PublicationAttemptV1 } from "../src/oversight/merge_executor.js";
import type { MergeAuthorityDecision } from "../src/oversight/merge_authority.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";

function g(cwd: string, ...args: string[]): string { return execFileSync("git", args, { cwd }).toString(); }
function gitSubcommand(args: readonly string[]): string | undefined {
  let index = 0;
  while (args[index] === "-c") index += 2;
  return args[index];
}

class PushAcknowledgementFaultGitAdapter extends GitAdapter {
  private pushCompleted = false;
  constructor(cwd: string, private readonly loseReconciliation: boolean) { super(cwd); }
  override async git(args: readonly string[]) {
    if (gitSubcommand(args) === "push" && args.includes("--atomic") && !this.pushCompleted) {
      await super.git(args);
      this.pushCompleted = true;
      throw new Error("simulated lost push acknowledgement");
    }
    if (this.pushCompleted && this.loseReconciliation && gitSubcommand(args) === "ls-remote") {
      throw new Error("simulated reconciliation outage");
    }
    return super.git(args);
  }
}

class PreEffectPushFaultGitAdapter extends GitAdapter {
  override async git(args: readonly string[]) {
    if (gitSubcommand(args) === "push" && args.includes("--atomic")) throw new Error("simulated transport failure before delivery");
    return super.git(args);
  }
}

class RemoteMovesAfterPreflightGitAdapter extends GitAdapter {
  private observations = 0;
  constructor(cwd: string, private readonly move: () => void) { super(cwd); }
  override async git(args: readonly string[]) {
    if (gitSubcommand(args) === "ls-remote" && ++this.observations === 2) this.move();
    return super.git(args);
  }
}

class PostMergeAppraisalFaultGitAdapter extends GitAdapter {
  private treeReads = 0;
  override async git(args: readonly string[]) {
    if (args[0] === "ls-tree" && ++this.treeReads === 3) throw new Error("simulated post-merge object appraisal failure");
    return super.git(args);
  }
}

/** A real repo on `main` with `file.txt`, plus a `keep/solve/X` branch that changes it. */
function repo(featureContent: string, baseContent = "base\n", file = "file.txt"): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-gmp-"));
  g(dir, "init", "-q", "-b", "main");
  g(dir, "config", "user.email", "keep@test"); g(dir, "config", "user.name", "keep");
  mkdirSync(dirname(join(dir, file)), { recursive: true });
  writeFileSync(join(dir, file), baseContent);
  g(dir, "add", "-A"); g(dir, "commit", "-q", "-m", "base");
  g(dir, "checkout", "-q", "-b", "keep/solve/X");
  writeFileSync(join(dir, file), featureContent);
  g(dir, "add", "-A"); g(dir, "commit", "-q", "-m", "feature");
  return dir;
}
function bareRemoteFor(dir: string): string {
  const remote = mkdtempSync(join(tmpdir(), "keep-gmp-remote-"));
  g(remote, "init", "-q", "--bare");
  g(dir, "remote", "add", "test-origin", `file://${remote}`);
  g(dir, "push", "-q", "test-origin", "main:main");
  return remote;
}
function durableSpine(dataDir: string): Spine {
  return new Spine(new FileSpineStore(dataDir, { fsync: true }), new InProcessLock(), new SchemaRegistry());
}
function mergePort(git: GitAdapter, opts: GitMergePortOptions = {}): GitMergePort {
  let url: string | undefined;
  if (opts.pushRemote && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(opts.pushRemote)) {
    try { url = g(git.workingDirectory(), "remote", "get-url", "--push", opts.pushRemote).trim(); } catch { /* refusal test */ }
  }
  const pushPin = opts.expectedPushUrlSha256 ?? (url ? pinnedRemoteUrlSha256(url) : undefined);
  const fetchPin = opts.expectedFetchUrlSha256 ?? (url ? pinnedRemoteFetchUrlSha256(url) : undefined);
  return new GitMergePort(git, { ...opts, ...(fetchPin ? { expectedFetchUrlSha256: fetchPin } : {}), ...(pushPin ? { expectedPushUrlSha256: pushPin } : {}), publicationSpine: opts.publicationSpine ?? durableSpine(mkdtempSync(join(tmpdir(), "keep-gmp-port-spine-"))) });
}
async function sealPublicationAttempt(spine: Spine, attempt: PublicationAttemptV1) {
  return sealPreparedPublication(spine, attempt);
}
async function mergeSpec(dir: string): Promise<MergeSpec> {
  return {
    issueId: "X",
    repoRef: dir,
    branch: "keep/solve/X",
    baseBranch: "main",
    expectedCandidateCommit: g(dir, "rev-parse", "keep/solve/X").trim(),
    expectedCandidateProjectManifestDigest: await computeMicrovmProjectSourceManifestSha256(dir),
    expectedGuestExecutionRequestDigest: "c".repeat(64),
    projectDir: dir,
  };
}

test("AM2b: a clean branch MERGES into base and the change is really on disk on main", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true, "dry-run sees a clean merge");
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, true);
  assert.equal(out.identity?.candidateCommit, spec.expectedCandidateCommit);
  assert.equal(out.identity?.candidateProjectManifestDigest, spec.expectedCandidateProjectManifestDigest);
  assert.equal(out.identity?.publishedProjectManifestDigest, await computeMicrovmProjectSourceManifestSha256(dir));
  assert.equal((await port.confirmPublished(out.identity!, spec)).current, true);
  assert.ok(out.mergeId.length > 0, "the merge commit is the rollback id");
  assert.equal(g(dir, "rev-parse", "--abbrev-ref", "HEAD").trim(), "main", "we are on base");
  assert.equal(readFileSync(join(dir, "file.txt"), "utf8"), "fixed\n", "the change landed on main");
});

test("AM2b: revert(-m 1) really UNDOES the merge — base returns to its pre-merge content", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(readFileSync(join(dir, "file.txt"), "utf8"), "fixed\n");
  const rev = await port.revert(out.mergeId, spec);
  assert.equal(rev.reverted, true);
  assert.equal(readFileSync(join(dir, "file.txt"), "utf8"), "base\n", "revert restored the pre-merge content on main");
  const replay = await port.revert(out.mergeId, spec);
  assert.equal(replay.reverted, true, replay.reason);
  assert.equal(replay.revertCommit, rev.revertCommit, "replay observes the exact prior compensation commit");
});

test("AM2b: a CONFLICTING branch is detected by dry-run WITHOUT touching the working tree", async () => {
  // base changes file.txt to "base-edited" on main after the feature branched → conflict.
  const dir = repo("feature-edit\n");
  g(dir, "checkout", "-q", "main");
  writeFileSync(join(dir, "file.txt"), "main-edit\n");
  g(dir, "add", "-A"); g(dir, "commit", "-q", "-m", "divergent main");
  g(dir, "checkout", "-q", "keep/solve/X");
  const port = mergePort(new GitAdapter(dir));
  const before = readFileSync(join(dir, "file.txt"), "utf8");
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, false, "conflict detected");
  assert.equal(readFileSync(join(dir, "file.txt"), "utf8"), before, "dry-run left the working tree untouched");
  assert.equal(g(dir, "status", "--porcelain").trim(), "", "no partial merge state left behind");
});

test("AM2b IDENTITY: candidate-commit substitution is refused before checkout or merge", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun({ ...spec, expectedCandidateCommit: "0".repeat(40) });
  assert.equal(dry.clean, false);
  assert.equal(g(dir, "rev-parse", "--abbrev-ref", "HEAD").trim(), "keep/solve/X");
});

test("AM2b IDENTITY: uncommitted or untracked bytes make the tested subject non-publishable", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  writeFileSync(join(dir, "untracked.txt"), "not in candidate commit\n");
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /changed, untracked, or unadmitted ignored/);
});

test("AM2b TREE IDENTITY: an ignored source file used by the tested workspace is refused", async () => {
  const dir = repo("fixed\n");
  writeFileSync(join(dir, ".gitignore"), "src/shim.ts\n");
  g(dir, "add", ".gitignore"); g(dir, "commit", "-q", "-m", "ignore shim");
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src/shim.ts"), "throw new Error('executed but unpublished');\n");
  const spec = await mergeSpec(dir);
  const dry = await mergePort(new GitAdapter(dir)).dryRun(spec);
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /unadmitted ignored bytes outside the Git tree/);
});

test("AM2b COMPOSITE SUBJECT: an explicitly admitted dependency root is measured but not mistaken for published source", async () => {
  const dir = repo("fixed\n");
  writeFileSync(join(dir, ".gitignore"), "node_modules/\n");
  g(dir, "add", ".gitignore"); g(dir, "commit", "-q", "-m", "declare dependency root");
  mkdirSync(join(dir, "node_modules/pkg"), { recursive: true });
  writeFileSync(join(dir, "node_modules/pkg/index.js"), "module.exports = 1;\n");
  const spec = { ...(await mergeSpec(dir)), executionAuxiliaryRoots: ["node_modules"] };
  const port = mergePort(new GitAdapter(dir));
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true, dry.reason);
  writeFileSync(join(dir, "node_modules/pkg/index.js"), "module.exports = 2;\n");
  const moved = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(moved.merged, false);
  assert.match(moved.reason ?? "", /candidate identity moved/);
});

test("AM2b CONTROL PLANE: a clean filter is refused before its command can execute", async () => {
  const dir = repo("fixed\n");
  const sentinel = join(dir, "filter-command-ran");
  g(dir, "config", "filter.keep-rewrite.clean", `sh -c 'touch ${sentinel}; sed s/fixed/published/'`);
  g(dir, "config", "filter.keep-rewrite.smudge", "cat");
  writeFileSync(join(dir, ".gitattributes"), "file.txt filter=keep-rewrite\n");
  g(dir, "add", ".gitattributes", "file.txt"); g(dir, "commit", "-q", "-m", "filtered candidate");
  if (existsSync(sentinel)) unlinkSync(sentinel);
  const spec = await mergeSpec(dir);
  const dry = await mergePort(new GitAdapter(dir)).dryRun(spec);
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /configuration key is not allowlisted/);
  assert.equal(existsSync(sentinel), false, "the configured process never executes during appraisal");
});

test("AM2b CONTROL PLANE: canonical Git LFS attributes remain usable under the closed Git child", async () => {
  const dir = repo("fixed\n");
  writeFileSync(join(dir, ".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n");
  g(dir, "add", ".gitattributes"); g(dir, "commit", "-q", "-m", "declare standard LFS data");
  const spec = await mergeSpec(dir);
  const dry = await mergePort(new GitAdapter(dir)).dryRun(spec);
  assert.equal(dry.clean, true, dry.reason);
});

test("AM2b CONTROL PLANE: an LFS declaration cannot carry an additional custom driver", async () => {
  const dir = repo("fixed\n");
  writeFileSync(join(dir, ".gitattributes"), "*.bin filter=lfs diff=hostile merge=lfs -text\n");
  g(dir, "add", ".gitattributes"); g(dir, "commit", "-q", "-m", "mixed attributes");
  const dry = await mergePort(new GitAdapter(dir)).dryRun(await mergeSpec(dir));
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /byte-transformation control is forbidden/u);
});

test("AM2b CONTROL PLANE: repository hooks cannot execute during the merge ceremony", async () => {
  const dir = repo("fixed\n");
  const sentinel = join(dir, "hook-ran");
  const hook = join(dir, ".git/hooks/post-merge");
  writeFileSync(hook, `#!/bin/sh\ntouch '${sentinel}'\n`);
  chmodSync(hook, 0o755);
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true);
  assert.equal((await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt))).merged, true);
  assert.equal(existsSync(sentinel), false, "closed Git invocation suppressed repository hooks");
});

test("AM2b CONTROL PLANE: dormant worktree config and info attributes are refused before publication", async () => {
  for (const carrier of ["config.worktree", "info/attributes"] as const) {
    const dir = repo("fixed\n");
    const path = join(dir, ".git", carrier);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, carrier === "config.worktree" ? "[core]\n\thooksPath = /tmp/hostile\n" : "* filter=hostile\n");
    const dry = await mergePort(new GitAdapter(dir)).dryRun(await mergeSpec(dir));
    assert.equal(dry.clean, false);
    assert.match(dry.reason ?? "", /worktree configuration carrier|info\/attributes policy/);
  }
});

test("AM2b CONTROL PLANE: an untracked byte-transforming attributes carrier is appraised", async () => {
  const dir = repo("fixed\n");
  writeFileSync(join(dir, ".gitattributes"), "file.txt working-tree-encoding=UTF-16\n");
  const dry = await mergePort(new GitAdapter(dir)).dryRun(await mergeSpec(dir));
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /byte-transformation control is forbidden/);
});

test("AM2b SCOPE: a strict project subdirectory cannot stand in for the published worktree", async () => {
  const dir = repo("fixed\n", "base\n", "package/file.txt");
  const projectDir = join(dir, "package");
  const spec = { ...(await mergeSpec(dir)), projectDir, expectedCandidateProjectManifestDigest: await computeMicrovmProjectSourceManifestSha256(projectDir) };
  const dry = await mergePort(new GitAdapter(dir)).dryRun(spec);
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /must equal the complete Git worktree root/);
});

test("AM2b MANIFEST: root Git control data is excluded while source-byte changes move identity", async () => {
  const dir = repo("fixed\n");
  const before = await computeMicrovmProjectSourceManifestSha256(dir);
  writeFileSync(join(dir, ".git", "keep-test-control"), "mutable ref-like data\n");
  assert.equal(await computeMicrovmProjectSourceManifestSha256(dir), before, "root Git control data is not guest/source identity");
  writeFileSync(join(dir, "file.txt"), "different source bytes\n");
  assert.notEqual(await computeMicrovmProjectSourceManifestSha256(dir), before, "source bytes remain load-bearing");
});

test("AM2b MANIFEST: repository measurement has explicit resource bounds", async () => {
  const dir = repo("fixed\n");
  writeFileSync(join(dir, "second.txt"), "second\n");
  await assert.rejects(() => computeMicrovmProjectSourceManifestSha256(dir, { maxRows: 1 }), /(?:row|directory entry) count exceeds policy/);
  await assert.rejects(() => computeMicrovmProjectSourceManifestSha256(dir, { maxTotalFileBytes: 1 }), /file bytes exceed policy/);
  await assert.rejects(() => computeMicrovmProjectSourceManifestSha256(dir, { maxPathBytes: 1 }), /path exceeds policy/);
  await assert.rejects(() => computeMicrovmProjectSourceManifestSha256(dir, { maxManifestBytes: 32 }), /canonical bytes exceed policy/);
  await assert.rejects(() => computeMicrovmProjectSourceManifestSha256(dir, { maxDepth: 0 }), /positive safe integer/);
  const fanout = join(dir, "fanout"); mkdirSync(fanout);
  for (const name of ["a", "b", "c", "d"]) mkdirSync(join(fanout, name));
  await assert.rejects(() => computeMicrovmProjectSourceManifestSha256(dir, { maxRows: 3 }), /directory entry count exceeds policy/);
});

test("AM2b IDENTITY: base movement after preflight is refused without merging", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true);
  g(dir, "checkout", "-q", "main");
  writeFileSync(join(dir, "base-moved.txt"), "new base\n");
  g(dir, "add", "-A"); g(dir, "commit", "-q", "-m", "move base");
  g(dir, "checkout", "-q", "keep/solve/X");
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, false);
  assert.match(out.reason ?? "", /base or candidate moved/);
});

test("AM2b IDENTITY: a substituted preflight merge tree is independently recomputed and refused", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const out = await port.merge(spec, { ...dry.identity!, expectedMergedTree: "0".repeat(40) }, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, false);
  assert.match(out.reason ?? "", /moved after preflight/);
});

test("AM2b COMPENSATION: every post-mutation appraisal failure reverts the local merge and preserves its handle", async () => {
  const dir = repo("fixed\n");
  const before = g(dir, "rev-parse", "main").trim();
  const port = mergePort(new PostMergeAppraisalFaultGitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, false);
  assert.ok(out.mergeId, "the mutated merge remains named even after compensation");
  assert.equal(out.rollbackFailed, undefined);
  assert.match(out.reason ?? "", /post-merge identity appraisal failed.*local merge was reverted/);
  assert.equal(readFileSync(join(dir, "file.txt"), "utf8"), "base\n");
  assert.equal(g(dir, "rev-parse", "HEAD^").trim(), out.mergeId, "the history-preserving revert names the exact merge");
  assert.equal(g(dir, "rev-parse", `${out.mergeId}^1`).trim(), before);
});

test("AM2b COMPENSATION CONTROL PLANE: hostile drivers introduced after merge fail-stop before revert", async () => {
  const dir = repo("fixed\n");
  const sentinel = join(dir, "compensation-driver-ran");
  class CompensationControlRaceAdapter extends GitAdapter {
    private treeReads = 0;
    override async git(args: readonly string[]) {
      if (gitSubcommand(args) === "ls-tree" && ++this.treeReads === 3) {
        g(dir, "config", "filter.compensation.smudge", `sh -c 'touch ${sentinel}; cat'`);
        throw new Error("force compensation after hostile control-plane insertion");
      }
      return super.git(args);
    }
  }
  const port = mergePort(new CompensationControlRaceAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const outcome = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(outcome.merged, false);
  assert.equal(outcome.rollbackFailed, true, "unsafe compensation is held instead of executing through hostile Git configuration");
  assert.equal(existsSync(sentinel), false);
  assert.equal(g(dir, "rev-parse", "HEAD").trim(), outcome.mergeId, "the exact merge remains named for safe recovery");
});

test("AM2c RECONCILIATION CONTROL PLANE: direct residue recovery re-appraises before reset", async () => {
  const dir = repo("fixed\n");
  const sentinel = join(dir, "reconcile-driver-ran");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const outcome = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(outcome.merged, true);
  g(dir, "config", "filter.reconcile.smudge", `sh -c 'touch ${sentinel}; cat'`);
  const reconciled = await port.reconcileAbsentPublication(makePublicationAttempt(spec, outcome.identity!));
  assert.equal(reconciled.reconciled, false);
  assert.match(reconciled.reason, /not allowlisted/);
  assert.equal(existsSync(sentinel), false);
  assert.equal(g(dir, "rev-parse", "HEAD").trim(), outcome.mergeId, "recovery leaves the exact merge untouched on policy refusal");
});

test("AM2b PUBLICATION: exact merge commit is published and re-observed on a real bare remote", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, true);
  assert.equal(g(remote, "rev-parse", "refs/heads/main").trim(), out.mergeId);
  assert.equal((await port.confirmPublished(out.identity!, spec)).current, true);
});

test("AM2b PUBLICATION: a remote base that differs from the appraised local base refuses before merge", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const other = mkdtempSync(join(tmpdir(), "keep-gmp-other-"));
  g(other, "clone", "-q", "-b", "main", remote, ".");
  g(other, "config", "user.email", "keep@test"); g(other, "config", "user.name", "keep");
  writeFileSync(join(other, "remote-move.txt"), "move\n");
  g(other, "add", "-A"); g(other, "commit", "-q", "-m", "remote move"); g(other, "push", "-q", "origin", "HEAD:main");
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin" });
  const dry = await port.dryRun(await mergeSpec(dir));
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /remote base ref/);
  assert.equal(g(dir, "rev-parse", "--abbrev-ref", "HEAD").trim(), "keep/solve/X");
});

test("AM2b PUBLICATION CAS: remote movement after preflight is refused before the local merge", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const original = g(dir, "rev-parse", "main").trim();
  const other = g(dir, "commit-tree", `${original}^{tree}`, "-p", original, "-m", "concurrent remote writer").trim();
  g(dir, "push", "-q", "test-origin", `${other}:refs/heads/concurrent-writer`);
  const adapter = new RemoteMovesAfterPreflightGitAdapter(dir, () => {
    execFileSync("git", ["--git-dir", remote, "update-ref", "refs/heads/main", other]);
  });
  const port = mergePort(adapter, { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, false);
  assert.equal(g(dir, "rev-parse", "--abbrev-ref", "HEAD").trim(), "main", "checkout may occur but no merge commit is created");
  assert.equal(g(dir, "rev-parse", "HEAD").trim(), original);
  assert.match(out.reason ?? "", /base or candidate moved/);
});

test("AM2b PUBLICATION: an option-like remote operand is refused without invocation", async () => {
  const dir = repo("fixed\n");
  const spec = await mergeSpec(dir);
  const dry = await mergePort(new GitAdapter(dir), { pushRemote: "--receive-pack=evil" }).dryRun(spec);
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /canonical configured-remote name/);
});

test("AM2b PUBLICATION: Git remote-helper and path transports are refused; only configured remote names are accepted", async () => {
  const dir = repo("fixed\n");
  const spec = await mergeSpec(dir);
  for (const remote of ["ext::sh -c touch /tmp/keep-pwned", "/tmp/repository.git", "https://example.invalid/repo.git"]) {
    const dry = await mergePort(new GitAdapter(dir), { pushRemote: remote }).dryRun(spec);
    assert.equal(dry.clean, false);
    assert.match(dry.reason ?? "", /canonical configured-remote name/);
  }
});

test("AM2b PUBLICATION: repository-local URL rewriting cannot redirect a configured remote", async () => {
  const dir = repo("fixed\n");
  bareRemoteFor(dir);
  const spine = durableSpine(mkdtempSync(join(tmpdir(), "keep-url-rewrite-spine-")));
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin", publicationSpine: spine });
  const candidate = await mergeSpec(dir);
  const dry = await port.dryRun(candidate);
  g(dir, "config", "--local", "url.file:///tmp/hostile/.pushInsteadOf", "file://");
  const result = await port.merge(candidate, dry.identity!, async (attempt) => sealPublicationAttempt(spine, attempt));
  assert.equal(result.merged, false);
  assert.match(result.reason ?? "", /configuration key is not allowlisted/);
});

test("AM2b PUBLICATION: repository transport cannot substitute the operator-owned URL pin", async () => {
  const dir = repo("fixed\n"); bareRemoteFor(dir);
  const dry = await mergePort(new GitAdapter(dir), { pushRemote: "test-origin", expectedPushUrlSha256: "0".repeat(64) }).dryRun(await mergeSpec(dir));
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /operator-pinned transport/);
});

test("AM2b PUBLICATION: multiple fetch or push URLs are refused before any observation or effect", async () => {
  const dir = repo("fixed\n");
  const approved = bareRemoteFor(dir);
  const attacker = join(mkdtempSync(join(tmpdir(), "keep-multi-remote-")), "attacker.git");
  execFileSync("git", ["init", "-q", "--bare", attacker]);
  const approvedUrl = `file://${approved}`;
  const opts = {
    pushRemote: "test-origin",
    expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(approvedUrl),
    expectedPushUrlSha256: pinnedRemoteUrlSha256(approvedUrl),
  } as const;
  g(dir, "config", "--add", "remote.test-origin.url", `file://${attacker}`);
  let dry = await mergePort(new GitAdapter(dir), opts).dryRun(await mergeSpec(dir));
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /one exact fetch URL/);
  g(dir, "config", "--unset-all", "remote.test-origin.url");
  g(dir, "config", "remote.test-origin.url", approvedUrl);
  g(dir, "config", "remote.test-origin.pushurl", approvedUrl);
  g(dir, "config", "--add", "remote.test-origin.pushurl", `file://${attacker}`);
  dry = await mergePort(new GitAdapter(dir), opts).dryRun(await mergeSpec(dir));
  assert.equal(dry.clean, false);
  assert.match(dry.reason ?? "", /one exact push URL/);
  assert.throws(() => g(attacker, "show-ref"), /Command failed/);
});

test("AM2b PUBLICATION RACE: a repository pushurl rewrite cannot redirect the pinned observation or effect", async () => {
  const dir = repo("fixed\n");
  const approved = bareRemoteFor(dir);
  const attacker = join(mkdtempSync(join(tmpdir(), "keep-hostile-remote-")), "attacker.git");
  execFileSync("git", ["init", "-q", "--bare", attacker]);
  const before = g(dir, "rev-parse", "main").trim();
  g(dir, "push", `file://${attacker}`, "main:main");
  const approvedUrl = g(dir, "remote", "get-url", "--push", "test-origin").trim();
  class RacingRemoteConfigAdapter extends GitAdapter {
    override async git(args: readonly string[]) {
      const command = gitSubcommand(args);
      if (command === "ls-remote" || (command === "push" && args.includes("--atomic"))) {
        g(dir, "config", "remote.test-origin.pushurl", `file://${attacker}`);
        try { return await super.git(args); }
        finally { g(dir, "config", "remote.test-origin.pushurl", approvedUrl); }
      }
      return super.git(args);
    }
  }
  const port = mergePort(new RacingRemoteConfigAdapter(dir), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  assert.equal(dry.clean, true, dry.reason);
  const outcome = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(outcome.merged, true, outcome.reason);
  assert.equal(g(approved, "rev-parse", "refs/heads/main").trim(), outcome.mergeId);
  assert.equal(g(attacker, "rev-parse", "refs/heads/main").trim(), before, "attacker remote remains at the seeded lease value and receives no publication");
});

test("AM2b REVERT: a detached or substituted base cannot redirect the compensating publication", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  g(dir, "checkout", "-q", "--detach", out.mergeId);
  const rev = await port.revert(out.mergeId, spec);
  assert.equal(rev.reverted, false);
  assert.match(rev.reason ?? "", /checked-out branch/);
  assert.equal(g(dir, "rev-parse", "HEAD").trim(), out.mergeId);
});

test("AM2b DELIVERY: lost push acknowledgement is reconciled as success when the exact remote commit is observed", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const port = mergePort(new PushAcknowledgementFaultGitAdapter(dir, false), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, true);
  assert.equal(out.uncertainPublication, undefined);
  assert.equal(g(remote, "rev-parse", "refs/heads/main").trim(), out.mergeId);
});

test("AM2b DELIVERY: lost acknowledgement plus unavailable reconciliation is uncertain and never locally reverted", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const port = mergePort(new PushAcknowledgementFaultGitAdapter(dir, true), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const out = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(out.merged, false);
  assert.ok(out.uncertainPublication);
  assert.equal(g(dir, "rev-parse", "HEAD").trim(), out.mergeId, "local merge is preserved for reconciliation, not falsely reverted");
  assert.equal(g(remote, "rev-parse", "refs/heads/main").trim(), out.mergeId, "the simulated remote effect really happened");
});

test("AM2c TERMINAL INPUT: proven-absent post-prepare transport failure is explicitly marked compensated", async () => {
  const dir = repo("fixed\n");
  bareRemoteFor(dir);
  const port = mergePort(new PreEffectPushFaultGitAdapter(dir), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const outcome = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  assert.equal(outcome.merged, false);
  assert.equal(outcome.compensatedPublicationAbsent, true);
  assert.match(outcome.reason ?? "", /observed unchanged.*local merge was reverted/);
});

test("AM2c OBSERVATION: a deleted authoritative ref is a structural conflict, not an outage", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const delivered = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  execFileSync("git", ["--git-dir", remote, "update-ref", "-d", "refs/heads/main"]);
  const observation = await port.observePublication(makePublicationAttempt(spec, delivered.identity!));
  assert.equal(observation.status, "conflict");
  assert.match(observation.reason, /absent/);
});

test("AM2c OBSERVATION: configured-remote rebinding cannot reinterpret a sealed publication target", async () => {
  const dir = repo("fixed\n");
  bareRemoteFor(dir);
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin" });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const delivered = await port.merge(spec, dry.identity!, (attempt) => port.preparePublication(attempt));
  const other = join(mkdtempSync(join(tmpdir(), "keep-other-remote-")), "other.git");
  execFileSync("git", ["init", "-q", "--bare", other]);
  g(dir, "config", "remote.test-origin.url", other);
  const observation = await port.observePublication(makePublicationAttempt(spec, delivered.identity!));
  assert.equal(observation.status, "conflict");
  assert.match(observation.reason, /transport identity|not explicitly permitted/);
});

test("AM2c WAL: the exact attempted commit is durably sealed before the remote push is invoked", async () => {
  const dir = repo("fixed\n");
  bareRemoteFor(dir);
  const dataDir = mkdtempSync(join(tmpdir(), "keep-am2c-spine-"));
  const spine = durableSpine(dataDir);
  class OrderingAdapter extends GitAdapter {
    override async git(args: readonly string[]) {
      if (gitSubcommand(args) === "push" && args.includes("--atomic")) {
        const prepared = spine.replay().find((event) => event.type === "effect.intent" && event.payload.kind === "auto_merge.publication_prepared");
        assert.ok(prepared, "remote push cannot begin before exact preparation is sealed");
        assert.equal((prepared.payload.attempt as PublicationAttemptV1).attemptedCommit, await this.head());
      }
      return super.git(args);
    }
  }
  const port = mergePort(new OrderingAdapter(dir), { pushRemote: "test-origin", publicationSpine: spine });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const result = await port.merge(spec, dry.identity!, async (attempt) => sealPublicationAttempt(spine, attempt));
  assert.equal(result.merged, true);
});

test("AM2c WAL AUTHORITY: a structural imitation cannot authorize publication", async () => {
  const dir = repo("fixed\n");
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const result = await port.merge(spec, dry.identity!, async () => ({ kind: "keep.prepared-publication-authority/v1" } as never));
  assert.equal(result.merged, false);
  assert.match(result.reason ?? "", /authority is absent, forged, replayed/);
  assert.equal(g(dir, "show", "main:file.txt"), "base\n", "forged preparation authority cannot move the publication target");
});

test("AM2c WAL AUTHORITY: a consumed preparation authority cannot be replayed", async () => {
  const dir = repo("fixed\n");
  const spine = durableSpine(mkdtempSync(join(tmpdir(), "keep-gmp-replayed-preparation-")));
  const port = mergePort(new GitAdapter(dir), { publicationSpine: spine });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const result = await port.merge(spec, dry.identity!, async (attempt) => {
    const authority = await sealPreparedPublication(spine, attempt);
    assert.equal(consumePreparedPublicationAuthority(authority, attempt, spine), true, "control consumption succeeds once");
    return authority;
  });
  assert.equal(result.merged, false);
  assert.match(result.reason ?? "", /authority is absent, forged, replayed/);
  assert.equal(g(dir, "show", "main:file.txt"), "base\n", "replayed preparation authority cannot move the publication target");
});

test("AM2c WAL AUTHORITY: preparation for different semantic bytes cannot be substituted", async () => {
  const dir = repo("fixed\n");
  const spine = durableSpine(mkdtempSync(join(tmpdir(), "keep-gmp-substituted-preparation-")));
  const port = mergePort(new GitAdapter(dir), { publicationSpine: spine });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const result = await port.merge(spec, dry.identity!, async (attempt) => {
    const other = makePublicationAttempt({ ...attempt.spec, issueId: "different-operation" }, attempt.identity);
    return sealPreparedPublication(spine, other);
  });
  assert.equal(result.merged, false);
  assert.match(result.reason ?? "", /authority is absent, forged, replayed, or bound to different bytes/);
  assert.equal(g(dir, "show", "main:file.txt"), "base\n", "cross-attempt preparation authority cannot move the publication target");
});

test("AM2c WAL AUTHORITY: a valid receipt from a sacrificial durable Spine cannot authorize the canonical actuator", async () => {
  const dir = repo("fixed\n");
  const canonical = durableSpine(mkdtempSync(join(tmpdir(), "keep-gmp-canonical-preparation-")));
  const sacrificial = durableSpine(mkdtempSync(join(tmpdir(), "keep-gmp-sacrificial-preparation-")));
  const port = mergePort(new GitAdapter(dir), { publicationSpine: canonical });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const result = await port.merge(spec, dry.identity!, (attempt) => sealPreparedPublication(sacrificial, attempt));
  assert.equal(result.merged, false);
  assert.match(result.reason ?? "", /authority is absent, forged, replayed, or bound to different bytes/);
  assert.equal(canonical.replay().some((event) => event.type === "effect.intent"), false, "canonical recovery history was not falsely populated");
  assert.equal(g(dir, "show", "main:file.txt"), "base\n", "sacrificial-journal authority cannot move the publication target");
});

test("AM2c RECOVERY: fresh process observes exact predecessor, seals absent, and never retries publication", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const prior = g(remote, "rev-parse", "refs/heads/main").trim();
  const dataDir = mkdtempSync(join(tmpdir(), "keep-am2c-spine-"));
  const firstSpine = durableSpine(dataDir);
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin", publicationSpine: firstSpine });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const interrupted = await port.merge(spec, dry.identity!, async (attempt) => {
    await sealPublicationAttempt(firstSpine, attempt);
    throw new Error("simulated process loss before push");
  });
  assert.equal(interrupted.merged, false);
  assert.equal(g(remote, "rev-parse", "refs/heads/main").trim(), prior);
  // The test process did not actually die, so GitMergePort compensated. Recreate the exact crash residue that would
  // exist after the durable prepare returned and before the first push byte, including a power cut after the
  // content-addressed recovery ref was created but before reset completed.
  g(dir, "reset", "--hard", interrupted.mergeId);
  const preparedEvent = firstSpine.replay().find((event) => (event.payload as Record<string, unknown>).kind === "auto_merge.publication_prepared")!;
  const attemptDigest = (preparedEvent.payload as { attemptDigest: string }).attemptDigest;
  g(dir, "update-ref", `refs/keep/publication-recovery/${attemptDigest}`, interrupted.mergeId);

  class NoPushDuringRecoveryAdapter extends GitAdapter {
    override async git(args: readonly string[]) {
      assert.notEqual(gitSubcommand(args), "push", "recovery of an absent effect must not retry publication");
      return super.git(args);
    }
  }
  const freshSpine = durableSpine(dataDir);
  const recovery = new AutonomousMergeExecutor({
    port: mergePort(new NoPushDuringRecoveryAdapter(dir), { pushRemote: "test-origin", publicationSpine: freshSpine }), spine: freshSpine,
    postMergeVerify: async () => { throw new Error("must not verify an absent publication"); },
  });
  const results = await recovery.reconcileOutstandingPublications();
  assert.equal(results.length, 1);
  assert.equal(results[0]?.status, "abstained");
  assert.match(results[0]?.reason ?? "", /reconciled absent/);
  assert.equal(g(dir, "rev-parse", "main").trim(), prior);
  assert.equal(g(dir, "rev-parse", `refs/keep/publication-recovery/${results[0]?.attemptDigest}`).trim(), interrupted.mergeId);
  assert.equal((await recovery.reconcileOutstandingPublications()).length, 0, "sealed terminal makes restart idempotent");
});

test("AM2c RECOVERY: crash after compensation converges without repeating the revert", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const prior = g(remote, "rev-parse", "refs/heads/main").trim();
  const dataDir = mkdtempSync(join(tmpdir(), "keep-am2c-compensated-"));
  const firstSpine = durableSpine(dataDir);
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin", publicationSpine: firstSpine });
  const candidate = await mergeSpec(dir);
  const dry = await port.dryRun(candidate);
  const interrupted = await port.merge(candidate, dry.identity!, async (attempt) => {
    await sealPublicationAttempt(firstSpine, attempt);
    throw new Error("simulated loss after durable preparation");
  });
  assert.equal(interrupted.compensatedPublicationAbsent, true);
  const compensatedHead = g(dir, "rev-parse", "HEAD").trim();
  assert.notEqual(compensatedHead, prior, "compensation is an auditable revert commit, not history deletion");
  assert.equal(g(dir, "rev-parse", "HEAD^{tree}").trim(), g(dir, `rev-parse`, `${prior}^{tree}`).trim());

  class NoMutationDuringRecovery extends GitAdapter {
    override async git(args: readonly string[]) {
      assert.notEqual(gitSubcommand(args), "push");
      assert.notEqual(args[0], "reset");
      assert.notEqual(args[0], "revert");
      return super.git(args);
    }
  }
  const freshSpine = durableSpine(dataDir);
  const recovery = new AutonomousMergeExecutor({
    port: mergePort(new NoMutationDuringRecovery(dir), { pushRemote: "test-origin", publicationSpine: freshSpine }),
    spine: freshSpine,
    postMergeVerify: async () => { throw new Error("absent publication is never verified as delivered"); },
  });
  const result = await recovery.reconcileOutstandingPublications();
  assert.equal(result[0]?.status, "abstained");
  assert.match(result[0]?.reason ?? "", /already-compensated/);
  assert.equal(g(dir, "rev-parse", "HEAD").trim(), compensatedHead);
  assert.equal((await recovery.reconcileOutstandingPublications()).length, 0);
});

test("AM2c RECOVERY: fresh process observes delivered commit but cannot promote without fresh Firecracker authority", async () => {
  const dir = repo("fixed\n");
  const remote = bareRemoteFor(dir);
  const dataDir = mkdtempSync(join(tmpdir(), "keep-am2c-spine-"));
  const firstSpine = durableSpine(dataDir);
  const port = mergePort(new GitAdapter(dir), { pushRemote: "test-origin", publicationSpine: firstSpine });
  const spec = await mergeSpec(dir);
  const dry = await port.dryRun(spec);
  const delivered = await port.merge(spec, dry.identity!, async (attempt) => sealPublicationAttempt(firstSpine, attempt));
  assert.equal(delivered.merged, true);

  let verified = 0;
  const freshSpine = durableSpine(dataDir);
  const recovery = new AutonomousMergeExecutor({
    port: mergePort(new GitAdapter(dir), { pushRemote: "test-origin", publicationSpine: freshSpine }), spine: freshSpine,
    postMergeVerify: async (_candidate, identity) => {
      verified++;
      return { regressed: false, verifiedProjectManifestDigest: identity.publishedProjectManifestDigest, verifiedGuestExecutionRequestDigest: spec.expectedGuestExecutionRequestDigest };
    },
  });
  const results = await recovery.reconcileOutstandingPublications();
  assert.equal(verified, 1, "recovered delivery runs post-publication verification");
  assert.equal(results[0]?.status, "uncertain", "copied digests without fresh verifier authority cannot promote or authorize compensation");
  assert.equal(g(remote, "rev-parse", "refs/heads/main").trim(), delivered.mergeId, "unverified recovered delivery is preserved while held");
});

test("AM2b AUTHORITY: a real Git port cannot publish from copied digest fields without verifier-owned authority", async () => {
  const dir = repo("fixed\n");
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-gmp-s-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const decision: MergeAuthorityDecision = { verdict: "autonomous-merge", reason: "", consequential: false, verified: true };
  const ex = new AutonomousMergeExecutor({ port, spine, postMergeVerify: async () => ({ regressed: true, detail: "smoke test failed" }) });
  const r = await ex.execute(decision, spec);
  assert.equal(r.status, "refused");
  assert.match(r.reason, /verifier-owned Firecracker execution-subject authority/);
  assert.equal(g(dir, "show", "main:file.txt"), "base\n", "the publication target did not move");
});

test("AM2b AUTHORITY: a plain-object imitation cannot forge the opaque execution-subject capability", async () => {
  const dir = repo("fixed\n");
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-gmp-s2-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const port = mergePort(new GitAdapter(dir));
  const spec = await mergeSpec(dir);
  const decision: MergeAuthorityDecision = { verdict: "autonomous-merge", reason: "", consequential: false, verified: true };
  const ex = new AutonomousMergeExecutor({ port, spine, postMergeVerify: async (_spec, identity) => ({ regressed: false, verifiedProjectManifestDigest: identity.publishedProjectManifestDigest }) });
  const r = await ex.execute(decision, spec, {} as never);
  assert.equal(r.status, "refused");
  assert.equal(g(dir, "show", "main:file.txt"), "base\n", "forged authority did not move the publication target");
});
