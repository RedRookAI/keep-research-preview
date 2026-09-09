import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { GitAdapter } from "../src/infra/git_adapter.js";
import { GitMergePort } from "../src/git/git_merge_port.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../src/infra/microvm_boundary.js";
import type { MergeSpec } from "../src/oversight/merge_executor.js";
import { GitRevertSignalSource } from "../src/oversight/revert_signal.js";
import { CalibrationWire } from "../src/oversight/calibration_wire.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

function git(cwd: string, ...args: string[]): string { return execFileSync("git", args, { cwd, encoding: "utf8" }); }
function newRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-revsig-"));
  git(dir, "init", "-q"); git(dir, "config", "user.email", "keep@x.io"); git(dir, "config", "user.name", "keep");
  writeFileSync(join(dir, "f.txt"), "base\n"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "base");
  return dir;
}
function spine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-rs-spine-")), { fsync: true }), new InProcessLock(), new SchemaRegistry()); }
async function land(port: GitMergePort, dir: string, branch: string, issueId: string) {
  const spec: MergeSpec = {
    issueId,
    repoRef: dir,
    baseBranch: "master",
    branch,
    expectedCandidateCommit: git(dir, "rev-parse", branch).trim(),
    expectedCandidateProjectManifestDigest: await computeMicrovmProjectSourceManifestSha256(dir),
    expectedGuestExecutionRequestDigest: "c".repeat(64),
    projectDir: dir,
  };
  const preflight = await port.dryRun(spec);
  assert.equal(preflight.clean, true);
  return { outcome: await port.merge(spec, preflight.identity!, (attempt) => port.preparePublication(attempt)), spec };
}

test("REVERT SIGNAL (crown): a REAL merge that is REALLY reverted → the source reports 'reverted' from git history", async () => {
  const dir = newRepo();
  const adapter = new GitAdapter(dir);
  const port = new GitMergePort(adapter, { publicationSpine: spine() });

  // a real feature branch merged into main
  git(dir, "checkout", "-qb", "feature");
  writeFileSync(join(dir, "f.txt"), "base\nfeature\n"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "feature");
  const merge = await land(port, dir, "feature", "feat");
  assert.ok(merge.outcome.merged, "the merge landed");
  const mergeSha = merge.outcome.mergeId;

  const wire = new CalibrationWire();
  wire.recordDecision("auto-low-risk", true, true); // the gate approved this change (recorded at decision time)
  const source = new GitRevertSignalSource(adapter, wire, spine());

  // REALLY revert the merge commit on disk, then observe the outcome ONCE (as the real flow would, once it's known).
  await port.revert(mergeSha, merge.spec);
  const scan = await source.reconcile([{ mergeSha, gate: "auto-low-risk" }]);
  assert.equal(scan[0]!.outcome, "reverted", "the real revert is detected from git history's 'This reverts commit' trailer");
  assert.ok(scan[0]!.assessment.revertRate > 0, "calibration observed the real revert");

  // control: a DIFFERENT merge that was NOT reverted reads back clean.
  git(dir, "checkout", "-qb", "clean-feature");
  writeFileSync(join(dir, "g.txt"), "clean\n"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "clean feat");
  const m2 = await land(port, dir, "clean-feature", "i2");
  const clean = await source.reconcile([{ mergeSha: m2.outcome.mergeId, gate: "auto-low-risk" }]);
  assert.equal(clean[0]!.outcome, "clean", "an un-reverted merge reads back clean");
});

test("TIGHTENING: a rising real revert rate drives calibration toward MORE scrutiny (safe direction)", async () => {
  const dir = newRepo();
  const adapter = new GitAdapter(dir);
  const port = new GitMergePort(adapter, { publicationSpine: spine() });
  const wire = new CalibrationWire();
  const source = new GitRevertSignalSource(adapter, wire, spine());

  // land + revert several merges on one gate
  const merges: { mergeSha: string; gate: string }[] = [];
  for (let i = 0; i < 3; i++) {
    wire.recordDecision("loose-gate", true, true); // each merge was an approved decision
    git(dir, "checkout", "-qb", `f${i}`);
    writeFileSync(join(dir, `x${i}.txt`), `v${i}\n`); git(dir, "add", "-A"); git(dir, "commit", "-qm", `c${i}`);
    const m = await land(port, dir, `f${i}`, `t${i}`);
    const sha = m.outcome.mergeId;
    await port.revert(sha, m.spec);
    merges.push({ mergeSha: sha, gate: "loose-gate" });
  }
  const scan = await source.reconcile(merges);
  assert.ok(scan.every((r) => r.outcome === "reverted"), "all real reverts detected");
  const last = scan[scan.length - 1]!.assessment;
  assert.ok(last.revertRate > 0.5, "a high real revert rate is measured");
  assert.notEqual(last.recommendation, "reduce-escalation-candidate", "a high revert rate never recommends LESS scrutiny");
});

test("WIRE: composeKeep(repoDir) exposes a real revert signal; absent → seam stays a no-op", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const dir = newRepo();
  const withRepo = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-rs-d1-")), repoDir: dir });
  assert.ok(withRepo.revertSignal, "a git tree activates the real revert-signal source");
  const bare = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-rs-d2-")) });
  assert.equal(bare.revertSignal, undefined, "no repo ⇒ no source (honest: the seam isn't claimed as built)");
});
