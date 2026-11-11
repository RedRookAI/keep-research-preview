import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { materializeRepository } from "../src/git/repository_materializer.js";
import { gitChildHardening } from "../src/cli/runtime_config.js";

test("local materialization owns every Git object and cannot overwrite its source object bytes", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-clone-isolation-"));
  const source = join(root, "source"), workspaceBase = join(root, "workspaces");
  const hardening = gitChildHardening(process.platform, process.env);
  const git = (...args: string[]) => execFileSync("git", [...hardening.configArgs, "-C", source, ...args], {
    env: hardening.env, encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  mkdirSync(source); mkdirSync(workspaceBase);
  try {
    git("init", "-q", "-b", "main");
    writeFileSync(join(source, "work.txt"), "original source\n");
    git("add", "."); git("-c", "user.name=Keep Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "base");
    const commit = git("rev-parse", "HEAD");
    const objectPath = (repo: string, oid: string) => join(repo, ".git/objects", oid.slice(0, 2), oid.slice(2));
    const objects = git("rev-list", "--objects", "--all").split("\n").map(row => row.split(" ")[0]!);
    assert.ok(objects.length >= 3, "real commit, tree and blob required");
    const before = objects.map(oid => ({ oid, bytes: readFileSync(objectPath(source, oid)), identity: statSync(objectPath(source, oid)) }));
    const materialized = await materializeRepository({ sourceDir: source, workspaceBase, repoRef: "project", commit });
    for (const original of before) {
      const copied = objectPath(materialized.projectDir, original.oid), identity = statSync(copied);
      assert.equal(identity.nlink, 1, "workspace object must be single-link data");
      assert.notDeepEqual([identity.dev, identity.ino], [original.identity.dev, original.identity.ino]);
      assert.deepEqual(readFileSync(copied), original.bytes);
      // Prove a clone-only object write cannot propagate to the source inode.
      chmodSync(copied, 0o600); writeFileSync(copied, "changed disposable object\n");
      assert.deepEqual(readFileSync(objectPath(source, original.oid)), original.bytes);
      assert.equal(statSync(objectPath(source, original.oid)).nlink, 1);
    }
    assert.equal(git("rev-parse", "HEAD"), commit); assert.equal(git("status", "--porcelain"), "");
    assert.equal(readFileSync(join(source, "work.txt"), "utf8"), "original source\n");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
