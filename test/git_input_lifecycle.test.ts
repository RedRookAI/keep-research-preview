import { test } from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GitAdapter } from "../src/infra/git_adapter.js";

// Force the observed ordering: the child closes its input before the parent's
// write. This falsifies the bug deterministically, without retry-until-green.
for (const input of [undefined, Buffer.alloc(0), Buffer.from("required bytes")]) {
  test(`gitInput closed child input: ${input === undefined ? "absent" : input.length === 0 ? "empty" : "nonempty"}`, async (t) => {
    let writes = 0;
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(), stderr: new PassThrough(),
      stdin: new Writable({ write(_chunk, _encoding, callback) {
        writes += 1; callback(Object.assign(new Error("write EPIPE"), { code: "EPIPE" }));
      } }),
      kill: () => { setImmediate(() => child.emit("close", null, "SIGKILL")); return true; },
    });
    const replacement = (() => {
      setImmediate(() => {
        child.stdout.end("MM tracked.txt\0?? new.txt\0"); child.stderr.end(); child.emit("close", 0, null);
      });
      return child;
    }) as unknown as typeof childProcess.spawn;
    const mocked = t.mock.method(childProcess, "spawn", replacement);
    syncBuiltinESMExports();
    try {
      const result = new GitAdapter(tmpdir()).gitInput(["status", "--porcelain=v1", "-z"], input === undefined ? {} : { stdin: input });
      if (input !== undefined && input.length > 0) {
        await assert.rejects(result, { code: "EPIPE" }); assert.equal(writes, 1);
      } else {
        assert.equal((await result).stdout.toString(), "MM tracked.txt\0?? new.txt\0"); assert.equal(writes, 0);
      }
    } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
  });
}

test("gitInput retains real binary input, empty-blob and failing-command semantics", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-git-input-lifecycle-"));
  const git = new GitAdapter(root); await git.git(["init"]);
  for (const bytes of [Buffer.alloc(0), Buffer.from([0, 255, 10, 128, 65, 0])]) {
    const oid = (await git.gitInput(["hash-object", "-w", "--stdin"], { stdin: bytes })).stdout.toString().trim();
    assert.deepEqual((await git.gitInput(["cat-file", "blob", oid])).stdout, bytes);
  }
  await assert.rejects(git.gitInput(["rev-parse", "--verify", "refs/heads/missing"]), /git command failed \(128\)/u);
});
