import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Argument/refusal checks only. Never launch a VM or fabricate a signed policy.
const common = ["--vmm", "--jailer", "--kernel", "--rootfs", "--work-root", "--output", "--subject-manifest", "--policy"];
for (const [tool, required] of [
  ["firecracker_host_evidence.mjs", [...common, "--signed-policy", "--trust-root"]],
  ["firecracker_host_hostile.mjs", common],
] as const) {
  test(`${tool}: explicit host inputs required before any file access or execution`, () => {
    const root = mkdtempSync(join(tmpdir(), "keep-firecracker-args-"));
    const path = join(root, "intentionally-absent");
    assert.doesNotMatch(readFileSync(join(process.cwd(), "tools", tool), "utf8"), /\/root\/keep|docs\/review\/|\/var\/lib\/keep/);
    const invoke = (args: readonly string[]) => spawnSync(process.execPath,
      [join(process.cwd(), "tools", tool), ...args], {
        cwd: root, encoding: "utf8", timeout: 5000,
        env: { PATH: "/usr/bin:/bin", LANG: "C" },
      });
    try {
      for (const missing of required) {
        const result = invoke(required.filter(flag => flag !== missing).flatMap(flag => [flag, path]));
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stderr, new RegExp(`explicit ${missing} path required`));
        // Node's stack includes the actual checkout path. That is not a fallback
        // input path; check absence of attempted I/O and historical inputs instead.
        assert.doesNotMatch(result.stderr, /ENOENT|EACCES|REAL-FIRECRACKER/);
        assert.deepEqual(readdirSync(root), [], "missing configuration must not prepare a work/output directory");
      }
      for (const args of [["--vmm"], ["--vmm", "--jailer", path]]) {
        const result = invoke(args);
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stderr, /explicit --vmm path required/);
        assert.deepEqual(readdirSync(root), []);
      }

      // Complete flags get past preflight, but do not authorize invented evidence.
      // The evidence tool reads its signed policy first; the hostile tool reads
      // the subject manifest first. Both must reject invalid supplied content.
      const invalid = join(root, "invalid.json");
      writeFileSync(invalid, "{}\n");
      const result = invoke(required.flatMap(flag => [flag, invalid]));
      assert.equal(result.status, 1, result.stderr);
      assert.doesNotMatch(result.stderr, /explicit .* path required/);
      assert.match(result.stderr, /malformed|schema|policy|authority|trust/i);
      assert.deepEqual(readdirSync(root), ["invalid.json"]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}
