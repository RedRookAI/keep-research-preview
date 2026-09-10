import { test } from "node:test";
import assert from "node:assert/strict";
import childProcess, { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { chmodSync, cpSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { exchangePackagedNativeCancel, NativeBoundaryTransportError } from "../src/platform/native_boundary_transport.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const options = { socketPath: `/tmp/keep-diagnostic-absent-${process.pid}.sock`,
  expectedServerUid: process.geteuid!(), expectedServerGid: process.getegid!(),
  expectedServerSecurityLabel: readFileSync("/proc/self/attr/current", "utf8").replace(/[\0\n]+$/u, ""), timeoutMs: 1000 };
const request = () => ({ protocol: "keep.native-boundary", version: 2n, kind: "cancel",
  requestId: "diagnostic.request", deploymentId: "diagnostic.deployment", bootId: "diagnostic.boot",
  manifestDigest: "11".repeat(32), nonce: "diagnostic.nonce", sequence: 1n,
  deadlineMs: BigInt(Date.now() + 5000), targetRequestId: "diagnostic.target" });

test("KEEP-11B-E01 actual copied native client preserves its custody refusal at the Node caller", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-diagnostic-copy-"));
  try {
    cpSync(join(root, "dist"), join(directory, "dist"), { recursive: true, dereference: true });
    assert.notEqual(realpathSync(join(directory, "dist")), realpathSync(join(root, "dist")));
    cpSync(join(root, "package.json"), join(directory, "package.json"));
    const native = join(directory, "dist/native/linux-x64");
    chmodSync(native, 0o755); // Disposable copy only; exact installed-style writable metadata.
    const client = join(native, "keep-native-client");
    const digest = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");
    assert.equal(digest(client), digest(join(root, "dist/native/linux-x64/keep-native-client")));
    const args = ["--socket", options.socketPath, "--expected-server-uid", String(options.expectedServerUid),
      "--expected-server-gid", String(options.expectedServerGid), "--expected-server-security-label", options.expectedServerSecurityLabel];
    const raw = spawnSync(client, args, { cwd: "/", env: {}, input: Buffer.alloc(0), encoding: "utf8", timeout: 2000, maxBuffer: 8192 });
    assert.equal(raw.status, 1); assert.equal(raw.stdout, "");
    assert.match(raw.stderr, /client package directory ownership or mode is invalid/u);
    const copied = await import(pathToFileURL(join(directory, "dist/src/platform/native_boundary_transport.js")).href) as typeof import("../src/platform/native_boundary_transport.js");
    await assert.rejects(copied.exchangePackagedNativeCancel(options, request()),
      /client package directory ownership or mode is invalid/u);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

// Inject only child/stream event ordering. These cases do not claim native
// execution, custody, peer identity, or a remotely triggered exploit.
for (const schedule of ["close-one", "close-zero", "stderr-cap", "stall", "stdout-cap"] as const) {
  test(`KEEP-11B-E01 supplied stream schedule: ${schedule}`, async (t) => {
    let kills = 0, writes = 0;
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(), stderr: new PassThrough(),
      stdin: new Writable({ write(_chunk, _encoding, callback) {
        writes += 1; callback(Object.assign(new Error("write EPIPE"), { code: "EPIPE" }));
      } }),
      kill: () => { kills += 1; setImmediate(() => child.emit("close", null, "SIGKILL")); return true; },
    });
    const replacement = (() => {
      setImmediate(() => {
        if (schedule === "stall") { child.stderr.write("setup remained incomplete"); return; }
        if (schedule === "stdout-cap") { child.stdout.end(Buffer.alloc(65_541)); return; }
        child.stderr.end(schedule === "stderr-cap" ? "x".repeat(4096) + "MUST_NOT_APPEAR" : "native setup refused\n");
        child.stdout.end(); child.emit("close", schedule === "close-zero" ? 0 : 1, null);
      });
      return child;
    }) as unknown as typeof childProcess.spawn;
    const mocked = t.mock.method(childProcess, "spawn", replacement);
    syncBuiltinESMExports();
    // The supplied child has no real OS handle to keep the deadline test alive.
    const keepAlive = setTimeout(() => {}, 2000);
    const started = Date.now();
    try {
      await assert.rejects(exchangePackagedNativeCancel({ ...options, timeoutMs: 100 }, request()), (error: unknown) => {
        assert.ok(error instanceof NativeBoundaryTransportError);
        if (schedule === "stall") {
          assert.match(error.message, /client deadline exceeded/u);
          assert.match(error.message, /stdin failed: write EPIPE/u);
          assert.match(error.message, /setup remained incomplete/u);
        } else if (schedule === "stdout-cap") assert.match(error.message, /stdout exceeds one bounded frame/u);
        else {
          assert.match(error.message, /stdin failed: write EPIPE/u);
          assert.match(error.message, schedule === "close-zero" ? /client failed \(0\)/u : /client failed \(1\)/u);
          if (schedule === "stderr-cap") {
            assert.match(error.message, /x{4096}/u); assert.doesNotMatch(error.message, /MUST_NOT_APPEAR/u);
            assert.ok(error.message.length < 4300);
          } else assert.match(error.message, /native setup refused/u);
        }
        return true;
      });
      assert.equal(writes, 1);
      assert.equal(kills, schedule === "stall" || schedule === "stdout-cap" ? 1 : 0);
      assert.ok(Date.now() - started < 1500, "original deadline must remain bounded");
    } finally {
      clearTimeout(keepAlive); mocked.mock.restore(); syncBuiltinESMExports();
      child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    }
  });
}
