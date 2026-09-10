import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, chmodSync, cpSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  exchangePackagedNativeCancel,
  NativeBoundaryTransportError,
} from "../src/platform/native_boundary_transport.js";
import { composeKeep } from "../src/compose.js";
import { encodeCanonical } from "../src/eir/canonical.js";
import { captureNativeV2Schema } from "../src/platform/native_boundary_protocol_v2.js";
import {
  buildNativeTransportDevelopmentFixture,
  buildNativeTransportDevelopmentProbe,
} from "../src/platform/native_boundary_development_fixture.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const supervisor = join(root, "dist/native/linux-x64/keep-native-supervisor");
const D = "11".repeat(32);
const uid = process.geteuid?.() ?? 0;
const gid = process.getegid?.() ?? 0;
const securityLabel = readFileSync("/proc/self/attr/current", "utf8").replace(/[\0\n]+$/, "");

function cancel(
  deadlineMs = BigInt(Date.now() + 5000),
  manifestDigest = D,
  deploymentId = "development.deployment",
) {
  return {
    protocol: "keep.native-boundary",
    version: 2n,
    kind: "cancel",
    requestId: "transport.request",
    deploymentId,
    bootId: "development.boot",
    manifestDigest: D,
    nonce: "transport.nonce",
    sequence: 7n,
    deadlineMs,
    targetRequestId: "transport.probe",
  } as const;
}

async function waitForSocket(path: string, child: ChildProcess): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`supervisor exited before ready: ${child.exitCode}`);
    try {
      const { lstat } = await import("node:fs/promises");
      if ((await lstat(path)).isSocket()) return;
    } catch { /* not ready */ }
    await delay(10);
  }
  throw new Error("supervisor socket did not appear");
}

async function waitForExit(child: ChildProcess): Promise<number | null> {
  if (child.exitCode !== null) return child.exitCode;
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("supervisor timeout")); }, 2000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
}

test("A6 installed Node path reaches packaged client and supervisor but returns only refusal", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-node-native-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "native.sock");
  const child = spawn(supervisor, [
    "--socket", socketPath,
    "--expected-client-uid", String(uid),
    "--expected-client-gid", String(gid),
    "--expected-client-security-label", securityLabel,
  ], { cwd: "/", env: {}, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  try {
    await waitForSocket(socketPath, child);
    const app = composeKeep({
      dataDir: join(directory, "keep-data"),
      nativeBoundaryTransport: { socketPath, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel, timeoutMs: 2000 },
    });
    assert.ok(app.nativeBoundaryTransport);
    const fixture = app.nativeBoundaryTransport.developmentFixture;
    assert.equal(fixture.channelMaxFrameBytes, 65_536);
    const response = await app.nativeBoundaryTransport.probe({
      bootId: "development.boot",
      deadlineMs: BigInt(Date.now() + 5000),
      sequence: 7n,
    });
    assert.equal(response.deploymentId, fixture.deploymentId);
    assert.equal(response.status, "refused");
    assert.equal(response.failureCode, "evidence.unavailable.transport_only");
    assert.equal(response.evidenceBundleDigest, null);
    assert.deepEqual(response.roleHandles, []);
    assert.deepEqual(response.measurements, []);
    assert.equal(await waitForExit(child), 0, stderr);
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 transport fixture has an exact envelope digest and is categorically development-only", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-fixture-"));
  try {
    const app = composeKeep({
      dataDir: directory,
      nativeBoundaryTransport: { socketPath: "/run/keep/not-opened.sock", expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel },
    });
    const fixture = app.nativeBoundaryTransport!.developmentFixture;
    const deployment = fixture.deployment as unknown as {
      payload: { channels: { channelId: string; maxFrameBytes: bigint }[] };
    };
    assert.equal(
      deployment.payload.channels.find((row) => row.channelId === fixture.channelId)?.maxFrameBytes,
      65_536n,
    );
    assert.equal(
      createHash("sha256").update(encodeCanonical(fixture.deployment)).digest("hex"),
      fixture.manifestDigest,
    );
    assert.equal(captureNativeV2Schema(fixture.deployment, "deployment", "development").schema, "deployment");
    const canonical = Buffer.from(encodeCanonical(fixture.deployment));
    const oracle = join(root, "native/target/x86_64-unknown-linux-musl/debug/keep-native-protocol-oracle");
    const rust = spawn(oracle, { env: {}, stdio: ["pipe", "pipe", "pipe"] });
    const output = await new Promise<string>((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      rust.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
      rust.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
      rust.once("error", reject);
      rust.once("close", (code) => code === 0 ? resolve(stdout.trim()) : reject(new Error(stderr)));
      rust.stdin?.end(`${canonical.toString("hex")}\n`);
    });
    assert.equal(
      output,
      `OK\tDeployment\t${fixture.manifestDigest}\t${canonical.toString("hex")}`,
    );
    assert.throws(
      () => captureNativeV2Schema(fixture.deployment, "deployment", "production"),
      /development|production|trust class|signature key refused/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 development transport nonces are fresh 128-bit CSPRNG outputs with no fallback", () => {
  const fixture = buildNativeTransportDevelopmentFixture();
  const input = { bootId: "development.boot", deadlineMs: BigInt(Date.now() + 5000) };
  const first = buildNativeTransportDevelopmentProbe(fixture, input);
  const second = buildNativeTransportDevelopmentProbe(fixture, input);
  assert.match(first.nonce, /^transport\.nonce\.[0-9a-f]{32}$/);
  assert.match(first.requestId, /^transport\.probe\.[0-9a-f]{32}$/);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.requestId, second.requestId);
  const source = readFileSync(
    join(root, "src/platform/native_boundary_development_fixture.ts"),
    "utf8",
  );
  assert.match(source, /randomBytes\(16\)\.toString\("hex"\)/);
  assert.doesNotMatch(source, /Math\.random|randomUUID|Date\.now|catch\s*\{/);
});

test("A6 packaged refusal adapter rejects non-cancel authority before opening transport", async () => {
  const { targetRequestId: _targetRequestId, ...base } = cancel();
  await assert.rejects(
    exchangePackagedNativeCancel(
      { socketPath: "/run/keep/absent.sock", expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel },
      { ...base, kind: "probe", roleHandleIds: ["handle.1"], challengeNonce: "challenge.1" },
    ),
    (error: unknown) => error instanceof NativeBoundaryTransportError && /cancel requests only/.test(error.message),
  );
});

test("A6 packaged refusal adapter reports an honest absent-endpoint failure", async () => {
  await assert.rejects(
    exchangePackagedNativeCancel(
      { socketPath: `/tmp/keep-native-absent-${process.pid}.sock`, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel },
      cancel(),
    ),
    (error: unknown) => error instanceof NativeBoundaryTransportError && /client failed/.test(error.message),
  );
});

test("A6 packaged client refuses a supervisor with the wrong configured security label", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-wrong-label-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "native.sock");
  const child = spawn(supervisor, [
    "--socket", socketPath,
    "--expected-client-uid", String(uid),
    "--expected-client-gid", String(gid),
    "--expected-client-security-label", securityLabel,
  ], { cwd: "/", env: {}, stdio: ["ignore", "ignore", "pipe"] });
  try {
    await waitForSocket(socketPath, child);
    await assert.rejects(
      exchangePackagedNativeCancel(
        { socketPath, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: "keep.invalid.security.label", timeoutMs: 1000 },
        cancel(),
      ),
      (error: unknown) => error instanceof NativeBoundaryTransportError && /peer security label mismatch/.test(error.message),
    );
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
    await waitForExit(child).catch(() => null);
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 Node deadline kills a client blocked behind a stopped supervisor", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-timeout-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "native.sock");
  const child = spawn(supervisor, [
    "--socket", socketPath,
    "--expected-client-uid", String(uid),
    "--expected-client-gid", String(gid),
    "--expected-client-security-label", securityLabel,
  ], { cwd: "/", env: {}, stdio: ["ignore", "ignore", "pipe"] });
  try {
    await waitForSocket(socketPath, child);
    child.kill("SIGSTOP");
    const started = Date.now();
    await assert.rejects(
      exchangePackagedNativeCancel(
        { socketPath, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel, timeoutMs: 100 },
        cancel(),
      ),
      (error: unknown) => error instanceof NativeBoundaryTransportError && /client deadline exceeded/.test(error.message),
    );
    assert.ok(Date.now() - started < 1500, "deadline did not bound the blocked client");
  } finally {
    child.kill("SIGCONT");
    if (child.exitCode === null) child.kill("SIGKILL");
    await waitForExit(child).catch(() => null);
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 packaged client rejects same-identity supervisor substitution by executable measurement", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-supervisor-substitution-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "native.sock");
  const substitute = spawn("/usr/bin/python3", [
    "-c",
    [
      "import os, socket, sys",
      "path = sys.argv[1]",
      "server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)",
      "server.bind(path)",
      "os.chmod(path, 0o600)",
      "server.listen(1)",
      "peer, _ = server.accept()",
      "peer.recv(65536)",
    ].join("\n"),
    socketPath,
  ], { cwd: "/", env: {}, stdio: ["ignore", "ignore", "pipe"] });
  try {
    await waitForSocket(socketPath, substitute);
    await assert.rejects(
      exchangePackagedNativeCancel(
        { socketPath, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel, timeoutMs: 1000 },
        cancel(),
      ),
      (error: unknown) => error instanceof NativeBoundaryTransportError && /peer executable measurement mismatch/.test(error.message),
    );
    assert.equal(await waitForExit(substitute), 0);
  } finally {
    if (substitute.exitCode === null) substitute.kill("SIGKILL");
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 packaged client refuses a non-private replacement at the genuine socket path", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-socket-replacement-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "native.sock");
  const child = spawn(supervisor, [
    "--socket", socketPath,
    "--expected-client-uid", String(uid),
    "--expected-client-gid", String(gid),
    "--expected-client-security-label", securityLabel,
  ], { cwd: "/", env: {}, stdio: ["ignore", "ignore", "pipe"] });
  try {
    await waitForSocket(socketPath, child);
    chmodSync(socketPath, 0o666);
    await assert.rejects(
      exchangePackagedNativeCancel(
        { socketPath, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel, timeoutMs: 1000 },
        cancel(),
      ),
      (error: unknown) => error instanceof NativeBoundaryTransportError && /socket must not grant group\/other access/.test(error.message),
    );
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
    await waitForExit(child).catch(() => null);
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 installed-copy client substitution is rejected before transport", async () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-substitution-"));
  try {
    // Installed test harnesses may resolve dist through a symlink. Materialize
    // independent bytes before tampering; never copy an alias to the subject.
    cpSync(join(root, "dist"), join(directory, "dist"), { recursive: true, dereference: true });
    assert.notEqual(realpathSync(join(directory, "dist")), realpathSync(join(root, "dist")));
    writeFileSync(join(directory, "package.json"), '{"type":"module"}\n');
    appendFileSync(join(directory, "dist/native/linux-x64/keep-native-client"), Buffer.from([0]));
    const copied = await import(
      `${pathToFileURL(join(directory, "dist/src/platform/native_boundary_transport.js")).href}?copy=${Date.now()}`
    ) as typeof import("../src/platform/native_boundary_transport.js");
    await assert.rejects(
      copied.exchangePackagedNativeCancel(
        { socketPath: `/tmp/keep-native-absent-${process.pid}.sock`, expectedServerUid: uid, expectedServerGid: gid, expectedServerSecurityLabel: securityLabel },
        cancel(),
      ),
      /packaged client type, size, or mode mismatch|packaged client digest mismatch/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("A6 release client refuses a relocated writable package and forged supervisor sidecar", () => {
  const directory = mkdtempSync(join(tmpdir(), "keep-native-relocated-client-"));
  try {
    const client = join(directory, "keep-native-client");
    cpSync(join(root, "dist/native/linux-x64/keep-native-client"), client);
    chmodSync(client, 0o555);
    const sidecar = join(directory, "keep-native-supervisor.sha256");
    writeFileSync(sidecar, `${"00".repeat(32)}\n`, { mode: 0o444 });
    chmodSync(sidecar, 0o444);
    const result = spawnSync(client, [
      "--socket", `/tmp/keep-native-absent-${process.pid}.sock`,
      "--expected-server-uid", String(uid),
      "--expected-server-gid", String(gid),
      "--expected-server-security-label", securityLabel,
    ], { cwd: "/", env: {}, input: Buffer.alloc(0), encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /client package directory ownership or mode is invalid/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
