#!/usr/bin/env node
import { closeSync, constants, fstatSync, mkdtempSync, openSync, readFileSync, readSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const options = { tarball: null, sha256: null, n1Only: false, n1EventOnly: false, timeoutMs: 1_200_000 };
const seen = new Set();
for (const arg of process.argv.slice(2)) {
  const key = arg.split("=", 1)[0];
  if (seen.has(key)) throw new Error(`duplicate installed-runner option: ${key}`);
  seen.add(key);
  if (arg.startsWith("--tarball=") && arg.length > 10) options.tarball = resolve(arg.slice(10));
  else if (/^--sha256=[a-f0-9]{64}$/u.test(arg)) options.sha256 = arg.slice(9);
  else if (arg === "--n1-only") options.n1Only = true;
  else if (arg === "--n1-event-only") options.n1EventOnly = true;
  else if (/^--timeout-ms=[1-9][0-9]*$/u.test(arg) && Number(arg.slice(13)) <= 86_400_000) options.timeoutMs = Number(arg.slice(13));
  else throw new Error(`invalid installed-runner option: ${arg}`);
}
if ((options.tarball === null) !== (options.sha256 === null)) throw new Error("retained --tarball and --sha256 must be supplied together");
const deadline = performance.now() + options.timeoutMs;
function run(command, args, cwd, inherit = false, env = process.env) {
  const timeout = Math.floor(deadline - performance.now());
  if (timeout <= 0) throw new Error("installed-runner total time budget exhausted");
  const childEnv = { ...env };
  delete childEnv.NODE_TEST_CONTEXT;
  const result = spawnSync(command, args, { cwd, env: childEnv, encoding: "utf8", timeout, killSignal: "SIGKILL", maxBuffer: 4 * 1024 * 1024, ...(inherit ? { stdio: "inherit" } : {}) });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (status=${result.status}, signal=${result.signal}): ${result.stderr ?? "see streamed output"}`);
  return result;
}

// Capture one bounded regular file through a held descriptor, then install the private copy.
// The digest is supplied by the caller's retained-artifact authority, not inferred from a filename.
function captureTarball(path, expected) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 256 * 1024 * 1024) throw new Error("tarball must be a nonempty regular file of at most 256MiB");
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count === 0) throw new Error("tarball truncated during capture");
      offset += count;
    }
    if (readSync(fd, Buffer.alloc(1), 0, 1, null) !== 0) throw new Error("tarball grew during capture");
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (expected !== null && digest !== expected) throw new Error("retained tarball SHA256 mismatch; no install or test dispatched");
    return { bytes, digest };
  } finally { closeSync(fd); }
}

// Validate retained bytes before even creating an install directory or invoking npm.
let captured = options.tarball === null ? null : captureTarball(options.tarball, options.sha256);
const fixture = mkdtempSync(join(tmpdir(), "keep-installed-journeys-"));
if (captured === null) {
  process.stdout.write("[test:installed] building one new package (prepack lifecycle enabled); use --tarball=PATH --sha256=HEX to consume retained bytes without rebuilding\n");
  const packed = run("npm", ["pack", "--offline", "--pack-destination", fixture, "--silent"], root);
  const name = packed.stdout.trim().split(/\r?\n/u).at(-1);
  if (!name || basename(name) !== name || !/^[A-Za-z0-9_.-]+\.tgz$/u.test(name)) throw new Error("npm pack did not return a single safe archive filename");
  captured = captureTarball(join(fixture, name), null);
}
const tarball = join(fixture, "retained-input.tgz");
writeFileSync(tarball, captured.bytes, { flag: "wx", mode: 0o400 });
process.stdout.write(`[test:installed] sha256=${captured.digest} fixture=${fixture}; ${options.n1Only || options.n1EventOnly ? "PARTIAL n1 selection, not paired qualification" : "paired n1/enterprise selection"}\n`);
writeFileSync(join(fixture, "package.json"), JSON.stringify({ name: "keep-installed-consumer", version: "1.0.0", private: true, type: "module" }), { flag: "wx", mode: 0o600 });
run("npm", ["install", "--offline", tarball, "--ignore-scripts", "--no-audit", "--no-fund"], fixture);

const installedRoot = join(fixture, "node_modules", "keep");
const allTests = [
  join(root, "acceptance", "installed_n1_golden_journey.test.mjs"),
  join(root, "acceptance", "installed_enterprise_golden_journey.test.mjs"),
  join(root, "acceptance", "installed_sg01_recovery_journey.test.mjs"),
  join(root, "acceptance", "installed_bounded_recovery.test.mjs"),
  join(root, "acceptance", "installed_sg02_capture_journey.test.mjs"),
];
const n1EventOnly = options.n1EventOnly;
const tests = options.n1Only || n1EventOnly ? [allTests[0]] : allTests;
const testArgs = ["--test", "--test-concurrency=1", ...(n1EventOnly ? ["--test-name-pattern=SG-01-T001|PG-05-T015"] : []), ...tests];
const installedEnv = { ...process.env, KEEP_INSTALLED_PACKAGE_ROOT: installedRoot };
if (tests.some(file => file.includes("installed_sg02_capture_journey"))) {
  const lock = JSON.parse(readFileSync(join(installedRoot, "native/toolchain-lock.json"), "utf8"));
  installedEnv.KEEP_P1_TOOLCHAIN_ROOT ??= join(process.env.RUSTUP_HOME ?? join(homedir(), ".rustup"), "toolchains", lock.toolchain);
}
run(process.execPath, testArgs, fixture, true, installedEnv);
