#!/usr/bin/env node
/** Production-shaped hostile checks against the real Firecracker+jailer boundary. */
import { execFileSync } from "node:child_process";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createHash } from "node:crypto";
import { buildMicrovmBoundaryRun, verifiedMicrovmRunReceipt } from "../dist/src/infra/microvm_boundary.js";

const root = resolve(new URL("..", import.meta.url).pathname);
// No maintainer paths or historical evidence are defaults in the public tool.
const arg = (name) => {
  const index = process.argv.indexOf(name);
  const value = index >= 0 ? process.argv[index + 1] : undefined;
  if (!value || value.startsWith("--")) throw new Error(`explicit ${name} path required; Firecracker qualification needs a separately prepared authorized host`);
  return value;
};
const vmm = resolve(arg("--vmm"));
const jailer = resolve(arg("--jailer"));
const kernel = resolve(arg("--kernel"));
const rootfs = resolve(arg("--rootfs"));
const workRoot = resolve(arg("--work-root"));
const output = resolve(root, arg("--output"));
const runtimeSubjectManifestPath = resolve(root, arg("--subject-manifest"));
const policyPath = resolve(root, arg("--policy"));
const runtimeSubjectManifestBytes = readFileSync(runtimeSubjectManifestPath);
const runtimeSubjectManifest = JSON.parse(runtimeSubjectManifestBytes.toString("utf8"));
if (runtimeSubjectManifest.schema !== "keep.runtime-subject-manifest/v1" || !Array.isArray(runtimeSubjectManifest.files)) throw new Error("runtime subject manifest is malformed");
for (const row of runtimeSubjectManifest.files) {
  if (typeof row?.path !== "string" || typeof row?.sha256 !== "string" || createHash("sha256").update(readFileSync(resolve(root, row.path))).digest("hex") !== row.sha256) {
    throw new Error(`runtime subject drift: ${String(row?.path)}`);
  }
}
const runtimeSubjectManifestSha256 = createHash("sha256").update(runtimeSubjectManifestBytes).digest("hex");
const runtime = { kind: "firecracker", available: true, tier: "microvm", kvmPresent: true, detail: "pinned hostile evidence", vmmPath: vmm, jailerPath: jailer };
const trustedMeasurements = JSON.parse(readFileSync(policyPath, "utf8"));
const base = {
  projectDir: root, kernelImage: kernel, rootfsImage: rootfs,
  memoryBytes: 256 * 1024 * 1024, maxFileSizeBytes: 64 * 1024 * 1024, maxProcesses: 128,
  timeoutMs: 120_000, maxOutputBytes: 1024 * 1024, vmmBin: vmm, jailerBin: jailer,
  guestInitPath: resolve(root, "assets/microvm/keep-init"), workRoot, trustedMeasurements,
};

async function invoke(id, command, args, overrides = {}) {
  const run = buildMicrovmBoundaryRun(runtime, { ...base, command, args, ...overrides });
  const result = await run({}, { projectDir: root, repoRef: ".", patchRisk: "high" });
  const receipt = verifiedMicrovmRunReceipt(result);
  return { id, result, receipt: receipt ?? null };
}

const checks = [];
checks.push(await invoke("argv-metacharacters-inert", "/usr/bin/printf", ["%s\\n", "$(printf PWNED);*'\\\""]));
if (checks.at(-1).receipt?.guestResult.stdout !== "$(printf PWNED);*'\\\"\n") {
  throw new Error(`argv metacharacters were not preserved literally: ${JSON.stringify(checks.at(-1))}`);
}

checks.push(await invoke("no-virtio-net-device", "/bin/sh", ["-c", "test ! -e /sys/class/net/eth0 && echo 'ok 1 - no-nic'"]));
if (!checks.at(-1).receipt?.guestResult.stdout.includes("ok 1 - no-nic")) throw new Error("guest unexpectedly observed eth0");

checks.push(await invoke("readonly-rootfs", "/bin/sh", ["-c", "if touch /etc/keep-escape 2>/dev/null; then exit 91; else echo 'ok 1 - readonly-rootfs'; fi"]));
if (!checks.at(-1).receipt?.guestResult.stdout.includes("ok 1 - readonly-rootfs")) throw new Error("guest rootfs write was not refused");

checks.push(await invoke("serial-paths-open-denied", "/bin/sh", ["-c", "if printf 'FORGED\\n' >/dev/ttyS0 2>/dev/null || printf 'FORGED\\n' >/dev/console 2>/dev/null || printf 'FORGED\\n' >/dev/tty 2>/dev/null; then exit 92; else echo 'ok 1 - serial-paths-open-denied'; fi"]));
if (!checks.at(-1).receipt?.guestResult.stdout.includes("ok 1 - serial-paths-open-denied")) throw new Error("untrusted guest command could open a supervisor serial path");

checks.push(await invoke("inherited-console-fd-closed", "/bin/sh", ["-c", "if printf 'FORGED\\n' >&0 2>/dev/null; then exit 93; else echo 'ok 1 - inherited-console-fd-closed'; fi"]));
if (!checks.at(-1).receipt?.guestResult.stdout.includes("ok 1 - inherited-console-fd-closed")) throw new Error("untrusted guest command retained a writable inherited console descriptor");

checks.push(await invoke("result-secret-absent-from-proc-and-survivor-reaped", "/bin/sh", ["-c", "( while :; do for f in /proc/[0-9]*/cmdline; do tr '\\000' ' ' <\"$f\" 2>/dev/null | grep -q 'hexkey:' && echo SECRET-LEAK; done; done ) & echo 'ok 1 - proc-scan-survivor-started'"]));
if (!checks.at(-1).receipt?.guestResult.stdout.includes("ok 1 - proc-scan-survivor-started") || checks.at(-1).receipt?.guestResult.stdout.includes("SECRET-LEAK")) {
  throw new Error("untrusted guest recovered result authentication material from proc");
}

checks.push(await invoke("attempt-nonce-absent-from-global-cmdline", "/bin/sh", ["-c", "if grep -q 'keep.nonce=' /proc/cmdline; then exit 94; else echo 'ok 1 - nonce-private'; fi"]));
if (!checks.at(-1).receipt?.guestResult.stdout.includes("ok 1 - nonce-private")) throw new Error("attempt nonce remained visible on the global kernel command line");

checks.push(await invoke("output-exhaustion-emits-authenticated-adverse-frame", "/bin/sh", ["-c", "dd if=/dev/zero bs=1048576 count=32 >&1 2>/dev/null; exit 0"], { maxOutputBytes: 4096 }));
if (!checks.at(-1).receipt || checks.at(-1).receipt.guestResult.exitCode !== 125 || checks.at(-1).result.results.some((row) => row.passed)) {
  throw new Error("guest output exhaustion suppressed or forged the trusted adverse frame");
}

checks.push(await invoke("measurement-substitution-refused", "/bin/true", [], {
  trustedMeasurements: { ...trustedMeasurements, kernelSha256: "0".repeat(64) },
}));
if (checks.at(-1).receipt !== null || !/measurement mismatch: kernelSha256/.test(checks.at(-1).result.runnerError ?? "")) throw new Error("measurement substitution did not refuse before launch");

checks.push(await invoke("timeout-kills-without-receipt", "/bin/sleep", ["30"], { timeoutMs: 1_000 }));
const timeout = checks.at(-1);
if (timeout.receipt !== null || !/exceeded 1000ms/.test(timeout.result.runnerError ?? "")) throw new Error("timeout did not fail closed without a receipt");

for (const check of checks.slice(0, 8)) {
  if (!check.receipt || check.result.runnerError || !check.receipt.teardownClean) throw new Error(`${check.id} lacked a clean real-run receipt`);
}
const recursiveDirectoryMatches = (base, match, prefix = "") => {
  const rows = [];
  for (const entry of readdirSync(base, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (match(relativePath)) rows.push(relativePath);
    rows.push(...recursiveDirectoryMatches(resolve(base, entry.name), match, relativePath));
  }
  return rows;
};
const cgroupResidue = recursiveDirectoryMatches("/sys/fs/cgroup/keep", (path) => path.split("/").some((part) => part.startsWith("keep-")));
if (cgroupResidue.length) throw new Error(`hostile suite left cgroup residue: ${cgroupResidue}`);
const uidLeaseResidue = readdirSync(resolve(workRoot, ".uid-leases"), { withFileTypes: true }).filter((entry) => entry.isFile()).map((entry) => entry.name);
if (uidLeaseResidue.length) throw new Error(`hostile suite left UID lease residue: ${uidLeaseResidue}`);
const evidence = {
  schema: "keep.real-firecracker-hostile-evidence/v1",
  capturedAt: new Date().toISOString(),
  repositoryCommit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
  runtimeSubjectManifest: { path: runtimeSubjectManifestPath, sha256: runtimeSubjectManifestSha256 },
  checks,
  residue: { cgroupResidue, uidLeaseResidue, clean: true },
  limitations: ["These checks prove the named host mechanisms, not exhaustive VMM escape resistance or semantic correctness."],
};
mkdirSync(dirname(output), { recursive: true });
const temporary = `${output}.tmp-${process.pid}`;
const fd = openSync(temporary, "wx", 0o600);
try { writeFileSync(fd, `${JSON.stringify(evidence, null, 2)}\n`, "utf8"); fsyncSync(fd); } finally { closeSync(fd); }
renameSync(temporary, output);
const dirFd = openSync(dirname(output), "r");
try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
console.log(JSON.stringify({ output, checks: checks.map((check) => ({ id: check.id, receipt: check.receipt !== null, runnerError: check.result.runnerError ?? null })), status: "PASS" }));
