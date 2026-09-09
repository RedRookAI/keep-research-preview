#!/usr/bin/env node
/** Capture one durable, real Firecracker+jailer execution receipt on the current repository bytes. */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { computeMicrovmProjectSourceManifestSha256, detectMicrovmRuntime, loadVerifiedMicrovmMeasurementPolicyAuthority, verifiedMicrovmMeasurementPolicyAuthorityDigest, verifiedMicrovmRunReceipt } from "../dist/src/infra/microvm_boundary.js";
import { selectExecutor } from "../dist/src/isolation/isolated_executor.js";
import { createRunAttestationChannel } from "../dist/src/isolation/isolation_attestation.js";

const root = resolve(new URL("..", import.meta.url).pathname);
// A published tool must not silently select the maintainer's host or old evidence.
// Resolve all required arguments before reading inputs or preparing execution.
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
const output = resolve(root, arg("--output"));
const runtimeSubjectManifestPath = resolve(root, arg("--subject-manifest"));
const policyPath = resolve(root, arg("--policy"));
const signedPolicyPath = resolve(root, arg("--signed-policy"));
const trustRootPath = resolve(root, arg("--trust-root"));
const workRoot = resolve(arg("--work-root"));
const trustedMeasurements = JSON.parse(readFileSync(policyPath, "utf8"));
const measurementPolicyAuthority = loadVerifiedMicrovmMeasurementPolicyAuthority(
  signedPolicyPath,
  trustRootPath,
);
const trustedMeasurementPolicyDigest = verifiedMicrovmMeasurementPolicyAuthorityDigest(measurementPolicyAuthority);
const runtimeSubjectManifestBytes = readFileSync(runtimeSubjectManifestPath);
const runtimeSubjectManifest = JSON.parse(runtimeSubjectManifestBytes.toString("utf8"));
if (runtimeSubjectManifest.schema !== "keep.runtime-subject-manifest/v1" || !Array.isArray(runtimeSubjectManifest.files)) throw new Error("runtime subject manifest is malformed");
for (const row of runtimeSubjectManifest.files) {
  if (typeof row?.path !== "string" || typeof row?.sha256 !== "string" || createHash("sha256").update(readFileSync(resolve(root, row.path))).digest("hex") !== row.sha256) {
    throw new Error(`runtime subject drift: ${String(row?.path)}`);
  }
}
const runtimeSubjectManifestSha256 = createHash("sha256").update(runtimeSubjectManifestBytes).digest("hex");

const spec = {
  projectDir: root,
  kernelImage: kernel,
  rootfsImage: rootfs,
  command: "/bin/echo",
  args: ["ok 1 - real-firecracker-jailer"],
  memoryBytes: 256 * 1024 * 1024,
  maxFileSizeBytes: 64 * 1024 * 1024,
  maxProcesses: 128,
  timeoutMs: 120_000,
  maxOutputBytes: 1024 * 1024,
  vmmBin: vmm,
  jailerBin: jailer,
  guestInitPath: resolve(root, "assets/microvm/keep-init"),
  workRoot, trustedMeasurements,
};
const runtime = detectMicrovmRuntime(true, { vmmBin: vmm, jailerBin: jailer });
if (!runtime.available || runtime.kind !== "firecracker") throw new Error(`unstubbed detector refused the pinned runtime: ${runtime.detail}`);
const relativeDetection = detectMicrovmRuntime(true, { vmmBin: basename(vmm), jailerBin: basename(jailer) });
if (relativeDetection.available) throw new Error("PATH-relative runtime unexpectedly passed trusted detection");
const mismatchedDetection = detectMicrovmRuntime(true, { vmmBin: vmm, jailerBin: "/usr/bin/true" });
if (mismatchedDetection.available) throw new Error("version-mismatched runtime unexpectedly passed detection");
mkdirSync(workRoot, { recursive: true, mode: 0o700 });
const symlinkProbe = resolve(workRoot, `.vmm-symlink-probe-${process.pid}`);
symlinkSync(vmm, symlinkProbe);
let symlinkDetection;
try { symlinkDetection = detectMicrovmRuntime(true, { vmmBin: symlinkProbe, jailerBin: jailer }); }
finally { unlinkSync(symlinkProbe); }
if (symlinkDetection.available) throw new Error("symlink runtime unexpectedly passed trusted detection");
const executor = selectExecutor(
  { kvmAvailable: true, gvisorAvailable: false, containerRuntime: false, canScopeProcess: true },
  { microvm: spec },
);
if (executor.tier !== "microvm") throw new Error(`installed selector chose ${executor.tier}, not microvm`);
const outcome = await executor.runIsolated({ run: async () => { throw new Error("host runner must not execute outside guest"); } }, { projectDir: root, repoRef: ".", patchRisk: "high" });
if (!outcome.executed || !outcome.result) throw new Error(`installed executor refused: ${outcome.refusedReason ?? "unknown"}`);
const result = outcome.result;
const receipt = verifiedMicrovmRunReceipt(result);
if (!receipt) throw new Error(`real Firecracker receipt absent: ${result.runnerError ?? JSON.stringify(result)}`);
const independentlyRecomputedProjectManifest = await computeMicrovmProjectSourceManifestSha256(root);
if (receipt.projectSourceManifestSha256 !== independentlyRecomputedProjectManifest) {
  throw new Error(`real Firecracker receipt did not bind the current project bytes: receipt=${receipt.projectSourceManifestSha256} recomputed=${independentlyRecomputedProjectManifest}`);
}
if (result.runnerError || result.results.length !== 1 || !result.results[0]?.passed) {
  throw new Error(`real Firecracker fixture did not pass exactly once: ${JSON.stringify(result)}`);
}
const channel = createRunAttestationChannel({ trustedMicrovmMeasurementPolicyDigests: [trustedMeasurementPolicyDigest] });
const crossProjectAttestation = executor.attest?.(channel.attestor, "/tmp", Date.now());
const crossProjectVerification = channel.verifier.verify(crossProjectAttestation);
if (crossProjectVerification.ok || crossProjectVerification.verifiedTier !== "none") throw new Error("cross-project receipt substitution was accepted");
const mismatchedPolicyChannel = createRunAttestationChannel({ trustedMicrovmMeasurementPolicyDigests: ["0".repeat(64)] });
const mismatchedPolicyAttestation = executor.attest?.(mismatchedPolicyChannel.attestor, root, Date.now());
const mismatchedPolicyVerification = mismatchedPolicyChannel.verifier.verify(mismatchedPolicyAttestation);
if (mismatchedPolicyVerification.ok || mismatchedPolicyVerification.verifiedTier !== "none") throw new Error("runner policy not admitted by independent verifier trust was accepted");
const attestation = executor.attest?.(channel.attestor, root, Date.now());
const authorityVerification = channel.verifier.verify(attestation);
if (!authorityVerification.ok || authorityVerification.verifiedTier !== "microvm") throw new Error(`real receipt did not enable microVM authority: ${JSON.stringify(authorityVerification)}`);
const replayVerification = channel.verifier.verify(attestation);
if (replayVerification.ok || replayVerification.verifiedTier !== "none") throw new Error("microVM receipt replay was accepted");

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
const cgroupResidue = recursiveDirectoryMatches("/sys/fs/cgroup/keep", (path) => path.includes(receipt.attemptNonce));
const jailParent = resolve(workRoot, basename(vmm));
const jailResidue = readdirSync(jailParent, { withFileTypes: true }).filter((entry) => entry.name.includes(receipt.attemptNonce)).map((entry) => entry.name);
if (cgroupResidue.length || jailResidue.length) throw new Error(`runtime residue remained: cgroup=${cgroupResidue} jail=${jailResidue}`);

const canonicalReceipt = `${JSON.stringify(receipt)}\n`;
const evidence = {
  schema: "keep.real-firecracker-host-evidence/v1",
  capturedAt: new Date().toISOString(),
  repositoryCommit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
  runtimeSubjectManifest: { path: runtimeSubjectManifestPath, sha256: runtimeSubjectManifestSha256 },
  host: {
    platform: process.platform,
    arch: process.arch,
    kernelRelease: execFileSync("uname", ["-r"], { encoding: "utf8" }).trim(),
    kvm: { path: "/dev/kvm", characterDevice: statSync("/dev/kvm").isCharacterDevice() },
  },
  invocation: { vmm, jailer, kernel, rootfs, noNetworkInterface: true, jailerRequired: true, defaultSeccomp: true },
  negativeDetection: { relativeDetection, mismatchedDetection, symlinkDetection },
  receipt,
  independentlyRecomputedProjectManifest,
  receiptDigest: createHash("sha256").update("keep.verified-microvm-run-receipt/v1\0").update(canonicalReceipt).digest("hex"),
  result,
  authorityVerification,
  crossProjectVerification,
  mismatchedPolicyVerification,
  replayVerification,
  residue: { cgroupResidue, jailResidue, clean: true },
};

mkdirSync(dirname(output), { recursive: true });
const temporary = `${output}.tmp-${process.pid}`;
const fd = openSync(temporary, "wx", 0o600);
try {
  writeFileSync(fd, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  fsyncSync(fd);
} finally { closeSync(fd); }
renameSync(temporary, output);
const dirFd = openSync(dirname(output), "r");
try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
console.log(JSON.stringify({ output, receiptDigest: evidence.receiptDigest, attemptNonce: receipt.attemptNonce, status: "PASS" }));
