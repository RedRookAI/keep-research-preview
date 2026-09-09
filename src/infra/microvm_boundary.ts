/**
 * BUILD-ORDER 1.3b (BIND-MICROVM-TIER-BOUNDARY) — the TOP-tier boundary that runs the untrusted test
 * PROCESS behind the SAME `IsolatedExecutor`/`BoundaryExecutor` port round 1.3/1.3c established, but
 * enforced by a dedicated GUEST KERNEL inside a Firecracker (else Cloud Hypervisor) microVM — a HARDWARE
 * boundary (KVM), not a shared-kernel namespace/container.
 *
 * It proves the EXACT default-path containment contract one tier up from the container:
 *   - a child cannot write outside the project on the filesystem — the rootfs drive is READ-ONLY and ONLY
 *     the project data disk is attached read-write (no arbitrary host-FS passthrough; the minimal virtio
 *     device model IS the jail);
 *   - a child cannot reach the network — NO virtio-net device is attached (egress denied at the device
 *     level, not a firewall rule that can be misconfigured — there is simply no NIC);
 *   - a child is resource-bounded — `fsize`/`pids` rlimits AND, the bound the weaker tiers could not
 *     deliver cleanly, a HARD guest-RAM cap (`mem_size_mib`) that OOM-kills a memory bomb inside the guest
 *     and never touches the host (round 1.3 FILED this: RLIMIT_AS killed Node at startup; `--memory` cgroup
 *     accounting was unreliable in-env — a guest with a fixed RAM allotment bounds memory cleanly).
 * The hardening is the hard default; `allowNet`/`allowWritePaths` are opt-IN operator allowances (additive,
 * never a weakened default) — mirroring the namespace floor and the container tier exactly.
 *
 * COMPOSED, not forked: this builds a `boundaryRun` closure that plugs into the EXISTING `BoundaryExecutor`
 * (isolated_executor.ts) — one executor port, not two. Detect-and-select is honest: `detectMicrovmRuntime`
 * MEASURES what is really present (a `/dev/kvm` char device + a firecracker/cloud-hypervisor binary), and
 * `selectExecutor` only claims the microvm tier when a real boundary + a built kernel/rootfs back it.
 *
 * SOTA basis (2026-08-15, quotes/URLs in redrook-ops/.round-artifacts/BIND-MICROVM-TIER-BOUNDARY/sota.txt):
 *  - Firecracker = hardware-enforced microVM; "an untrusted workload talks to its own guest kernel,
 *    separated from the host by CPU virtualization ... escape both the guest kernel AND break out of the VM."
 *  - "Deliberately minimal with only virtio-net, virtio-block, a serial console ... no BIOS, PCI, or USB" —
 *    so omitting virtio-net = no NIC = egress denied; the project reaches the guest via a virtio-block disk.
 *  - The microVM TAX / DISCONFIRMING CASE: needs Linux + `/dev/kvm`; a built guest kernel + rootfs must
 *    exist. A KVM-less host or a run with no rootfs cannot boot → route to a weaker-but-honest tier, never a
 *    false pass. A boundary run that cannot COMPLETE surfaces a runnerError, never a false green.
 *
 * Zero runtime deps (node:child_process / node:fs / node:os / node:path only).
 */

import { execFileSync, spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import {
  chmodSync, chownSync, closeSync, constants, cpSync, createReadStream, existsSync, fstatSync, lchownSync, lstatSync,
  mkdirSync, mkdtempSync, opendirSync, openSync, readFileSync, readlinkSync, readdirSync, realpathSync, renameSync, rmSync, statSync,
  truncateSync, unlinkSync, writeFileSync, rmdirSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { types } from "node:util";
import type { TestRunner, TestRunResult, TestCaseResult } from "../solve/validate.js";
import { ProcessIsolationAdapter, resolvedWithinProject } from "./process_isolation.js";
import { parseTap } from "../solve/sandboxed_runner.js";
import type { ExecutionSpec } from "../isolation/isolated_executor.js";
import type { IsolationTier } from "../isolation/isolation_tier.js";
import {
  DEFAULT_MICROVM_FRAME_LIMITS, mintMicrovmAttemptNonce, mintMicrovmResultAuthenticationKey, parseMicrovmGuestFrame,
  type MicrovmGuestResult,
} from "./microvm_guest_protocol.js";
import {
  containmentDecision, type ContainmentContract, type RequestedEffect,
} from "./container_boundary.js";

/** Which microVM VMM backs the boundary. `firecracker` is preferred; `cloud-hypervisor` is the alternate. */
export type MicrovmRuntimeKind = "firecracker" | "cloud-hypervisor" | "none";

/** Detected/declared microVM runtime — measured, never assumed. `available` gates any tier claim. */
export interface MicrovmRuntimeInfo {
  readonly kind: MicrovmRuntimeKind;
  /** True iff `/dev/kvm` is a real char device AND a VMM binary (firecracker/cloud-hypervisor) is present. */
  readonly available: boolean;
  /** The isolation tier this runtime provides. "microvm" when usable; "none" otherwise. */
  readonly tier: IsolationTier;
  /** Recorded separately from `available`: a KVM-present-but-no-VMM host degrades honestly (not a claim). */
  readonly kvmPresent: boolean;
  /** Honest one-line description of what was measured (never a false claim). */
  readonly detail: string;
  /** Exact measured executables when Firecracker is usable. */
  readonly vmmPath?: string;
  readonly jailerPath?: string;
}

/**
 * The microVM boundary spec — a HARD default (net-denied via no NIC, filesystem-jailed to the project data
 * disk over a read-only rootfs, resource-bounded incl. a hard guest-RAM cap). `allowNet`/`allowWritePaths`
 * are opt-IN allowances, additive.
 */
export interface MicrovmBoundarySpec {
  /** The project dir — attached as the SINGLE read-write virtio-block DATA disk into the guest. */
  readonly projectDir: string;
  /** The guest kernel image (vmlinux). A legitimate run needs a built kernel — absent → route down. */
  readonly kernelImage: string;
  /** The guest rootfs image — attached READ-ONLY (the fs-jail: a write outside the data disk hits ro rootfs). */
  readonly rootfsImage: string;
  /** The test command (argv[0]) run INSIDE the guest. */
  readonly command: string;
  /** Command args, passed as argv (shell metacharacters inert — the same argument-injection defense). */
  readonly args: readonly string[];
  /** The HARD guest-RAM cap (bytes). Fixed `mem_size_mib` — a memory bomb OOMs in-guest. The NEW bound. */
  readonly memoryBytes: number;
  /** Operator opt-IN: attach a virtio-net device (skip the no-NIC default). Default false → network-DENIED. */
  readonly allowNet?: boolean;
  /** Operator opt-IN: extra absolute paths attached as additional rw data disks. Default: only the project. */
  readonly allowWritePaths?: readonly string[];
  /** RLIMIT_FSIZE (bytes) inside the guest — bounds a disk bomb; bites cleanly (SIGXFSZ). */
  readonly maxFileSizeBytes?: number;
  /** RLIMIT_NPROC inside the guest — bounds process count (fork-bomb defense). */
  readonly maxProcesses?: number;
  /** Guest vCPU count. Default 1. */
  readonly vcpuCount?: number;
  /** Wall-clock timeout (ms). Default 60s. */
  readonly timeoutMs?: number;
  /** Captured-output cap (bytes). Default 1 MiB. */
  readonly maxOutputBytes?: number;
  /** The VMM binary to spawn. Default: "firecracker" (or "cloud-hypervisor" per the detected runtime). */
  readonly vmmBin?: string;
  /** Matching Firecracker jailer. Required for a production receipt; direct VMM execution never earns one. */
  readonly jailerBin?: string;
  /** Root-owned, non-user-writable base for per-attempt jails. Default `/var/lib/keep/microvm`. */
  readonly workRoot?: string;
  /** Trusted guest supervisor installed into the disposable rootfs for this attempt. */
  readonly guestInitPath?: string;
  /** Root-owned absolute image-construction tools; defaults are the deployed Linux paths. */
  readonly debugfsBin?: string;
  readonly mke2fsBin?: string;
  readonly e2fsckBin?: string;
  /** Release-policy measurements. Production authority refuses absent or mismatched pins. */
  readonly trustedMeasurements?: TrustedMicrovmMeasurements;
  /** Injectable adapter (tests). Default: a fresh ProcessIsolationAdapter (spawns the VMM, no double-jail). */
  readonly adapter?: ProcessIsolationAdapter;
}

export interface TrustedMicrovmMeasurements {
  readonly schema: "keep.trusted-microvm-measurements/v1";
  readonly vmmSha256: string;
  readonly jailerSha256: string;
  readonly kernelSha256: string;
  readonly baseRootfsSha256: string;
  readonly guestSupervisorSha256: string;
  readonly debugfsSha256: string;
  readonly mke2fsSha256: string;
  readonly e2fsckSha256: string;
}

/** Signed release-policy carrier appraised independently of the boundary spec that consumes it. */
export interface SignedMicrovmMeasurementPolicy {
  readonly schema: "keep.signed-microvm-measurement-policy/v1";
  readonly keyId: string;
  readonly policy: TrustedMicrovmMeasurements;
  readonly signature: string;
}

export interface MicrovmMeasurementPolicyTrustRoot {
  readonly schema: "keep.microvm-measurement-policy-trust-root/v1";
  readonly keyId: string;
  readonly publicKeyPem: string;
}

const VERIFIED_MICROVM_POLICY_AUTHORITY = Symbol("keep.verified-microvm-policy-authority");
export interface VerifiedMicrovmMeasurementPolicyAuthority {
  readonly keyId: string;
  readonly policyDigest: string;
  readonly signedPolicyPath: string;
  readonly trustRootPath: string;
  readonly [VERIFIED_MICROVM_POLICY_AUTHORITY]: true;
}

/** The Firecracker VMM machine config — the containment contract expressed as guest hardware. */
export interface MicrovmMachineConfig {
  readonly "boot-source": { readonly kernel_image_path: string; readonly boot_args: string };
  readonly drives: ReadonlyArray<{
    readonly drive_id: string;
    readonly path_on_host: string;
    readonly is_root_device: boolean;
    readonly is_read_only: boolean;
  }>;
  readonly "machine-config": { readonly vcpu_count: number; readonly mem_size_mib: number };
  /** Present ONLY on the `allowNet` opt-in. Absent by default → the guest has NO NIC → egress denied. */
  readonly "network-interfaces"?: ReadonlyArray<{ readonly iface_id: string; readonly host_dev_name: string }>;
}

/** A planned microVM boot: the VMM argv + the machine config + any control the VMM could not enforce. */
export interface MicrovmRunPlan {
  readonly cmd: string;
  readonly args: readonly string[];
  readonly config: MicrovmMachineConfig;
  readonly degraded: readonly string[];
}

/** Verifier-owned evidence that one exact guest invocation completed through the real boundary. */
export interface VerifiedMicrovmRunReceipt {
  readonly schema: "keep.verified-microvm-run-receipt/v3";
  readonly runtimeKind: Exclude<MicrovmRuntimeKind, "none">;
  readonly attemptNonce: string;
  readonly projectDir: string;
  readonly executionSpecSha256: string;
  /** Canonical command/argv and enforced boundary-policy identity actually installed in the guest. */
  readonly guestExecutionRequestSha256: string;
  readonly guestRequestScriptSha256: string;
  /** Read back from the constructed project image, not inferred from the caller's command object. */
  readonly installedGuestRequestScriptSha256: string;
  readonly startedAt: string;
  readonly durationMs: number;
  readonly jailerSha256: string;
  readonly vmmSha256: string;
  readonly kernelSha256: string;
  readonly guestSupervisorSha256: string;
  /** Read back from the constructed rootfs, not inferred from the source carrier. */
  readonly installedGuestSupervisorSha256: string;
  readonly debugfsSha256: string;
  readonly mke2fsSha256: string;
  readonly e2fsckSha256: string;
  readonly baseRootfsSha256: string;
  readonly rootfsSha256: string;
  /** Canonical source-tree identity before disposable ext4 packaging. */
  readonly projectSourceManifestSha256: string;
  readonly projectImageSha256: string;
  readonly configSha256: string;
  readonly jailerArgsSha256: string;
  readonly serialSha256: string;
  readonly jailerStderrSha256: string;
  readonly vmmExitCode: number;
  readonly jailUid: number;
  readonly jailGid: number;
  readonly measuredCgroupMemoryMax: string;
  readonly measuredCgroupPidsMax: string;
  /** Domain-separated canonical verifier policy identity, not the source carrier's file digest. */
  readonly measurementPolicyCanonicalSha256: string;
  readonly testRunResultSha256: string;
  readonly guestResult: MicrovmGuestResult;
  readonly teardownClean: true;
  readonly degraded: readonly string[];
}

const VERIFIED_MICROVM_RECEIPT = Symbol("keep.verified-microvm-run-receipt");
type ReceiptBearingResult = TestRunResult & { readonly [VERIFIED_MICROVM_RECEIPT]?: VerifiedMicrovmRunReceipt };
const LIVE_RECEIPTS = new Map<string, {
  readonly projectDir: string;
  readonly executionSpecSha256: string;
  readonly guestExecutionRequestSha256: string;
  readonly projectSourceManifestSha256: string;
  readonly testRunResultSha256: string;
  readonly issuedAtMs: number;
}>();
const LIVE_RECEIPT_TTL_MS = 5 * 60_000;
const MAX_LIVE_RECEIPTS = 256;

function purgeExpiredLiveReceipts(now = Date.now()): void {
  for (const [digest, receipt] of LIVE_RECEIPTS) if (now - receipt.issuedAtMs > LIVE_RECEIPT_TTL_MS) LIVE_RECEIPTS.delete(digest);
}

function canonicalReceiptDigest(receipt: VerifiedMicrovmRunReceipt): string {
  return createHash("sha256")
    .update("keep.verified-microvm-run-receipt/v3\0")
    .update(`${JSON.stringify(receipt)}\n`)
    .digest("hex");
}

/** Only this module can attach the private-symbol receipt; ordinary/injected boundary results cannot forge it. */
export function verifiedMicrovmRunReceipt(result: TestRunResult): VerifiedMicrovmRunReceipt | undefined {
  return (result as ReceiptBearingResult)[VERIFIED_MICROVM_RECEIPT];
}

export function verifiedMicrovmRunReceiptDigest(receipt: VerifiedMicrovmRunReceipt): string {
  return canonicalReceiptDigest(receipt);
}

export function trustedMicrovmMeasurementPolicyDigest(policy: TrustedMicrovmMeasurements): string {
  return domainDigest("keep.trusted-microvm-measurements/v1", captureTrustedMeasurements(policy));
}

export function microvmMeasurementPolicySignaturePreimage(policy: TrustedMicrovmMeasurements): Buffer {
  return Buffer.from(`keep.signed-microvm-measurement-policy/v1\0${JSON.stringify(captureTrustedMeasurements(policy))}\n`, "utf8");
}

/** Verify a separately-held Ed25519 release policy before it enters the run-local appraisal channel. */
export function verifySignedMicrovmMeasurementPolicy(
  signed: SignedMicrovmMeasurementPolicy,
  trust: MicrovmMeasurementPolicyTrustRoot,
): string {
  if (signed.schema !== "keep.signed-microvm-measurement-policy/v1" ||
      trust.schema !== "keep.microvm-measurement-policy-trust-root/v1" ||
      signed.keyId !== trust.keyId || !/^[A-Za-z0-9._-]{1,128}$/.test(signed.keyId)) {
    throw new Error("signed microVM measurement policy identity is invalid");
  }
  const key = createPublicKey(trust.publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("microVM measurement policy trust key is not Ed25519");
  let signature: Buffer;
  try { signature = Buffer.from(signed.signature, "base64"); } catch { throw new Error("microVM measurement policy signature is not base64"); }
  if (signature.length !== 64 || !cryptoVerify(null, microvmMeasurementPolicySignaturePreimage(signed.policy), key, signature)) {
    throw new Error("microVM measurement policy signature verification failed");
  }
  return trustedMicrovmMeasurementPolicyDigest(signed.policy);
}

/** Load authority only from separately pinned root-owned files; caller-authored objects cannot mint the brand. */
export function loadVerifiedMicrovmMeasurementPolicyAuthority(
  signedPolicyPath: string,
  trustRootPath: string,
): VerifiedMicrovmMeasurementPolicyAuthority {
  const signedPath = assertTrustedRegular(signedPolicyPath, "signed microVM measurement policy");
  const rootPath = assertTrustedRegular(trustRootPath, "microVM measurement policy trust root");
  const signed = JSON.parse(readFileSync(signedPath, "utf8")) as SignedMicrovmMeasurementPolicy;
  const trust = JSON.parse(readFileSync(rootPath, "utf8")) as MicrovmMeasurementPolicyTrustRoot;
  if (Object.keys(signed).sort().join("\0") !== ["keyId", "policy", "schema", "signature"].join("\0") ||
      Object.keys(trust).sort().join("\0") !== ["keyId", "publicKeyPem", "schema"].join("\0")) {
    throw new Error("microVM signed policy/trust-root fields are not exact");
  }
  return Object.freeze({
    keyId: signed.keyId,
    policyDigest: verifySignedMicrovmMeasurementPolicy(signed, trust), signedPolicyPath: signedPath, trustRootPath: rootPath,
    [VERIFIED_MICROVM_POLICY_AUTHORITY]: true as const,
  });
}

export function verifiedMicrovmMeasurementPolicyAuthorityDigest(authority: VerifiedMicrovmMeasurementPolicyAuthority): string {
  if (authority[VERIFIED_MICROVM_POLICY_AUTHORITY] !== true || !/^[A-Za-z0-9._:-]{1,128}$/.test(authority.keyId) || !/^[0-9a-f]{64}$/.test(authority.policyDigest)) {
    throw new Error("microVM measurement policy authority is not verifier-owned");
  }
  return authority.policyDigest;
}

/** Recompute the exact returned result identity; callers must join it to the private receipt before use. */
export function verifiedMicrovmTestRunResultDigest(result: TestRunResult): string {
  return exactTestRunResultDigest({ results: result.results, ...(result.runnerError === undefined ? {} : { runnerError: result.runnerError }) });
}

/** One-time verifier join: a digest is useful only for the exact project and only once. */
export function consumeVerifiedMicrovmRunReceiptDigest(
  digest: string,
  projectDir: string,
  executionSpecSha256: string,
  guestExecutionRequestSha256: string,
  projectSourceManifestSha256: string,
  testRunResultSha256: string,
): boolean {
  purgeExpiredLiveReceipts();
  const entry = LIVE_RECEIPTS.get(digest);
  if (!entry) return false;
  let actual: string;
  try { actual = realpathSync(projectDir); } catch { return false; }
  if (actual !== entry.projectDir || executionSpecSha256 !== entry.executionSpecSha256 || guestExecutionRequestSha256 !== entry.guestExecutionRequestSha256 ||
      projectSourceManifestSha256 !== entry.projectSourceManifestSha256 || testRunResultSha256 !== entry.testRunResultSha256) return false;
  LIVE_RECEIPTS.delete(digest);
  return true;
}

function attachVerifiedMicrovmRunReceipt(result: TestRunResult, receipt: VerifiedMicrovmRunReceipt): TestRunResult {
  purgeExpiredLiveReceipts();
  if (LIVE_RECEIPTS.size >= MAX_LIVE_RECEIPTS) {
    const refused: TestRunResult = {
      results: result.results,
      runnerError: `completed microVM result cannot authorize: live receipt registry capacity ${MAX_LIVE_RECEIPTS} is exhausted`,
    };
    for (const row of refused.results) Object.freeze(row);
    Object.freeze(refused.results);
    return Object.freeze(refused);
  }
  LIVE_RECEIPTS.set(canonicalReceiptDigest(receipt), {
    projectDir: receipt.projectDir,
    executionSpecSha256: receipt.executionSpecSha256,
    guestExecutionRequestSha256: receipt.guestExecutionRequestSha256,
    projectSourceManifestSha256: receipt.projectSourceManifestSha256,
    testRunResultSha256: receipt.testRunResultSha256,
    issuedAtMs: Date.now(),
  });
  Object.defineProperty(result, VERIFIED_MICROVM_RECEIPT, { value: Object.freeze(receipt), enumerable: false, writable: false, configurable: false });
  for (const row of result.results) Object.freeze(row);
  Object.freeze(result.results);
  return Object.freeze(result);
}

function sha256Bytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function domainDigest(domain: string, value: unknown): string {
  return sha256Bytes(Buffer.from(`${domain}\0${JSON.stringify(value)}\n`, "utf8"));
}

function exactExecutionSpecDigest(spec: ExecutionSpec, guestExecutionRequestSha256: string): string {
  return domainDigest("keep.microvm-execution-spec/v2", {
    projectDir: realpathSync(spec.projectDir), repoRef: spec.repoRef, patchRisk: spec.patchRisk, guestExecutionRequestSha256,
  });
}

interface CapturedMicrovmGuestExecutionRequest {
  readonly command: string; readonly args: readonly string[]; readonly requestScript: Buffer;
  readonly requestScriptSha256: string; readonly memoryBytes: number; readonly allowNet: boolean;
  readonly allowWritePaths: readonly string[]; readonly maxFileSizeBytes: number; readonly maxProcesses: number;
  readonly vcpuCount: number; readonly timeoutMs: number; readonly maxOutputBytes: number;
}

function captureDenseStringArray(value: unknown, label: string, maxCount: number): readonly string[] {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new Error(`${label} must be a plain array`);
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>;
  const length = descriptors["length"]?.value as unknown;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0 || length > maxCount) throw new Error(`${label} length exceeds its bound`);
  const allowed = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string" || !allowed.has(key))) throw new Error(`${label} contains sparse, accessor, symbol, or extra fields`);
  const captured: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "string" || descriptor.value.includes("\0") || Buffer.byteLength(descriptor.value) > 64 * 1024) throw new Error(`${label} contains a malformed or oversized string`);
    captured.push(descriptor.value);
  }
  return Object.freeze(captured);
}

function captureMicrovmGuestExecutionRequest(spec: MicrovmBoundarySpec): CapturedMicrovmGuestExecutionRequest {
  if (!spec || typeof spec !== "object" || types.isProxy(spec)) throw new Error("microVM boundary spec must be an inert object");
  const descriptor = (key: keyof MicrovmBoundarySpec): unknown => {
    const row = Object.getOwnPropertyDescriptor(spec, key);
    if (!row) return undefined;
    if (!("value" in row)) throw new Error(`microVM boundary spec ${key} must be an own data field`);
    return row.value;
  };
  const command = descriptor("command"); const args = captureDenseStringArray(descriptor("args"), "microVM guest argv", 4096);
  if (typeof command !== "string" || command.length < 1 || command.includes("\0") || Buffer.byteLength(command) > 64 * 1024) throw new Error("microVM guest command/argv is malformed or exceeds its bound");
  const numberField = (key: keyof MicrovmBoundarySpec, fallback: number, min: number, max: number): number => {
    const value = descriptor(key) ?? fallback;
    if (!Number.isSafeInteger(value) || Number(value) < min || Number(value) > max) throw new Error(`microVM ${key} must be an integer in ${min}..${max}`);
    return Number(value);
  };
  const allowNetValue = descriptor("allowNet");
  if (allowNetValue !== undefined && typeof allowNetValue !== "boolean") throw new Error("microVM allowNet must be boolean");
  const allowWritePathsValue = descriptor("allowWritePaths");
  const allowWritePaths = allowWritePathsValue === undefined ? Object.freeze([] as string[]) : captureDenseStringArray(allowWritePathsValue, "microVM allowWritePaths", 128);
  const requestScript = Buffer.from(`#!/bin/sh\nexec ${[command, ...args].map(shellQuote).join(" ")}\n`, "utf8");
  return Object.freeze({
    command, args, requestScript, requestScriptSha256: sha256Bytes(requestScript),
    memoryBytes: numberField("memoryBytes", 256 * 1024 * 1024, 64 * 1024 * 1024, 16 * 1024 * 1024 * 1024),
    allowNet: allowNetValue ?? false, allowWritePaths,
    maxFileSizeBytes: numberField("maxFileSizeBytes", 256 * 1024 * 1024, 1, 4 * 1024 * 1024 * 1024),
    maxProcesses: numberField("maxProcesses", 256, 1, 65_535),
    vcpuCount: numberField("vcpuCount", 1, 1, 32),
    timeoutMs: numberField("timeoutMs", 60_000, 1_000, 24 * 60 * 60_000),
    maxOutputBytes: numberField("maxOutputBytes", DEFAULT_MICROVM_FRAME_LIMITS.maxStreamBytes, 1, 4 * 1024 * 1024),
  });
}

/** Bind what the guest executes and every caller-selected limit that changes its authority envelope. */
function capturedMicrovmGuestExecutionRequestDigest(captured: CapturedMicrovmGuestExecutionRequest): string {
  return domainDigest("keep.microvm-guest-execution-request/v2", {
    command: captured.command, args: captured.args, requestScriptSha256: captured.requestScriptSha256,
    memoryBytes: captured.memoryBytes, allowNet: captured.allowNet, allowWritePaths: captured.allowWritePaths,
    maxFileSizeBytes: captured.maxFileSizeBytes, maxProcesses: captured.maxProcesses, vcpuCount: captured.vcpuCount,
    timeoutMs: captured.timeoutMs, maxOutputBytes: captured.maxOutputBytes,
  });
}
export function microvmGuestExecutionRequestDigest(spec: MicrovmBoundarySpec): string {
  return capturedMicrovmGuestExecutionRequestDigest(captureMicrovmGuestExecutionRequest(spec));
}

function exactTestRunResultDigest(result: TestRunResult): string {
  return domainDigest("keep.microvm-test-run-result/v1", { results: result.results, ...(result.runnerError === undefined ? {} : { runnerError: result.runnerError }) });
}

function assertTrustedMeasurements(actual: Omit<TrustedMicrovmMeasurements, "schema">, expected: TrustedMicrovmMeasurements | undefined): string {
  if (!expected) throw new Error("trusted Firecracker measurement policy is absent");
  const captured = captureTrustedMeasurements(expected);
  for (const key of ["vmmSha256", "jailerSha256", "kernelSha256", "baseRootfsSha256", "guestSupervisorSha256", "debugfsSha256", "mke2fsSha256", "e2fsckSha256"] as const) {
    if (!/^[0-9a-f]{64}$/.test(captured[key]) || captured[key] !== actual[key]) throw new Error(`trusted Firecracker measurement mismatch: ${key}`);
  }
  return trustedMicrovmMeasurementPolicyDigest(captured);
}

const TRUSTED_MEASUREMENT_KEYS = ["schema", "vmmSha256", "jailerSha256", "kernelSha256", "baseRootfsSha256", "guestSupervisorSha256", "debugfsSha256", "mke2fsSha256", "e2fsckSha256"] as const;
function captureTrustedMeasurements(value: TrustedMicrovmMeasurements): TrustedMicrovmMeasurements {
  if (types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("trusted Firecracker measurement policy must be an inert plain record");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") ||
      Object.keys(descriptors).sort().join("\0") !== [...TRUSTED_MEASUREMENT_KEYS].sort().join("\0")) {
    throw new Error("trusted Firecracker measurement policy fields are not exact");
  }
  const read = (key: typeof TRUSTED_MEASUREMENT_KEYS[number]): string => {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "string") throw new Error(`trusted Firecracker measurement policy ${key} is not inert text`);
    return descriptor.value;
  };
  const schema = read("schema");
  if (schema !== "keep.trusted-microvm-measurements/v1") throw new Error("trusted Firecracker measurement policy schema is unsupported");
  const captured: TrustedMicrovmMeasurements = {
    schema, vmmSha256: read("vmmSha256"), jailerSha256: read("jailerSha256"),
    kernelSha256: read("kernelSha256"), baseRootfsSha256: read("baseRootfsSha256"), guestSupervisorSha256: read("guestSupervisorSha256"),
    debugfsSha256: read("debugfsSha256"), mke2fsSha256: read("mke2fsSha256"), e2fsckSha256: read("e2fsckSha256"),
  };
  return Object.freeze(captured);
}

async function sha256File(path: string): Promise<string> {
  return await new Promise<string>((resolveDigest, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolveDigest(hash.digest("hex")));
  });
}

function shellQuote(value: string): string {
  if (value.includes("\0") || Buffer.byteLength(value) > 64 * 1024) {
    throw new Error("microVM argv contains NUL or exceeds 64 KiB");
  }
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function assertTrustedRegular(path: string, label: string): string {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute pinned path`);
  const st = lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink()) throw new Error(`${label} must be a non-symlink regular file`);
  if (st.uid !== 0 || (st.mode & 0o022) !== 0) throw new Error(`${label} must be root-owned and not group/other writable`);
  const actual = realpathSync(path);
  for (let cursor = dirname(actual); ; cursor = dirname(cursor)) {
    const ancestor = lstatSync(cursor);
    if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || ancestor.uid !== 0 || (ancestor.mode & 0o022) !== 0) {
      throw new Error(`${label} ancestor is not a root-owned, non-writable directory: ${cursor}`);
    }
    if (cursor === dirname(cursor)) break;
  }
  return actual;
}

function assertTrustedDirectory(path: string, label: string): string {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute pinned path`);
  const actual = realpathSync(path);
  for (let cursor = actual; ; cursor = dirname(cursor)) {
    const st = lstatSync(cursor);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== 0 || (st.mode & 0o022) !== 0) {
      throw new Error(`${label} is not beneath root-owned, non-writable directories: ${cursor}`);
    }
    if (cursor === dirname(cursor)) break;
  }
  return actual;
}

function uidHasLiveProcess(uid: number): boolean {
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try { if (statSync(join("/proc", name)).uid === uid) return true; } catch { /* raced process exit */ }
  }
  return false;
}

interface ProjectManifestRow {
  readonly path: string;
  readonly kind: "file" | "symlink";
  readonly mode: number;
  readonly byteLength: number;
  readonly sha256?: string;
  readonly linkTarget?: string;
}

async function sha256StableManifestFile(path: string, observed: Stats): Promise<string> {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== observed.dev || opened.ino !== observed.ino || opened.mode !== observed.mode || opened.size !== observed.size) {
      throw new Error("microVM project file changed before manifest capture");
    }
    const digest = await new Promise<string>((accept, reject) => {
      const hash = createHash("sha256");
      const stream = createReadStream("", { fd, autoClose: false });
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("error", reject);
      stream.on("end", () => accept(hash.digest("hex")));
    });
    const after = fstatSync(fd);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.mode !== opened.mode || after.size !== opened.size) {
      throw new Error("microVM project file changed during manifest capture");
    }
    return digest;
  } finally { closeSync(fd); }
}

export interface MicrovmProjectManifestLimits {
  readonly maxRows?: number;
  readonly maxTotalFileBytes?: number;
  readonly maxPathBytes?: number;
  readonly maxDepth?: number;
  /** Bound the canonical row carrier before materializing it for hashing. */
  readonly maxManifestBytes?: number;
}

/**
 * Canonical byte manifest used by both the Firecracker receipt and the Git publication join.
 * Repository-control metadata is deliberately excluded: it is not guest input, changes while refs
 * move, and would make the same checked-out source acquire a different execution identity. Everything
 * else beneath the project root—including untracked files and modes—is included, so a clean Git tree
 * is required before this digest can be equated with a commit.
 */
export async function computeMicrovmProjectSourceManifestSha256(root: string, limits: MicrovmProjectManifestLimits = {}): Promise<string> {
  const maxRows = limits.maxRows ?? 100_000;
  const maxTotalFileBytes = limits.maxTotalFileBytes ?? 64 * 1024 * 1024 * 1024;
  const maxPathBytes = limits.maxPathBytes ?? 4096;
  const maxDepth = limits.maxDepth ?? 256;
  const maxManifestBytes = limits.maxManifestBytes ?? 64 * 1024 * 1024;
  for (const [name, value] of Object.entries({ maxRows, maxTotalFileBytes, maxPathBytes, maxDepth, maxManifestBytes })) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`microVM project manifest ${name} must be a positive safe integer`);
  }
  const rows: ProjectManifestRow[] = [];
  let manifestBytes = 3; // '[' + ']' + trailing newline
  const appendRow = (row: ProjectManifestRow): void => {
    const rowBytes = Buffer.byteLength(JSON.stringify(row), "utf8") + (rows.length === 0 ? 0 : 1);
    manifestBytes += rowBytes;
    if (!Number.isSafeInteger(manifestBytes) || manifestBytes > maxManifestBytes) throw new Error("microVM project manifest canonical bytes exceed policy");
    rows.push(row);
  };
  let totalFileBytes = 0;
  const pending: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  while (pending.length > 0) {
    const { dir, depth } = pending.pop()!;
    if (depth > maxDepth) throw new Error("microVM project manifest directory depth exceeds policy");
    const names: string[] = [];
    const handle = opendirSync(dir);
    try {
      for (;;) {
        const entry = handle.readSync();
        if (entry === null) break;
        names.push(entry.name);
        // Directory fan-out is bounded independently of accepted manifest rows. Without this check,
        // millions of excluded/control entries could exhaust memory before the row limit is reached.
        if (names.length > maxRows) throw new Error("microVM project manifest directory entry count exceeds policy");
      }
    } finally { handle.closeSync(); }
    names.sort();
    for (const name of names) {
      if (dir === root && name === ".git") continue;
      const path = join(dir, name);
      const rel = relative(root, path).split(sep).join("/");
      if (Buffer.byteLength(rel, "utf8") > maxPathBytes) throw new Error("microVM project manifest path exceeds policy");
      const st = lstatSync(path);
      const mode = st.isSymbolicLink() ? 0o777 : (st.mode & 0o111) !== 0 ? 0o755 : 0o644;
      if (st.isFile()) {
        if (rows.length >= maxRows) throw new Error("microVM project manifest row count exceeds policy");
        totalFileBytes += st.size;
        if (!Number.isSafeInteger(totalFileBytes) || totalFileBytes > maxTotalFileBytes) throw new Error("microVM project manifest file bytes exceed policy");
        appendRow({ path: rel, kind: "file", mode, byteLength: st.size, sha256: await sha256StableManifestFile(path, st) });
      }
      else if (st.isDirectory()) {
        pending.push({ dir: path, depth: depth + 1 });
      } else if (st.isSymbolicLink()) {
        if (rows.length >= maxRows) throw new Error("microVM project manifest row count exceeds policy");
        const linkTarget = readlinkSync(path);
        if (Buffer.byteLength(linkTarget, "utf8") > maxPathBytes) throw new Error("microVM project manifest symlink target exceeds policy");
        appendRow({ path: rel, kind: "symlink", mode, byteLength: Buffer.byteLength(linkTarget), linkTarget });
      } else throw new Error(`unsupported project filesystem object: ${path}`);
    }
  }
  rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return createHash("sha256")
    .update("keep.microvm-project-source-manifest/v1\0")
    .update(`${JSON.stringify(rows)}\n`)
    .digest("hex");
}

function acquireUidLease(workRoot: string, nonce: string): { uid: number; gid: number; path: string } {
  const leaseRoot = join(workRoot, ".uid-leases");
  mkdirSync(leaseRoot, { recursive: true, mode: 0o700 });
  chmodSync(leaseRoot, 0o700);
  if (lstatSync(leaseRoot).isSymbolicLink() || statSync(leaseRoot).uid !== 0) {
    throw new Error("microVM UID lease root must be a root-owned non-symlink directory");
  }
  const ownerStart = readFileSync(`/proc/${process.pid}/stat`, "utf8").trim().split(/\s+/)[21] ?? "unknown";
  const allocator = join(workRoot, ".uid-allocator-lock");
  try {
    mkdirSync(allocator, { mode: 0o700 });
    writeFileSync(join(allocator, "owner.json"), `${JSON.stringify({ pid: process.pid, start: ownerStart, nonce })}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    let live = true;
    try {
      const owner = JSON.parse(readFileSync(join(allocator, "owner.json"), "utf8")) as { pid: number; start: string };
      live = readFileSync(`/proc/${owner.pid}/stat`, "utf8").trim().split(/\s+/)[21] === owner.start;
    } catch {
      live = Date.now() - statSync(allocator).mtimeMs < 60_000;
    }
    if (live) throw new Error("microVM UID allocator is held by a live transaction");
    const quarantine = join(workRoot, `.uid-allocator-stale-${nonce}`);
    renameSync(allocator, quarantine);
    rmSync(quarantine, { recursive: true, force: true });
    mkdirSync(allocator, { mode: 0o700 });
    writeFileSync(join(allocator, "owner.json"), `${JSON.stringify({ pid: process.pid, start: ownerStart, nonce })}\n`, { flag: "wx", mode: 0o600 });
  }
  try {
    const leaseEntries = readdirSync(leaseRoot, { withFileTypes: true });
    if (leaseEntries.length > 40_000) throw new Error("microVM UID lease directory exceeds its bound");
    for (const entry of leaseEntries) {
      if (!entry.isFile() || !/^(?:2[0-3][0-9]{4})$/.test(entry.name)) throw new Error("microVM UID lease directory contains an invalid entry");
      const uid = Number(entry.name);
      if (uid < 200_000 || uid >= 240_000) throw new Error("microVM UID lease is outside the allocator range");
      const path = join(leaseRoot, entry.name);
      const status = lstatSync(path);
      if (!status.isFile() || status.isSymbolicLink() || status.uid !== 0 || status.nlink !== 1) throw new Error("microVM UID lease must be a root-owned regular single-link file");
      let ownerAlive = true;
      try {
        const prior = JSON.parse(readFileSync(path, "utf8")) as { nonce?: unknown; ownerPid?: unknown; ownerStart?: unknown };
        if (typeof prior.nonce !== "string" || !/^[0-9a-f]{32}$/.test(prior.nonce) || !Number.isSafeInteger(prior.ownerPid) || typeof prior.ownerStart !== "string") {
          throw new Error("malformed lease");
        }
        ownerAlive = readFileSync(`/proc/${prior.ownerPid}/stat`, "utf8").trim().split(/\s+/)[21] === prior.ownerStart;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new Error("microVM UID lease ownership record is malformed");
        ownerAlive = false;
      }
      if (!ownerAlive && !uidHasLiveProcess(uid)) unlinkSync(path);
    }
    const start = Number.parseInt(nonce.slice(0, 8), 16) % 40_000;
    for (let offset = 0; offset < 40_000; offset += 1) {
      const uid = 200_000 + ((start + offset) % 40_000);
      const path = join(leaseRoot, String(uid));
      if (uidHasLiveProcess(uid)) continue;
      try {
        const fd = openSync(path, "wx", 0o600);
        try { writeFileSync(fd, `${JSON.stringify({ nonce, ownerPid: process.pid, ownerStart })}\n`, "utf8"); } finally { closeSync(fd); }
        return { uid, gid: uid, path };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        let ownerAlive = true;
        try {
          const prior = JSON.parse(readFileSync(path, "utf8")) as { ownerPid: number; ownerStart: string };
          ownerAlive = readFileSync(`/proc/${prior.ownerPid}/stat`, "utf8").trim().split(/\s+/)[21] === prior.ownerStart;
        } catch { ownerAlive = false; }
        if (!ownerAlive && !uidHasLiveProcess(uid)) {
          unlinkSync(path);
          offset -= 1;
        }
      }
    }
    throw new Error("microVM UID lease space exhausted");
  } finally {
    rmSync(allocator, { recursive: true, force: true });
  }
}

function treeBytesAndEntries(root: string, limit = 200_000): { bytes: number; entries: number } {
  let bytes = 0;
  let entries = 0;
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      if (dir === root && name === ".git") continue;
      entries += 1;
      if (entries > limit) throw new Error(`project exceeds ${limit} filesystem entries`);
      const path = join(dir, name);
      const st = lstatSync(path);
      if (st.isFile()) bytes += st.size;
      else if (st.isDirectory()) walk(path);
      else if (!st.isSymbolicLink()) throw new Error(`unsupported project filesystem object: ${path}`);
      if (!Number.isSafeInteger(bytes) || bytes > 4 * 1024 * 1024 * 1024) throw new Error("project exceeds 4 GiB packaging bound");
    }
  };
  walk(root);
  return { bytes, entries };
}

function chownProjectForGuest(path: string, uid: number, gid: number): void {
  const st = lstatSync(path);
  if (st.isSymbolicLink()) { lchownSync(path, uid, gid); return; }
  chownSync(path, uid, gid);
  if (st.isDirectory()) for (const name of readdirSync(path)) chownProjectForGuest(join(path, name), uid, gid);
}

const IMAGE_TOOL_ENV = Object.freeze({ PATH: "/usr/sbin:/usr/bin:/bin", LANG: "C", LC_ALL: "C" });
function replaceGuestInit(rootfs: string, guestInit: string, nonceFile: string, ipadFile: string, opadFile: string, debugfs: string, e2fsck: string): void {
  const runDebugfs = (command: string): void => {
    execFileSync(debugfs, ["-w", "-R", command, rootfs], { stdio: "ignore", timeout: 30_000, env: IMAGE_TOOL_ENV });
  };
  runDebugfs("rm /keep-init");
  runDebugfs("rm /keep-secrets/nonce");
  runDebugfs("rm /keep-secrets/ipad");
  runDebugfs("rm /keep-secrets/opad");
  runDebugfs("rmdir /keep-secrets");
  runDebugfs(`write ${guestInit} /keep-init`);
  runDebugfs("mkdir /keep-secrets");
  runDebugfs(`write ${nonceFile} /keep-secrets/nonce`);
  runDebugfs(`write ${ipadFile} /keep-secrets/ipad`);
  runDebugfs(`write ${opadFile} /keep-secrets/opad`);
  runDebugfs("set_inode_field /keep-init mode 0100755");
  runDebugfs("set_inode_field /keep-secrets mode 040700");
  runDebugfs("set_inode_field /keep-secrets/nonce mode 0100600");
  runDebugfs("set_inode_field /keep-secrets/ipad mode 0100600");
  runDebugfs("set_inode_field /keep-secrets/opad mode 0100600");
  execFileSync(e2fsck, ["-fy", rootfs], { stdio: "ignore", timeout: 60_000, env: IMAGE_TOOL_ENV });
}

async function buildProjectImage(projectDir: string, stagingRoot: string, request: CapturedMicrovmGuestExecutionRequest, debugfs: string, mke2fs: string, e2fsck: string): Promise<{ image: string; manifestSha256: string; installedRequestScriptSha256: string }> {
  if (existsSync(join(projectDir, ".keep"))) throw new Error("project contains reserved .keep path — refusing snapshot mutation");
  const stagedProject = join(stagingRoot, "project");
  // verbatimSymlinks is load-bearing: Node otherwise rewrites relative symlink targets to absolute
  // source-host paths while copying, so the guest snapshot no longer has the same source identity.
  cpSync(projectDir, stagedProject, { recursive: true, dereference: false, verbatimSymlinks: true, preserveTimestamps: true,
    filter: (source) => source === projectDir || !(dirname(source) === projectDir && basename(source) === ".git") });
  // Git control data is neither source input nor safe guest material (it may contain credentials,
  // hooks, alternates, and mutable refs). Remove it only from the disposable staging copy. The
  // source manifest is taken before Keep adds its private execution request, so the same digest can
  // be independently recomputed from the clean published checkout. Command/argv remain bound by the
  // separately signed execution spec and the generated request is root-owned inside the image.
  rmSync(join(stagedProject, ".git"), { recursive: true, force: true });
  const manifestSha256 = await computeMicrovmProjectSourceManifestSha256(stagedProject);
  const reserved = join(stagedProject, ".keep");
  rmSync(reserved, { recursive: true, force: true });
  mkdirSync(reserved, { recursive: true, mode: 0o700 });
  writeFileSync(join(reserved, "request.sh"), request.requestScript, { mode: 0o700, flag: "wx" });
  chownProjectForGuest(stagedProject, 65534, 65534);
  chownSync(reserved, 0, 0);
  chownSync(join(reserved, "request.sh"), 0, 0);
  chmodSync(reserved, 0o700);
  chmodSync(join(reserved, "request.sh"), 0o700);
  const { bytes } = treeBytesAndEntries(stagedProject);
  const imageBytes = Math.min(4 * 1024 * 1024 * 1024, Math.max(64 * 1024 * 1024, Math.ceil((bytes * 2 + 64 * 1024 * 1024) / (1024 * 1024)) * 1024 * 1024));
  const image = join(stagingRoot, "project.ext4");
  writeFileSync(image, "", { flag: "wx", mode: 0o600 });
  truncateSync(image, imageBytes);
  execFileSync(mke2fs, ["-q", "-F", "-t", "ext4", "-d", stagedProject, image], { stdio: "ignore", timeout: 180_000, env: IMAGE_TOOL_ENV });
  execFileSync(e2fsck, ["-fn", image], { stdio: "ignore", timeout: 60_000, env: IMAGE_TOOL_ENV });
  const installedRequest = join(stagingRoot, "installed-request.sh");
  execFileSync(debugfs, ["-R", `dump /.keep/request.sh ${installedRequest}`, image], { stdio: "ignore", timeout: 30_000, env: IMAGE_TOOL_ENV });
  const installedRequestScriptSha256 = sha256Bytes(readFileSync(installedRequest));
  if (installedRequestScriptSha256 !== request.requestScriptSha256) throw new Error("constructed project image guest request readback mismatch");
  return { image, manifestSha256, installedRequestScriptSha256 };
}

function firecrackerConfig(spec: CapturedMicrovmGuestExecutionRequest, nonce: string): MicrovmMachineConfig {
  const bootParts = [
    "root=/dev/vda", "init=/keep-init", "ro", "console=ttyS0", "reboot=k", "panic=1", "pci=off", "quiet", "8250.nr_uarts=1",
    `keep.max_output=${spec.maxOutputBytes}`,
  ];
  bootParts.push(`keep.fsize=${spec.maxFileSizeBytes}`);
  bootParts.push(`keep.pids=${spec.maxProcesses}`);
  return {
    "boot-source": { kernel_image_path: "/vmlinux", boot_args: bootParts.join(" ") },
    drives: [
      { drive_id: "rootfs", path_on_host: "/rootfs.ext4", is_root_device: true, is_read_only: true },
      { drive_id: "project", path_on_host: "/project.ext4", is_root_device: false, is_read_only: false },
    ],
    "machine-config": { vcpu_count: spec.vcpuCount, mem_size_mib: memMib(spec.memoryBytes) },
  };
}

let _rtCache: { readonly value: MicrovmRuntimeInfo; readonly observedAtMs: number } | undefined;
const RUNTIME_CACHE_TTL_MS = 10_000;

/** True iff `/dev/kvm` exists and is a character device (the real KVM boundary, not a stray regular file). */
export function kvmDevicePresent(): boolean {
  try { return existsSync("/dev/kvm") && statSync("/dev/kvm").isCharacterDevice(); }
  catch { return false; }
}

/**
 * Detect the microVM runtime by REAL probes (measurement, not assumption). Cached once per process. A
 * microVM tier is available ONLY when `/dev/kvm` is a real char device AND a VMM binary responds. `kvmPresent`
 * is recorded separately so a KVM-present-but-no-VMM host (this env) reports HONESTLY — kvm yes, tier none —
 * rather than claiming a boundary no VMM can run.
 */
export function detectMicrovmRuntime(force = false, preferred: { readonly vmmBin?: string; readonly jailerBin?: string } = {}): MicrovmRuntimeInfo {
  if (_rtCache && Date.now() - _rtCache.observedAtMs <= RUNTIME_CACHE_TTL_MS && !force && !preferred.vmmBin && !preferred.jailerBin) return _rtCache.value;
  const kvmPresent = kvmDevicePresent();
  const version = (bin: string): string | undefined => {
    try {
      if (!isAbsolute(bin)) return undefined;
      const trusted = assertTrustedRegular(bin, "microVM runtime executable");
      const r = spawnSync(trusted, ["--version"], { encoding: "utf8", timeout: 8000 });
      return r.status === 0 && !r.error ? `${r.stdout}${r.stderr}`.match(/v([0-9]+\.[0-9]+\.[0-9]+)/)?.[1] : undefined;
    } catch { return undefined; }
  };
  const firecracker = preferred.vmmBin ?? "firecracker";
  const jailer = preferred.jailerBin ?? "jailer";
  const firecrackerVersion = version(firecracker);
  const jailerVersion = version(jailer);
  if (kvmPresent && firecrackerVersion && jailerVersion && firecrackerVersion === jailerVersion) {
    const vmmPath = isAbsolute(firecracker) ? realpathSync(firecracker) : firecracker;
    const jailerPath = isAbsolute(jailer) ? realpathSync(jailer) : jailer;
    const measured = { kind: "firecracker" as const, available: true, tier: "microvm" as const, kvmPresent, detail: `/dev/kvm + matched Firecracker/jailer v${firecrackerVersion}`, vmmPath, jailerPath };
    if (!preferred.vmmBin && !preferred.jailerBin) _rtCache = { value: measured, observedAtMs: Date.now() };
    return measured;
  }
  const unavailable: MicrovmRuntimeInfo = {
    kind: "none", available: false, tier: "none", kvmPresent,
    detail: kvmPresent
      ? "/dev/kvm present but no trusted absolute matched Firecracker+jailer runtime — production microVM tier unavailable"
      : "no /dev/kvm and no microVM VMM — microVM tier unavailable (route to a weaker-but-honest tier)",
  };
  if (!preferred.vmmBin && !preferred.jailerBin) _rtCache = { value: unavailable, observedAtMs: Date.now() };
  return unavailable;
}

/** True iff a built guest kernel AND rootfs image both exist — else a legitimate run cannot boot (route down). */
export function microvmImagesPresent(spec: Pick<MicrovmBoundarySpec, "kernelImage" | "rootfsImage">): boolean {
  try {
    const kernel = lstatSync(spec.kernelImage);
    const rootfs = lstatSync(spec.rootfsImage);
    return kernel.isFile() && !kernel.isSymbolicLink() && rootfs.isFile() && !rootfs.isSymbolicLink();
  }
  catch { return false; }
}

/** MiB the guest gets, rounded UP so the cap is never accidentally larger than requested. Min 1 MiB. */
function memMib(bytes: number): number {
  return Math.max(1, Math.ceil(bytes / (1024 * 1024)));
}

/**
 * BUILD-ORDER 1.3b — build the Firecracker VMM machine config + spawn argv. PURE (testable without booting
 * a guest), mirroring `planContainerRun`. The guest hardware IS the containment contract:
 *   - rootfs drive `is_read_only: true`, ONLY the project (+ declared paths) attached as a rw data disk
 *                                 → filesystem-jail (a write outside the data disk hits the ro rootfs)
 *   - NO `network-interfaces` entry (unless `allowNet`)
 *                                 → network-deny at the device level (the guest has no NIC)
 *   - `machine-config.mem_size_mib` (a FIXED guest-RAM allotment)
 *                                 → the HARD memory cap (a bomb OOMs in-guest)
 *   - `fsize`/`pids` rlimits threaded into the guest boot args
 *                                 → resource-bound
 * command/args are delivered to the guest init via boot args, so shell metacharacters are inert.
 */
export function planMicrovmRun(runtime: MicrovmRuntimeInfo, spec: MicrovmBoundarySpec): MicrovmRunPlan {
  const cmd = spec.vmmBin ?? (runtime.kind === "cloud-hypervisor" ? "cloud-hypervisor" : "firecracker");
  const degraded: string[] = [];

  // Resource rlimits + the command are handed to the guest init via boot args (the guest applies them
  // before exec'ing the untrusted command — SIGXFSZ on fsize, EAGAIN on nproc).
  const bootParts = ["console=ttyS0", "reboot=k", "panic=1", "pci=off"];
  if (spec.maxFileSizeBytes !== undefined) bootParts.push(`keep.fsize=${spec.maxFileSizeBytes}`);
  if (spec.maxProcesses !== undefined) bootParts.push(`keep.pids=${spec.maxProcesses}`);
  bootParts.push(`keep.cmd=${encodeURIComponent([spec.command, ...spec.args].join(" "))}`);

  const drives: MicrovmMachineConfig["drives"] = [
    // rootfs: READ-ONLY. A write whose path is not on the rw data disk lands here → refused.
    { drive_id: "rootfs", path_on_host: spec.rootfsImage, is_root_device: true, is_read_only: true },
    // the project: the SINGLE read-write data disk (the one rw island).
    { drive_id: "project", path_on_host: spec.projectDir, is_root_device: false, is_read_only: false },
    // operator-declared extra rw disks (additive).
    ...(spec.allowWritePaths ?? []).filter(Boolean).map((p, i) => ({
      drive_id: `extra${i}`, path_on_host: p, is_root_device: false, is_read_only: false,
    })),
  ];

  const config: MicrovmMachineConfig = {
    "boot-source": { kernel_image_path: spec.kernelImage, boot_args: bootParts.join(" ") },
    drives,
    "machine-config": { vcpu_count: spec.vcpuCount ?? 1, mem_size_mib: memMib(spec.memoryBytes) },
    // network-interfaces: attached ONLY on the allowNet opt-in. Absent → no NIC → egress denied.
    ...(spec.allowNet ? { "network-interfaces": [{ iface_id: "eth0", host_dev_name: "tap0" }] } : {}),
  };
  if (spec.allowNet) degraded.push("allowNet: a virtio-net device is attached (egress permitted by operator opt-in)");

  // Firecracker boots from a config file: `firecracker --no-api --config-file <path>`; cloud-hypervisor
  // takes equivalent flags. The concrete config path is written at run time (buildMicrovmBoundaryRun).
  const args = cmd === "cloud-hypervisor"
    ? ["--kernel", spec.kernelImage, "--cmdline", config["boot-source"].boot_args,
       "--disk", `path=${spec.rootfsImage},readonly=on`, "--disk", `path=${spec.projectDir}`,
       "--memory", `size=${memMib(spec.memoryBytes)}M`, "--cpus", `boot=${spec.vcpuCount ?? 1}`]
    : ["--no-api", "--config-file", "{CONFIG}"];
  return { cmd, args, config, degraded };
}

/**
 * Build a `boundaryRun` for the EXISTING `BoundaryExecutor` (the microVM tier). It boots the guest and runs
 * the configured command inside it, scoped to `spec.projectDir` (the SAME realpath jail primitive the
 * process floor uses on `repoRef` — one boundary, not a forked second), and maps the guest exit to a
 * TestRunResult. Fail-closed: a run that could not COMPLETE (no built kernel/rootfs, VMM spawn error,
 * timeout, guest that did not exit normally) is a runnerError, never a green — so a KVM-less/no-rootfs host,
 * or a suite that OOMs under the guest RAM cap, surfaces honestly and routes to a weaker tier.
 */
export function buildMicrovmBoundaryRun(
  runtime: MicrovmRuntimeInfo,
  spec: MicrovmBoundarySpec,
): (runner: TestRunner, execSpec: ExecutionSpec) => Promise<TestRunResult> {
  if (types.isProxy(spec)) throw new Error("microVM boundary spec must be an inert object");
  const adapterDescriptor = Object.getOwnPropertyDescriptor(spec, "adapter");
  if (adapterDescriptor && !("value" in adapterDescriptor)) throw new Error("microVM boundary adapter must be an own data field");
  const configuredAdapter = adapterDescriptor?.value as ProcessIsolationAdapter | undefined;
  const adapter = configuredAdapter ?? new ProcessIsolationAdapter();
  // Capture this receipt-eligibility decision exactly once with the adapter itself. A caller cannot
  // switch an injected diagnostic adapter to the production path between construction and invocation.
  const productionAdapter = configuredAdapter === undefined;
  return async (_runner: TestRunner, execSpec: ExecutionSpec): Promise<TestRunResult> => {
    const projectDir = execSpec.projectDir || spec.projectDir;
    let guestRequest: CapturedMicrovmGuestExecutionRequest;
    try { guestRequest = captureMicrovmGuestExecutionRequest(spec); }
    catch (error) { return { results: [], runnerError: `microVM guest execution request refused: ${(error as Error).message}` }; }
    const guestExecutionRequestSha256 = capturedMicrovmGuestExecutionRequestDigest(guestRequest);
    // Scope jail (same primitive as the floor): the repoRef must resolve within the project dir.
    const ref = execSpec.repoRef === "" || execSpec.repoRef === "." ? projectDir : execSpec.repoRef;
    if (!resolvedWithinProject(projectDir, ref)) {
      return { results: [], runnerError: `test scope escapes the project dir (${execSpec.repoRef}) — refusing to execute` };
    }
    // A legitimate run needs a built kernel + rootfs; with none, the guest cannot boot → route down (never green).
    if (!microvmImagesPresent(spec)) {
      return { results: [], runnerError: `microVM boundary cannot boot: guest kernel/rootfs not built (kernel=${spec.kernelImage}, rootfs=${spec.rootfsImage}) — routing to a weaker-but-honest tier` };
    }
    // A production receipt is Firecracker+jailer only. Cloud Hypervisor and injected adapters remain
    // diagnostic/test seams and cannot attach the private verifier-owned receipt.
    const production = runtime.kind === "firecracker" && productionAdapter;
    if (!production) {
      return { results: [], runnerError: "microVM diagnostic/direct or injected adapter is non-authorizing and was not invoked" };
    }
    if (guestRequest.allowNet || guestRequest.allowWritePaths.length > 0) {
      return { results: [], runnerError: "production Firecracker receipt refuses unsupported allowNet/allowWritePaths policy" };
    }
    const maxOutputBytes = guestRequest.maxOutputBytes;

    const started = Date.now();
    const nonce = mintMicrovmAttemptNonce();
    const vmm = assertTrustedRegular(spec.vmmBin ?? "", "Firecracker binary");
    const jailer = assertTrustedRegular(spec.jailerBin ?? "", "Firecracker jailer");
    const kernel = assertTrustedRegular(spec.kernelImage, "guest kernel");
    const baseRootfs = assertTrustedRegular(spec.rootfsImage, "guest rootfs");
    const installedGuestInit = resolve(dirname(fileURLToPath(import.meta.url)), "../../../assets/microvm/keep-init");
    const guestInit = assertTrustedRegular(spec.guestInitPath ?? installedGuestInit, "guest supervisor");
    const debugfs = assertTrustedRegular(spec.debugfsBin ?? "/usr/sbin/debugfs", "debugfs image tool");
    const mke2fs = assertTrustedRegular(spec.mke2fsBin ?? "/usr/sbin/mke2fs", "mke2fs image tool");
    const e2fsck = assertTrustedRegular(spec.e2fsckBin ?? "/usr/sbin/e2fsck", "e2fsck image tool");
    const requestedWorkRoot = resolve(spec.workRoot ?? "/var/lib/keep/microvm");
    mkdirSync(requestedWorkRoot, { recursive: true, mode: 0o700 });
    chmodSync(requestedWorkRoot, 0o700);
    let workRoot: string;
    try { workRoot = assertTrustedDirectory(requestedWorkRoot, "microVM work root"); }
    catch (error) { return { results: [], runnerError: (error as Error).message }; }
    const id = `keep-${nonce}`;
    const jailRoot = join(workRoot, basename(vmm), id, "root");
    // Firecracker jailer 1.16 with --parent-cgroup=keep materializes this exact v2 path on the
    // deployed host. The real-host evidence recursively checks the same layout.
    const cgroup = join("/sys/fs/cgroup/keep", id);
    let lease: { uid: number; gid: number; path: string } | undefined;
    let staging: string | undefined;
    let receipt: Omit<VerifiedMicrovmRunReceipt, "teardownClean"> | undefined;
    let teardownClean = false;
    let result: TestRunResult = { results: [], runnerError: "microVM run did not complete" };
    try {
      lease = acquireUidLease(workRoot, nonce);
      const { uid, gid } = lease;
      staging = mkdtempSync(join(workRoot, ".prepare-"));
      chmodSync(staging, 0o700);
      treeBytesAndEntries(projectDir);
      const projectSnapshot = await buildProjectImage(projectDir, staging, guestRequest, debugfs, mke2fs, e2fsck);
      const projectImage = projectSnapshot.image;
      const rootfs = join(staging, "rootfs.ext4");
      cpSync(baseRootfs, rootfs, { mode: 0, preserveTimestamps: true });
      chmodSync(rootfs, 0o600);
      const resultAuthenticationKey = mintMicrovmResultAuthenticationKey();
      const keyBlock = Buffer.alloc(64);
      resultAuthenticationKey.copy(keyBlock);
      const ipad = Buffer.from(keyBlock.map((byte) => byte ^ 0x36));
      const opad = Buffer.from(keyBlock.map((byte) => byte ^ 0x5c));
      const nonceFile = join(staging, "result-authentication-nonce");
      const ipadFile = join(staging, "result-authentication-ipad");
      const opadFile = join(staging, "result-authentication-opad");
      writeFileSync(nonceFile, `${nonce}\n`, { flag: "wx", mode: 0o600 });
      writeFileSync(ipadFile, `${ipad.toString("hex")}\n`, { flag: "wx", mode: 0o600 });
      writeFileSync(opadFile, `${opad.toString("hex")}\n`, { flag: "wx", mode: 0o600 });
      replaceGuestInit(rootfs, guestInit, nonceFile, ipadFile, opadFile, debugfs, e2fsck);
      unlinkSync(nonceFile);
      unlinkSync(ipadFile);
      unlinkSync(opadFile);
      const config = firecrackerConfig(guestRequest, nonce);
      const configBytes = Buffer.from(`${JSON.stringify(config)}\n`, "utf8");
      mkdirSync(jailRoot, { recursive: true, mode: 0o700 });
      const jailedKernel = join(jailRoot, "vmlinux");
      const jailedRootfs = join(jailRoot, "rootfs.ext4");
      const jailedProject = join(jailRoot, "project.ext4");
      const jailedConfig = join(jailRoot, "config.json");
      cpSync(kernel, jailedKernel, { preserveTimestamps: true });
      cpSync(rootfs, jailedRootfs, { preserveTimestamps: true });
      cpSync(projectImage, jailedProject, { preserveTimestamps: true });
      writeFileSync(jailedConfig, configBytes, { flag: "wx", mode: 0o400 });
      for (const path of [jailedKernel, jailedRootfs, jailedProject, jailedConfig]) {
        chownSync(path, uid, gid);
        chmodSync(path, path === jailedProject ? 0o600 : 0o400);
      }
      // Read back from the exact copies the jailer will launch, after copy/chown/chmod. Staging-image
      // measurements remain useful construction checks but cannot authorize a different launched image.
      const launchedGuestInitReadback = join(staging, "launched-keep-init");
      const launchedGuestRequestReadback = join(staging, "launched-request.sh");
      execFileSync(debugfs, ["-R", `dump /keep-init ${launchedGuestInitReadback}`, jailedRootfs], { stdio: "ignore", timeout: 30_000, env: IMAGE_TOOL_ENV });
      execFileSync(debugfs, ["-R", `dump /.keep/request.sh ${launchedGuestRequestReadback}`, jailedProject], { stdio: "ignore", timeout: 30_000, env: IMAGE_TOOL_ENV });
      const launchedGuestRequestScriptSha256 = sha256Bytes(readFileSync(launchedGuestRequestReadback));
      if (launchedGuestRequestScriptSha256 !== guestRequest.requestScriptSha256 || launchedGuestRequestScriptSha256 !== projectSnapshot.installedRequestScriptSha256) {
        throw new Error("jailed project image guest request readback mismatch");
      }
      const kernelSha256 = await sha256File(jailedKernel);
      const baseRootfsSha256 = await sha256File(baseRootfs);
      const vmmSha256 = await sha256File(vmm);
      const jailerSha256 = await sha256File(jailer);
      const guestSupervisorSha256 = await sha256File(guestInit);
      const installedGuestSupervisorSha256 = await sha256File(launchedGuestInitReadback);
      if (installedGuestSupervisorSha256 !== guestSupervisorSha256) throw new Error("constructed rootfs guest supervisor readback mismatch");
      const debugfsSha256 = await sha256File(debugfs);
      const mke2fsSha256 = await sha256File(mke2fs);
      const e2fsckSha256 = await sha256File(e2fsck);
      const rootfsSha256 = await sha256File(jailedRootfs);
      const projectImageSha256 = await sha256File(jailedProject);
      const configSha256 = sha256Bytes(configBytes);
      const measurementPolicyCanonicalSha256 = assertTrustedMeasurements({ vmmSha256, jailerSha256, kernelSha256, baseRootfsSha256, guestSupervisorSha256, debugfsSha256, mke2fsSha256, e2fsckSha256 }, spec.trustedMeasurements);
      const executionSpecSha256 = exactExecutionSpecDigest(execSpec, guestExecutionRequestSha256);
      const hostMemoryLimit = guestRequest.memoryBytes + 256 * 1024 * 1024;
      const jailerArgs = [
        "--id", id,
        "--exec-file", vmm,
        "--uid", String(uid),
        "--gid", String(gid),
        "--chroot-base-dir", workRoot,
        "--new-pid-ns",
        "--cgroup-version", "2",
        "--parent-cgroup", "keep",
        "--cgroup", `memory.max=${hostMemoryLimit}`,
        "--cgroup", `pids.max=${Math.max(64, guestRequest.maxProcesses)}`,
        "--resource-limit", `fsize=${Math.max(16 * 1024 * 1024, guestRequest.maxFileSizeBytes)}`,
        "--resource-limit", "no-file=1024",
        "--", "--no-api", "--config-file", "/config.json",
      ];
      const jailerArgsSha256 = sha256Bytes(Buffer.from(`keep.firecracker-jailer-argv/v1\0${JSON.stringify(jailerArgs)}\n`, "utf8"));
      const isolatedProcess = adapter.start(jailer, jailerArgs, {
        cwd: workRoot,
        timeoutMs: guestRequest.timeoutMs,
        maxOutputBytes: Math.min(16 * 1024 * 1024, guestRequest.maxOutputBytes * 2 + 384 * 1024),
      });
      // The jailer starts the VMM in a new PID namespace; a generic host process-group signal may not
      // reach it. The boundary therefore owns a second fail-safe watchdog at the actual cgroup.
      const cgroupKillWatchdog = setTimeout(() => {
        try { if (existsSync(join(cgroup, "cgroup.kill"))) writeFileSync(join(cgroup, "cgroup.kill"), "1\n", "utf8"); }
        catch { /* teardown and receipt validation remain fail-closed */ }
      }, guestRequest.timeoutMs + 250);
      const res = await isolatedProcess.done;
      clearTimeout(cgroupKillWatchdog);
      if (res.timedOut) {
        const serialTail = Buffer.from(res.stdout, "utf8").subarray(-2000).toString("base64");
        return { results: [], runnerError: `microVM boundary run exceeded ${guestRequest.timeoutMs}ms and the process group was killed; serialTailBase64=${serialTail}` };
      }
      if (res.truncated) return { results: [], runnerError: "microVM serial capture exceeded its host bound" };
      if (res.code === null) return { results: [], runnerError: `microVM jailer did not exit normally${res.signal ? ` (killed: ${res.signal})` : ""}` };
      if (res.code !== 0) return { results: [], runnerError: `microVM jailer exited non-zero (${res.code})` };
      if (!existsSync(cgroup)) throw new Error(`expected jailer cgroup is absent: ${cgroup}`);
      const observedMemoryMax = readFileSync(join(cgroup, "memory.max"), "utf8").trim();
      const observedPidsMax = readFileSync(join(cgroup, "pids.max"), "utf8").trim();
      if (observedMemoryMax !== String(hostMemoryLimit) || observedPidsMax !== String(Math.max(64, guestRequest.maxProcesses))) {
        throw new Error(`jailer cgroup limits mismatch: memory.max=${observedMemoryMax} pids.max=${observedPidsMax}`);
      }
      const serialBytes = res.stdoutBytes ?? Buffer.from(res.stdout, "utf8");
      const stderrBytes = res.stderrBytes ?? Buffer.from(res.stderr, "utf8");
      const serialSha256 = sha256Bytes(serialBytes);
      const jailerStderrSha256 = sha256Bytes(stderrBytes);
      let guest: MicrovmGuestResult;
      try {
        guest = parseMicrovmGuestFrame(serialBytes, nonce, resultAuthenticationKey, {
          maxStreamBytes: maxOutputBytes,
          maxEnvelopeBytes: maxOutputBytes * 2 + 4096,
          maxPreambleBytes: DEFAULT_MICROVM_FRAME_LIMITS.maxPreambleBytes,
          maxPostambleBytes: DEFAULT_MICROVM_FRAME_LIMITS.maxPostambleBytes,
        });
      }
      catch (error) {
        const serialTail = Buffer.from(res.stdout, "utf8").subarray(-2000).toString("base64");
        return { results: [], runnerError: `${(error as Error).message}; serialTailBase64=${serialTail}; jailer stderr=${res.stderr.slice(-1000)}` };
      }
      const cases: TestCaseResult[] = parseTap(`${guest.stdout}\n${guest.stderr}`);
      if (guest.exitCode === 0) {
        result = { results: cases.length > 0 ? cases : [{ name: `${guestRequest.command} ${guestRequest.args.join(" ")}`.trim(), passed: true }] };
      } else {
        const failing = cases.filter((c) => !c.passed);
        result = failing.length > 0
          ? { results: cases }
          : { results: [{ name: `${guestRequest.command} ${guestRequest.args.join(" ")}`.trim(), passed: false, output: (guest.stderr || guest.stdout).slice(-2000) || `exit code ${guest.exitCode}` }] };
      }
      const testRunResultSha256 = exactTestRunResultDigest(result);
      receipt = {
        schema: "keep.verified-microvm-run-receipt/v3",
        runtimeKind: "firecracker",
        attemptNonce: nonce,
        projectDir: realpathSync(projectDir),
        executionSpecSha256,
        guestExecutionRequestSha256,
        guestRequestScriptSha256: guestRequest.requestScriptSha256,
        installedGuestRequestScriptSha256: launchedGuestRequestScriptSha256,
        startedAt: new Date(started).toISOString(),
        durationMs: Date.now() - started,
        jailerSha256,
        vmmSha256,
        kernelSha256,
        guestSupervisorSha256,
        installedGuestSupervisorSha256,
        debugfsSha256,
        mke2fsSha256,
        e2fsckSha256,
        baseRootfsSha256,
        rootfsSha256,
        projectSourceManifestSha256: projectSnapshot.manifestSha256,
        projectImageSha256,
        configSha256,
        jailerArgsSha256,
        serialSha256,
        jailerStderrSha256,
        vmmExitCode: res.code,
        jailUid: uid,
        jailGid: gid,
        measuredCgroupMemoryMax: observedMemoryMax,
        measuredCgroupPidsMax: observedPidsMax,
        measurementPolicyCanonicalSha256,
        testRunResultSha256,
        guestResult: guest,
        degraded: [],
      };
    } catch (error) {
      result = { results: [], runnerError: `microVM jailer transaction refused: ${(error as Error).message}` };
    } finally {
      // The project/rootfs images are per-attempt and disposable. No guest write is copied to the host project.
      rmSync(join(workRoot, basename(vmm), id), { recursive: true, force: true });
      if (staging) rmSync(staging, { recursive: true, force: true });
      try {
        if (!existsSync(cgroup)) throw new Error("expected microVM cgroup disappeared before teardown verification");
        const descendants = readdirSync(cgroup, { withFileTypes: true }).filter((entry) => entry.isDirectory());
        const livePids = readFileSync(join(cgroup, "cgroup.procs"), "utf8").trim();
        if (livePids !== "" || descendants.length > 0) throw new Error("microVM cgroup still owns processes or descendants");
        rmdirSync(cgroup);
      } catch { receipt = undefined; }
      if (lease) {
        try {
          if (uidHasLiveProcess(lease.uid)) throw new Error(`leased UID ${lease.uid} still owns a live process`);
          unlinkSync(lease.path);
        } catch { receipt = undefined; }
      }
      teardownClean = !existsSync(cgroup) && !existsSync(join(workRoot, basename(vmm), id)) &&
        (staging === undefined || !existsSync(staging)) && (lease === undefined || !existsSync(lease.path));
      if (!teardownClean) receipt = undefined;
    }
    return receipt && teardownClean ? attachVerifiedMicrovmRunReceipt(result, { ...receipt, teardownClean: true }) : result;
  };
}

/**
 * The microVM containment CONTRACT — the SAME fs/net/fsize source of truth (`containmentDecision`, shared
 * with the container tier — one contract, not two) PLUS the bound the weaker tiers could not deliver: the
 * HARD guest-RAM cap. An allocation beyond the guest's fixed RAM allotment OOMs in-guest and is refused.
 */
export interface MicrovmContainmentContract extends ContainmentContract {
  /** The guest's fixed RAM allotment (bytes). An allocation beyond it OOMs in-guest → refused. */
  readonly maxMemoryBytes: number;
}

/** An effect an untrusted child intends inside the guest — the container effect PLUS a memory allocation. */
export interface MicrovmRequestedEffect extends RequestedEffect {
  /** Bytes the child intends to allocate (checked against the guest RAM cap). */
  readonly allocBytes?: number;
}

/**
 * The microVM boundary's containment DECISION. Composes the SAME `containmentDecision` (fs-jail + net-deny +
 * fsize — one source of truth, shared with the container tier) and ADDS the guest-RAM memory bound. The
 * neuterable enforcement point for the microVM tier. Deterministic.
 */
export function microvmContainmentDecision(
  contract: MicrovmContainmentContract,
  effect: MicrovmRequestedEffect,
): { allowed: boolean; reason: string } {
  const base = containmentDecision(contract, effect);
  if (!base.allowed) return base;
  if (effect.allocBytes !== undefined && effect.allocBytes > contract.maxMemoryBytes) {
    return { allowed: false, reason: `allocation of ${effect.allocBytes}B exceeds the guest RAM cap (${contract.maxMemoryBytes}B) — OOM-killed inside the guest, never a green` };
  }
  return { allowed: true, reason: "within the microVM containment contract" };
}
