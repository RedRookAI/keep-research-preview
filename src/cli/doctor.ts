import { constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { captureInstalledPackageSubjectDigest } from "../release/solo_non_regression.js";
import { readReleaseBootBundle, readReleaseTrustRoot } from "../graph/release_bundle.js";
import { verifyInstalledReleaseAtBoot } from "../graph/release_boot.js";
import { remoteProviderIdentityDigest } from "../gateway/provider_descriptor.js";
import { captureRuntimeContract, RuntimeConfigError, type CapturedRuntimeContract, type RuntimeConfigContext } from "./runtime_config.js";
import { loadMemoryRetentionProfile } from "./memory_retention_profile.js";

export type DoctorStatus = "ready" | "missing-input" | "unsupported" | "security-refusal";
export interface DoctorCheck { readonly name: string; readonly status: DoctorStatus; readonly detail: string; }
export interface DoctorReport { readonly ready: boolean; readonly contract?: CapturedRuntimeContract; readonly checks: readonly DoctorCheck[]; }

export interface DoctorOptions {
  readonly context: RuntimeConfigContext;
  readonly packageRoot: string;
  readonly stdinIsTTY: boolean;
  readonly platform?: NodeJS.Platform;
  readonly pathEnv?: string;
  readonly stat?: typeof statSync;
  readonly measurePackage?: (root: string) => string;
  readonly verifyRelease?: (contract: CapturedRuntimeContract, packageRoot: string) => void;
}

const ok = (name: string, detail: string): DoctorCheck => ({ name, status: "ready", detail });

/** Read-only installed readiness inspection. It never constructs a provider or persistent product object. */
export function inspectInstalledReadiness(env: Readonly<Record<string, string | undefined>>, options: DoctorOptions): DoctorReport {
  let contract: CapturedRuntimeContract;
  try { contract = captureRuntimeContract(env, options.context, { projectRequired: true }); }
  catch (error) {
    const field = error instanceof RuntimeConfigError ? error.field : "configuration";
    return { ready: false, checks: [{ name: field, status: "missing-input", detail: (error as Error).message }] };
  }
  const checks: DoctorCheck[] = [];
  if (env["KEEP_MEMORY_RETENTION_PROFILE"] !== undefined) {
    try {
      const policy = loadMemoryRetentionProfile(env["KEEP_MEMORY_RETENTION_PROFILE"], contract.provider.authority ?? "owner");
      checks.push(ok("private-memory-retention", `captured policy ${policy.identity}; ${policy.purposes.length} allowed purposes; private writes require explicit purpose and retention consent; reload requires process restart; not disclosure authority`));
    } catch (error) { checks.push({ name: "private-memory-retention", status: "security-refusal", detail: (error as Error).message }); }
  }
  try {
    const digest = (options.measurePackage ?? captureInstalledPackageSubjectDigest)(options.packageRoot);
    checks.push(ok("installed-package", `measured ${digest}`));
  } catch (error) { checks.push({ name: "installed-package", status: "security-refusal", detail: (error as Error).message }); }
  checks.push(ok("repository", `${contract.installedProject!.repository.root}@${contract.installedProject!.revision}`));
  checks.push(ok("workspace", `${contract.installedProject!.workspaceBase.root}/${contract.installedProject!.repoRef} is isolated from source`));
  checks.push(ok("provider", contract.provider.mode === "local" ? "offline deterministic provider selected (not real local inference)" : `${contract.provider.authority}/${contract.provider.location} ${contract.provider.mode} ${new URL(contract.provider.baseUrl).origin} model=${contract.provider.model}; purpose=${contract.remoteProcessing!.purpose}; region=${contract.remoteProcessing!.region}`));
  checks.push(checkCredential(contract, options));
  checks.push(checkRelease(contract, options));
  if (contract.encoder !== undefined) {
    const encoder = contract.encoder;
    checks.push(ok("semantic-encoder", `${encoder.authority}/${encoder.location} ${new URL(encoder.endpoint).origin} model=${encoder.model}; revision/dimension/prefixes declared, not weight-verified; original-job requests=${encoder.limits.requests}; document egress requires per-command consent`));
    const encoderContract: CapturedRuntimeContract = {
      provider: { mode: encoder.protocol, baseUrl: encoder.endpoint, model: encoder.model, authority: encoder.authority, location: encoder.location },
      memoryProvider: contract.memoryProvider, remoteProcessing: encoder.processing.query,
      ...(contract.encoderCredentialReference ? { credentialReference: contract.encoderCredentialReference } : {}),
      ...(encoder.release ? { releaseAdmission: encoder.release } : {}),
      ...(contract.organization ? { organization: contract.organization } : {}),
    };
    checks.push({ ...checkCredential(encoderContract, options), name: "encoder-credential" });
    checks.push({ ...checkRelease(encoderContract, options), name: "encoder-release-admission" });
  }
  checks.push(checkCommand(contract.installedProject!.testCommand.command, options));
  const ready = checks.every((check) => check.status === "ready");
  return { ready, contract, checks };
}

export function renderDoctorReport(report: DoctorReport): string {
  return [...report.checks.map((check) => `${check.status.padEnd(16)} ${check.name}: ${check.detail}`), report.ready ? "READY: installed project configuration is admissible" : "NOT READY: correct the first refusal above and run keep doctor again"].join("\n");
}

function checkCredential(contract: CapturedRuntimeContract, options: DoctorOptions): DoctorCheck {
  const reference = contract.credentialReference;
  if (!reference) return ok("credential", "not required for local provider");
  if (reference.kind === "environment") return ok("credential", "present via environment (value redacted)");
  if (reference.kind === "stdin") return options.stdinIsTTY
    ? { name: "credential", status: "missing-input", detail: "stdin credential selected but stdin is a terminal; pipe the credential without interactive prompts" }
    : ok("credential", "selected via non-terminal stdin (value not consumed by doctor)");
  try {
    const stat = (options.stat ?? statSync)(reference.path);
    if (!stat.isFile()) throw new Error("credential path is not a regular file");
    if ((stat.mode & 0o400) === 0) throw new Error("credential file is not owner-readable");
    if ((options.platform ?? process.platform) !== "win32" && (stat.mode & 0o077) !== 0) throw new Error("credential file permits group or other access; require mode 0600 or stricter");
    return ok("credential", `present in protected file ${reference.path} (value redacted)`);
  } catch (error) { return { name: "credential", status: "security-refusal", detail: (error as Error).message }; }
}

function checkRelease(contract: CapturedRuntimeContract, options: DoctorOptions): DoctorCheck {
  if (!contract.releaseAdmission) return ok("release-admission", contract.provider.mode !== "local" && contract.provider.authority === "owner" ? "owner configuration admitted; organization release signature not applicable" : "not required for offline provider");
  try {
    (options.verifyRelease ?? verifyRelease)(contract, options.packageRoot);
    return ok("release-admission", `verified bundle ${contract.releaseAdmission.bundlePath} against ${contract.releaseAdmission.trustRootPath}`);
  } catch (error) { return { name: "release-admission", status: "security-refusal", detail: (error as Error).message }; }
}

function verifyRelease(contract: CapturedRuntimeContract, packageRoot: string): void {
  const trust = readReleaseTrustRoot(contract.releaseAdmission!.trustRootPath);
  const bundle = readReleaseBootBundle(contract.releaseAdmission!.bundlePath, trust);
  const provider = contract.provider;
  if (provider.mode === "local") throw new Error("remote release admission requires a remote provider");
  let last = BigInt(Date.now()) - 1n;
  verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification: bundle.verification, authority: bundle.authority, providerDescriptorDigest: remoteProviderIdentityDigest({ mode: provider.mode, baseUrl: provider.baseUrl, model: provider.model, apiKey: "doctor-redacted-placeholder" }), trustedNowMs: () => ++last,
    ...(contract.organization?.scannerEnginePath ? { scannerEnginePath: contract.organization.scannerEnginePath } : {}) });
}

function checkCommand(command: string, options: DoctorOptions): DoctorCheck {
  const candidates = isAbsolute(command) ? [command] : (options.pathEnv ?? process.env.PATH ?? "").split(delimiter).filter(Boolean).map((path) => join(path, command));
  for (const path of candidates) {
    try {
      const stat = (options.stat ?? statSync)(path);
      if (stat.isFile() && ((options.platform ?? process.platform) === "win32" || (stat.mode & (constants.S_IXUSR | constants.S_IXGRP | constants.S_IXOTH)) !== 0)) return ok("test-command", `executable found at ${path}`);
    } catch { /* try next bounded PATH entry */ }
  }
  return { name: "test-command", status: "unsupported", detail: `cannot resolve executable ${command} on PATH` };
}
