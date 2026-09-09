/**
 * The thin `keep` entrypoint (Increment S0). Wires real stdin/stdout + a composed KeepApp into the testable
 * cli_core. Deliberately minimal: all logic lives in cli_core (tested); this file only builds the real ports.
 * Zero runtime deps (node:readline, node:fs, node:os, node:path are built-ins).
 *
 * Honesty: onboard/status/review/audit are fully live here (they need only the app + spine). A3 resolves and wires
 * provider/repository/workspace into the installed composition root, but `solve` remains absent until A10 supplies
 * repository materialization and the complete pipeline deps. Until then the CLI says so rather than faking a solve.
 */

import { createInterface } from "node:readline";
import { mkdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Spine } from "../spine/spine.js";
import { FileSpineStore } from "../spine/store.js";
import { InProcessLock } from "../lock/lock.js";
import { SchemaRegistry } from "../spine/upcaster.js";
import { ModelGateway } from "../gateway/gateway.js";
import { MemoryStore } from "../memory/store.js";
import { readFileSync } from "node:fs";
import { composeKeep } from "../compose.js";
import { runCli, runStaticCli, runGatewayCli, type CliIO, type CliDeps } from "./cli_core.js";
import { createGatewayClient } from "./gateway_client.js";
import { launchNativeWorker, recordNativeWorker } from "./native_worker.js";
import { startGatewayServer } from "../gateway/http_gateway.js";
import { captureRuntimeContract, createConfiguredProvider, resolveRuntimeConfig, resolveRuntimeIntent, type CapturedRuntimeContract, type CredentialReference } from "./runtime_config.js";
import { readReleaseBootBundle, readReleaseTrustRoot } from "../graph/release_bundle.js";
import { verifyInstalledReleaseAtBoot } from "../graph/release_boot.js";
import { remoteProviderIdentityDigest } from "../gateway/provider_descriptor.js";
import { inspectInstalledReadiness, renderDoctorReport } from "./doctor.js";
import { applyProviderProfile, defaultProviderProfilePath, loadProviderProfile, profileFromArgs, writeProviderProfile } from "./provider_profile.js";
import { loadInstalledOrganizationRuntime } from "./organization_runtime.js";
import { FileGatewayTokenStore } from "./gateway_token_store.js";
import { configuredSemanticEncoder, encoderProfileDescriptor, encoderProfileFromArgs, loadEncoderProfile, writeEncoderProfile } from "./encoder_profile.js";
import { loadMemoryRetentionProfile, memoryRetentionProfileFromArgs, writeMemoryRetentionProfile } from "./memory_retention_profile.js";

const SYSTEM_RELEASE_TRUST_ROOT = "/etc/keep/release-root.cbor";

function monotonicWallClock(): () => bigint {
  const wallBase = BigInt(Date.now()); const monoBase = process.hrtime.bigint(); let last = wallBase - 1n;
  return () => { const candidate = wallBase + (process.hrtime.bigint() - monoBase) / 1_000_000n; const next = candidate > last ? candidate : last + 1n; last = next; return next; };
}
export function executingPackageRoot(): string {
  let candidate = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth++) { try { if (statSync(join(candidate, "package.json")).isFile()) return realpathSync(candidate); } catch { /* continue upward */ } const parent = dirname(candidate); if (parent === candidate) break; candidate = parent; }
  throw new Error("cannot locate the executing installed package root");
}

export async function main(argv: readonly string[]): Promise<number> {
  const staticResult = runStaticCli(argv, (text) => process.stdout.write(`${text}\n`));
  if (staticResult) return staticResult.exitCode;
  if (argv[0]?.toLowerCase() === "memory-retention" && argv[1]?.toLowerCase() === "configure") {
    try {
      const configured = memoryRetentionProfileFromArgs(argv.slice(2), process.cwd());
      writeMemoryRetentionProfile(configured.path, configured.policy);
      process.stdout.write(`Memory retention policy saved at ${configured.path}. Set KEEP_MEMORY_RETENTION_PROFILE before startup; restart to apply changes. Explicit memory retention consent/purpose is still required. This is not model disclosure authority.\n`);
      return 0;
    } catch (error) { process.stderr.write(`Memory retention configuration refused: ${(error as Error).message}\n`); return 2; }
  }
  if (argv[0]?.toLowerCase() === "encoder" && ["configure", "show"].includes(argv[1]?.toLowerCase() ?? "")) {
    try {
      if (argv[1]!.toLowerCase() === "configure") {
        const configured = encoderProfileFromArgs(argv.slice(2), process.cwd());
        writeEncoderProfile(configured.path, configured.profile);
        process.stdout.write(`Encoder profile saved at ${configured.path}; no credential value was stored. Set KEEP_ENCODER_PROFILE to this path. Per-command semantic consent is still required.\n`);
      } else {
        if (argv.length !== 2 || !process.env["KEEP_ENCODER_PROFILE"]) throw new Error("encoder show requires KEEP_ENCODER_PROFILE and no additional arguments");
        process.stdout.write(JSON.stringify(loadEncoderProfile(process.env["KEEP_ENCODER_PROFILE"]), null, 2) + "\n");
      }
      return 0;
    } catch (error) { process.stderr.write(`Encoder configuration refused: ${(error as Error).message}\n`); return 2; }
  }
  if (process.env["KEEP_GATEWAY_URL"] !== undefined) {
    const tokenFile = process.env["KEEP_GATEWAY_TOKEN_FILE"], sessionFile = process.env["KEEP_GATEWAY_SESSION_FILE"];
    const token = tokenFile ? new FileGatewayTokenStore(tokenFile).load() : process.env["KEEP_GATEWAY_TOKEN"];
    if (!token || !/^[0-9a-f]{48,128}$/u.test(token)) throw new Error("remote client requires KEEP_GATEWAY_TOKEN_FILE or a valid KEEP_GATEWAY_TOKEN");
    const session = sessionFile ? new FileGatewayTokenStore(sessionFile).load() : undefined;
    if (sessionFile && !session) throw new Error("gateway session file is missing");
    return (await runGatewayCli(argv, { write: text => process.stdout.write(text + "\n"), prompt: async () => { throw new Error("remote command cannot prompt implicitly"); } },
      { gateway: createGatewayClient(process.env["KEEP_GATEWAY_URL"]!, session), gatewayToken: token, readFile: path => readFileSync(path, "utf8") })).exitCode;
  }
  if ((argv[0] ?? "").toLowerCase() === "provider" && (argv[1] ?? "").toLowerCase() === "configure") {
    try {
      const configured = profileFromArgs(argv.slice(2), process.cwd());
      writeProviderProfile(configured.path, configured.profile);
      process.stdout.write(`Provider profile ${configured.profile.name} saved at ${configured.path}; no credential value was stored.\n`);
      return 0;
    } catch (error) { process.stderr.write(`Provider configuration refused: ${(error as Error).message}\n`); return 2; }
  }
  if ((argv[0] ?? "").toLowerCase() === "provider" && (argv[1] ?? "").toLowerCase() === "show") {
    try {
      const path = process.env["KEEP_PROFILE"] ?? defaultProviderProfilePath();
      const profile = loadProviderProfile(path);
      process.stdout.write(`${JSON.stringify({ ...profile, credential: profile.credential === null ? null : { kind: profile.credential.kind, ...(profile.credential.kind === "file" ? { path: profile.credential.path } : {}) } }, null, 2)}\n`);
      return 0;
    } catch (error) { process.stderr.write(`Provider profile unavailable: ${(error as Error).message}\n`); return 2; }
  }
  let runtimeEnv: NodeJS.ProcessEnv;
  try { runtimeEnv = applyProviderProfile(process.env); }
  catch (error) { process.stderr.write(`Provider profile refused: ${(error as Error).message}\n`); return 2; }
  const workerRequested = argv[0] === "serve" && argv.includes("--gateway") && argv.includes("--project-worker");
  if (argv.includes("--paused") && !workerRequested) throw new Error("--paused requires a native project worker");
  if (argv.includes("--detach")) {
    if (!workerRequested) throw new Error("--detach requires serve --gateway --project-worker");
    process.stdout.write(JSON.stringify(await launchNativeWorker(argv, runtimeEnv)) + "\n"); return 0;
  }
  const managedId = argv.find(arg => arg.startsWith("--managed-worker-id="))?.slice("--managed-worker-id=".length);
  if (managedId !== undefined && (!workerRequested || !process.send || !/^[0-9a-f-]{36}$/u.test(managedId))) throw new Error("managed worker startup requires the installed launch channel");
  const workerId = workerRequested ? managedId ?? randomUUID() : undefined;
  if ((argv[0] ?? "").toLowerCase() === "doctor") {
    const report = inspectInstalledReadiness(runtimeEnv, { context: { cwd: process.cwd() }, packageRoot: executingPackageRoot(), stdinIsTTY: process.stdin.isTTY === true });
    process.stdout.write(`${renderDoctorReport(report)}\n`);
    return report.ready ? 0 : 2;
  }
  const dataDir = resolve(runtimeEnv["KEEP_DATA_DIR"] ?? join(homedir(), ".keep"));
  const directDomainRequested = argv.some((arg) => arg.startsWith("--domain="));
  const projectCommand = workerRequested || (!directDomainRequested && ["project", "projects", "merge", "revert"].includes((argv[0] ?? "").toLowerCase()));
  const domainSurfaceRequested = directDomainRequested || (argv[0] === "serve" && argv.includes("--gateway"));
  const organizationCommand = runtimeEnv["KEEP_PROVIDER_AUTHORITY"]?.toLowerCase() === "organization";
  const captured = projectCommand || organizationCommand || runtimeEnv["KEEP_ENCODER_PROFILE"] !== undefined || runtimeEnv["KEEP_ENCODER_API_KEY"] !== undefined ? captureRuntimeContract(runtimeEnv, { cwd: process.cwd() }, { projectRequired: projectCommand }) : undefined;
  const capturedCredential = captured ? await loadCapturedCredential(captured.credentialReference, runtimeEnv) : undefined;
  const encoderCredential = captured ? await loadCapturedCredential(captured.encoderCredentialReference, runtimeEnv) : undefined;
  const repositoryFreeProviderCheck = (argv[0] ?? "").toLowerCase() === "provider-check";
  const intent = captured ? undefined : resolveRuntimeIntent(runtimeEnv, { repositoryRequired: !directDomainRequested && !repositoryFreeProviderCheck });
  const provider = captured ? capturedProvider(captured, capturedCredential) : intent!.provider;
  const organizationProvider = provider.mode !== "local" && provider.authority !== "owner";
  const releaseBoot = !organizationProvider ? undefined : (() => {
    const path = captured?.releaseAdmission?.bundlePath ?? runtimeEnv["KEEP_RELEASE_BUNDLE"]; if (path === undefined || path === "") throw new Error("KEEP_RELEASE_BUNDLE is required for an organization provider");
    const trustRootPath = captured?.releaseAdmission?.trustRootPath ?? SYSTEM_RELEASE_TRUST_ROOT;
    const trustRoot = readReleaseTrustRoot(trustRootPath); const bundle = readReleaseBootBundle(path, trustRoot); return verifyInstalledReleaseAtBoot({ installedRoot: executingPackageRoot(), verification: bundle.verification, authority: bundle.authority, providerDescriptorDigest: remoteProviderIdentityDigest(providerDescriptor(provider)), trustedNowMs: monotonicWallClock(), ...(captured?.organization?.scannerEnginePath ? { scannerEnginePath: captured.organization.scannerEnginePath } : {}) });
  })();
  const encoder = captured?.encoder;
  const encoderRelease = encoder?.authority !== "organization" ? undefined : (() => {
    const trustRoot = readReleaseTrustRoot(encoder.release!.trustRootPath);
    const bundle = readReleaseBootBundle(encoder.release!.bundlePath, trustRoot);
    return verifyInstalledReleaseAtBoot({ installedRoot: executingPackageRoot(), verification: bundle.verification, authority: bundle.authority,
      providerDescriptorDigest: remoteProviderIdentityDigest(encoderProfileDescriptor(encoder, encoderCredential)), trustedNowMs: monotonicWallClock(),
      ...(captured?.organization?.scannerEnginePath ? { scannerEnginePath: captured.organization.scannerEnginePath } : {}) });
  })();
  const semanticEncoder = encoder === undefined ? undefined : configuredSemanticEncoder(encoder, encoderCredential, encoderRelease);
  // Repository discovery may invoke Git and therefore happens only after remote admission.
  const runtime = captured ? undefined : resolveRuntimeConfig(runtimeEnv, { cwd: process.cwd(), repositoryRequired: !directDomainRequested && !repositoryFreeProviderCheck });
  const project = captured?.installedProject;
  const organization = captured?.organization === undefined ? undefined : loadInstalledOrganizationRuntime(captured.organization);
  const retentionPath = runtimeEnv["KEEP_MEMORY_RETENTION_PROFILE"];
  const capturedRetention = retentionPath === undefined ? undefined : loadMemoryRetentionProfile(retentionPath, organizationProvider ? "organization" : "owner");
  const memoryRetentionPolicy = capturedRetention === undefined ? undefined : {
    schema: capturedRetention.schema, authority: capturedRetention.authority, purposes: capturedRetention.purposes,
  };
  mkdirSync(dataDir, { recursive: true });
  const ownerTokenPath = join(dataDir, "owner-token");
  let expectedOwnerToken: string | undefined;
  let presentedOwnerToken: string | undefined;
  if (projectCommand) {
    try { writeFileSync(ownerTokenPath, `${randomBytes(32).toString("hex")}\n`, { flag: "wx", mode: 0o600 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    expectedOwnerToken = readProtectedToken(ownerTokenPath, "owner authority token");
    const presentedPath = runtimeEnv["KEEP_OWNER_TOKEN_FILE"];
    presentedOwnerToken = runtimeEnv["KEEP_OWNER_TOKEN"] ?? (presentedPath ? readProtectedToken(presentedPath, "presented owner authority token") : expectedOwnerToken);
  }

  // Remote boot must precede all mutable app state. Until A10 moves this memory composition behind the admitted app,
  // probation memory is therefore local-only; remote mode remains honest rather than writing before release admission.
  const memory = (() => { const memoryProvider = createConfiguredProvider(captured?.memoryProvider ?? runtime!.memoryProvider); const memSpine = new Spine(new FileSpineStore(join(dataDir, "memory")), new InProcessLock(), new SchemaRegistry()); return new MemoryStore(memSpine, new ModelGateway(memoryProvider)); })();
  const app = composeKeep({
    dataDir,
    ...(memoryRetentionPolicy === undefined ? {} : { memoryRetentionPolicy }),
    ...(semanticEncoder ? { semanticEncoder } : {}),
    ...(workerId === undefined ? {} : { projectRuntimeOwnerId: workerId, projectRuntimePaused: argv.includes("--paused") }),
    ...(domainSurfaceRequested ? { enableDomainWorkflows: true as const } : {}),
    frontDoorMemory: memory,
    ...(provider.mode === "local"
      ? { provider: createConfiguredProvider(provider), ...(captured?.residency ? { residency: captured.residency } : {}) }
      : provider.authority === "owner"
        ? { ownerProvider: providerDescriptor(provider), ...(captured?.externalRouting ? { externalRouting: captured.externalRouting } : provider.externalRouting ? { externalRouting: provider.externalRouting } : {}), remoteProcessing: captured?.remoteProcessing ?? runtime!.remoteProcessing!, residency: captured?.residency ?? runtime!.residency! }
        : { remoteProvider: providerDescriptor(provider), ...(captured?.externalRouting ? { externalRouting: captured.externalRouting } : provider.externalRouting ? { externalRouting: provider.externalRouting } : {}), verifiedRelease: releaseBoot!, remoteProcessing: captured?.remoteProcessing ?? runtime!.remoteProcessing!, residency: organization?.residency ?? captured?.residency ?? runtime!.residency! }),
    ...(project ? {
      repositoryMaterialization: { sourceDir: project.repository.root, workspaceBase: project.workspaceBase.root, repoRef: project.repoRef, commit: project.revision, baseBranch: project.baseBranch },
      sourceLanding: true,
      testCommand: project.testCommand,
      projectPosture: project.posture,
      runtimePaths: { repository: project.repository.root, workspace: project.workspaceBase.root },
    } : runtime?.repository && runtime.workspace
      ? { repoDir: runtime.repository.root, runtimePaths: { repository: runtime.repository.root, workspace: runtime.workspace.root } }
      : {}),
    ...(organization ? { identity: organization.identity, delegationParentFor: organization.parentFor } : {}),
  });

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const io: CliIO = {
    write: (text) => process.stdout.write(text + "\n"),
    prompt: (question) => new Promise<string>((resolve) => rl.question(question, (a) => resolve(a.trim()))),
  };

  // `solve` is intentionally absent until a real provider+repo are configured; cli_core reports this honestly.
  const deps: CliDeps = { app, readFile: (p) => readFileSync(p, "utf8"), tokenStore: new FileGatewayTokenStore(join(dataDir, "gateway-token")), ...(presentedOwnerToken === undefined ? {} : { gatewayToken: presentedOwnerToken }), ...(expectedOwnerToken === undefined ? {} : { gatewayExpectedToken: expectedOwnerToken }),
    ...(workerId === undefined ? {} : { serveGateway: async (workerApp, options) => {
      if (workerApp.projectRuntime === undefined) throw new Error("native project worker requires a durable runtime");
      const handle = await startGatewayServer(workerApp, { ...options, worker: { id: workerId,
        onStopped: () => { recordNativeWorker(dataDir, { workerId, pid: process.pid, origin: handle.origin, tokenFile: join(dataDir, "gateway-token") }, "stopped"); },
      } });
      const receipt = recordNativeWorker(dataDir, { workerId, pid: process.pid, origin: handle.origin, tokenFile: join(dataDir, "gateway-token") }, "ready");
      if (managedId !== undefined) process.send!(receipt);
      return handle;
    } }),
  };

  try {
    const result = await runCli(argv, io, deps);
    return result.exitCode;
  } finally {
    rl.close();
  }
}

function readProtectedToken(path: string, label: string): string {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size < 2 || stat.size > 8_193 || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) throw new Error(`${label} must be a bounded mode-0600 regular file`);
  const value = readFileSync(path, "utf8").replace(/\r?\n$/u, "");
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error(`${label} is malformed`);
  return value;
}

function capturedProvider(contract: CapturedRuntimeContract, credential: string | undefined) {
  if (contract.provider.mode === "local") return contract.provider;
  if (!credential && !(contract.provider.authority === "owner" && contract.provider.location === "local")) throw new Error("configured provider credential is empty");
  return { ...contract.provider, ...(contract.externalRouting ? { externalRouting: contract.externalRouting } : {}), apiKey: credential ?? "keep-owner-local-no-token" } as const;
}

function providerDescriptor(provider: Exclude<ReturnType<typeof capturedProvider>, { readonly mode: "local" }>) {
  return { mode: provider.mode, baseUrl: provider.baseUrl, model: provider.model, apiKey: provider.apiKey || "keep-owner-local-no-token" } as const;
}

async function loadCapturedCredential(reference: CredentialReference | undefined, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  if (!reference) return undefined;
  let value: string;
  if (reference.kind === "environment") {
    value = env[reference.name] ?? "";
    delete env[reference.name];
    delete process.env[reference.name];
  } else if (reference.kind === "file") {
    const stat = statSync(reference.path);
    if (!stat.isFile() || stat.size < 1 || stat.size > 8_192) throw new Error("provider credential file must be a nonempty bounded regular file");
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) throw new Error("provider credential file must use mode 0600 or stricter");
    value = readFileSync(reference.path, "utf8").replace(/\r?\n$/u, "");
  } else {
    if (process.stdin.isTTY) throw new Error("stdin credential source requires non-terminal stdin");
    const chunks: Buffer[] = []; let size = 0;
    for await (const chunk of process.stdin) { const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)); size += bytes.length; if (size > 8_193) throw new Error("stdin provider credential exceeds 8192 bytes"); chunks.push(bytes); }
    value = Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/u, "");
  }
  if (!value || value.length > 8_192 || value.includes("\0") || value !== value.trim()) throw new Error("provider credential is malformed");
  return value;
}

// Executed directly (node dist/src/cli/keep.js ...): run the CLI with process argv.
if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code)).catch((err) => {
    process.stderr.write(`fatal: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
