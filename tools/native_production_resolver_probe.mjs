#!/usr/bin/env node
/** Real read-only bind-mount probe for the non-authorizing native production resolver. */
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statfsSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { encodeCanonical } from "../dist/src/eir/canonical.js";
import { productionDeploymentFixture } from "../dist/test/fixtures/native_v2_production_deployment.js";
import { nativeDeploymentBaseDigest } from "../dist/src/platform/native_boundary_protocol_v2.js";
import { nativeProductionResolutionTranscriptDigest } from "../dist/src/platform/native_production_resolution_observation.js";

const repository = resolve(fileURLToPath(new URL("..", import.meta.url)));
const resolver = process.env.KEEP_PRODUCTION_RESOLVER_PROBE ??
  join(repository, "native/target/x86_64-unknown-linux-musl/release/keep-native-production-resolver-probe");
const scratch = mkdtempSync(join(tmpdir(), "keep-production-resolver-probe-"));
const authority = join(scratch, "authority");
const payload = join(scratch, "payload");
const mounted = [];
const attack = process.env.KEEP_RESOLVER_ATTACK ?? "none";
const admittedAttacks = new Set(["none", "writable-root", "manifest-mode", "manifest-trailing", "manifest-oversize", "manifest-address", "development-trust", "duplicate-artifact", "extra-artifact", "artifact-mode", "artifact-symlink", "artifact-digest", "artifact-hardlink", "deployment-id", "request-traversal", "root-alias", "root-bind-alias", "root-mount-substitution", "ancestor-symlink", "ancestor-mount", "descendant-mount", "authority-descendant-mount"]);
const expectedRefusal = new Map([
  ["writable-root", "configured release root policy is invalid"],
  ["manifest-mode", "deployment object metadata is not immutable root-owned data"],
  ["manifest-trailing", "deployment object is not canonical production schema"],
  ["manifest-oversize", "deployment object could not be captured"],
  ["manifest-address", "deployment object content address does not match"],
  ["development-trust", "deployment object is not canonical production schema"],
  ["duplicate-artifact", "deployment object is not canonical production schema"],
  ["extra-artifact", "deployment object is not canonical production schema"],
  ["artifact-mode", "deployment object metadata is not immutable root-owned data"],
  ["artifact-symlink", "deployment object could not be captured"],
  ["artifact-digest", "deployment object content address does not match"],
  ["artifact-hardlink", "deployment object could not be captured"],
  ["deployment-id", "deployment object identity does not match the request"],
  ["request-traversal", "resolver request identity is malformed"],
  ["root-alias", "configured release root policy is invalid"],
  ["root-bind-alias", "configured release root policy is invalid"],
  ["root-mount-substitution", "configured release root identity does not match"],
  ["ancestor-symlink", "configured release root could not be pinned"],
  ["ancestor-mount", "configured release root could not be pinned"],
  ["descendant-mount", "deployment object could not be captured"],
  ["authority-descendant-mount", "deployment object could not be captured"],
]);
if (!admittedAttacks.has(attack)) throw new Error(`unknown resolver attack ${attack}`);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const rootIdentity = (spec, path) => {
  const [declaredDevice, declaredInode, declaredUid, declaredGid, declaredPermissions, mountId,
    declaredFilesystemType, declaredReadOnly] = spec.split(":").map(BigInt);
  const status = statSync(path, { bigint: true });
  const filesystem = statfsSync(path, { bigint: true });
  const observed = { device: status.dev, inode: status.ino, uid: status.uid, gid: status.gid,
    permissions: status.mode & 0o7777n, filesystemType: filesystem.type };
  if (observed.device !== declaredDevice || observed.inode !== declaredInode || observed.uid !== declaredUid ||
      observed.gid !== declaredGid || observed.permissions !== declaredPermissions ||
      observed.filesystemType !== declaredFilesystemType || declaredReadOnly !== 1n)
    throw new Error(`independent root identity disagrees with resolver enrollment for ${path}`);
  return { ...observed, mountId, readOnly: true };
};
const leafIdentity = (path) => {
  const status = statSync(path, { bigint: true });
  return { device: status.dev, inode: status.ino, uid: status.uid, gid: status.gid, mode: status.mode, size: status.size };
};
const artifactLeafIdentity = (path) => {
  const status = statSync(path, { bigint: true });
  return { ...leafIdentity(path), links: status.nlink };
};

try {
  mkdirSync(join(authority, "deployments/sha256"), { recursive: true });
  mkdirSync(join(payload, "artifacts/sha256"), { recursive: true });
  const executableBytes = { helper: Buffer.from("helper"), trampoline: Buffer.from("trampoline"), prober: Buffer.from("prober"), provisioner: Buffer.from("provisioner"), role: Buffer.from("role") };
  const executableDigests = Object.fromEntries(Object.entries(executableBytes).map(([kind, bytes]) => [kind, digest(bytes)]));
  for (const [kind, bytes] of Object.entries(executableBytes)) {
    const path = join(payload, "artifacts/sha256", executableDigests[kind]);
    if (attack === "artifact-symlink" && kind === "helper") {
      const outside = join(payload, "helper-outside");
      writeFileSync(outside, bytes, { mode: 0o555 });
      chmodSync(outside, 0o555);
      symlinkSync(outside, path);
    } else {
      writeFileSync(path, attack === "artifact-digest" && kind === "helper" ? Buffer.from("mutant") : bytes, { mode: 0o555 });
      chmodSync(path, attack === "artifact-mode" && kind === "helper" ? 0o755 : 0o555);
      if (attack === "artifact-hardlink" && kind === "helper") linkSync(path, join(payload, "helper-hardlink"));
    }
  }
  const fixture = productionDeploymentFixture(executableDigests);
  const fixtureRecord = fixture;
  const payloadRecord = fixtureRecord.payload;
  if (attack === "development-trust") payloadRecord.trustClass = "development";
  if (attack === "duplicate-artifact") payloadRecord.artifacts.splice(4, 0, structuredClone(payloadRecord.artifacts[3]));
  if (attack === "extra-artifact") {
    const extra = structuredClone(payloadRecord.artifacts[3]);
    extra.artifactId = "role.net.extra";
    payloadRecord.artifacts.splice(4, 0, extra);
  }
  if (["development-trust", "duplicate-artifact", "extra-artifact"].includes(attack)) {
    payloadRecord.deploymentBaseDigest = nativeDeploymentBaseDigest(payloadRecord);
    fixtureRecord.payloadDigest = digest(Buffer.from(encodeCanonical(payloadRecord)));
  }
  let manifest = Buffer.from(encodeCanonical(fixture));
  if (attack === "manifest-trailing") manifest = Buffer.concat([manifest, Buffer.from([0])]);
  if (attack === "manifest-oversize") manifest = Buffer.alloc(1_048_577, 0xa1);
  const manifestDigest = digest(manifest);
  const requestedDigest = attack === "manifest-address" ? "11".repeat(32) : manifestDigest;
  const manifestPath = join(authority, "deployments/sha256", `${requestedDigest}.cbor`);
  writeFileSync(manifestPath, manifest, { mode: 0o444 });
  chmodSync(manifestPath, attack === "manifest-mode" ? 0o644 : 0o444);
  for (const root of [authority, payload]) {
    chmodSync(root, 0o555);
    execFileSync("/usr/bin/mount", ["--bind", root, root]);
    mounted.push(root);
    execFileSync("/usr/bin/mount", ["-o", "remount,bind,ro", root]);
  }
  const observeRoot = (root) => {
    const observed = spawnSync(resolver, ["--observe-root", root], { encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } });
    if (observed.status !== 0 || !/^ROOT\t[0-9:]+\n$/.test(observed.stdout))
      throw new Error(`root enrollment failed: ${observed.stderr}`);
    return observed.stdout.trim().slice(5);
  };
  const authoritySpec = observeRoot(authority);
  const payloadSpec = observeRoot(payload);
  if (attack === "writable-root") execFileSync("/usr/bin/mount", ["-o", "remount,bind,rw", authority]);
  let authorityArgument = authority;
  if (attack === "ancestor-symlink") {
    const alias = join(scratch, "ancestor-alias");
    symlinkSync(scratch, alias);
    authorityArgument = join(alias, "authority");
  }
  if (attack === "ancestor-mount") {
    const ancestor = join(scratch, "ancestor-mount");
    mkdirSync(ancestor);
    execFileSync("/usr/bin/mount", ["--bind", tmpdir(), ancestor]);
    mounted.push(ancestor);
    authorityArgument = join(ancestor, scratch.slice(tmpdir().length + 1), "authority");
  }
  if (attack === "descendant-mount") {
    const substitute = join(scratch, "substitute-artifacts");
    mkdirSync(substitute);
    for (const [kind, bytes] of Object.entries(executableBytes)) {
      const path = join(substitute, executableDigests[kind]);
      writeFileSync(path, bytes, { mode: 0o555 });
      chmodSync(path, 0o555);
    }
    const target = join(payload, "artifacts/sha256");
    execFileSync("/usr/bin/mount", ["--bind", substitute, target]);
    mounted.push(target);
  }
  if (attack === "authority-descendant-mount") {
    const substitute = join(scratch, "substitute-deployments");
    mkdirSync(substitute);
    writeFileSync(join(substitute, `${requestedDigest}.cbor`), manifest, { mode: 0o444 });
    const target = join(authority, "deployments/sha256");
    execFileSync("/usr/bin/mount", ["--bind", substitute, target]);
    mounted.push(target);
  }
  if (attack === "root-mount-substitution") {
    const substitute = join(scratch, "substitute-authority");
    mkdirSync(join(substitute, "deployments/sha256"), { recursive: true });
    writeFileSync(join(substitute, `deployments/sha256/${requestedDigest}.cbor`), manifest, { mode: 0o444 });
    chmodSync(substitute, 0o555);
    execFileSync("/usr/bin/umount", [authority]);
    mounted.splice(mounted.indexOf(authority), 1);
    execFileSync("/usr/bin/mount", ["--bind", substitute, authority]);
    mounted.push(authority);
    execFileSync("/usr/bin/mount", ["-o", "remount,bind,ro", authority]);
  }
  let payloadArgument = payload;
  let effectivePayloadSpec = payloadSpec;
  if (attack === "root-alias") { payloadArgument = authorityArgument; effectivePayloadSpec = authoritySpec; }
  if (attack === "root-bind-alias") {
    payloadArgument = join(scratch, "authority-bind-alias");
    mkdirSync(payloadArgument);
    execFileSync("/usr/bin/mount", ["--bind", authority, payloadArgument]);
    mounted.push(payloadArgument);
    execFileSync("/usr/bin/mount", ["-o", "remount,bind,ro", payloadArgument]);
    effectivePayloadSpec = observeRoot(payloadArgument);
  }
  const requestedDeployment = attack === "deployment-id" ? "deploy.other" : attack === "request-traversal" ? "../deploy" : "deploy.1";
  const resolverArguments = [authorityArgument, authoritySpec, payloadArgument, effectivePayloadSpec,
    requestedDeployment, requestedDigest];
  const effectTrace = join(scratch, "effects.strace");
  const executable = attack === "none" ? "/usr/bin/strace" : resolver;
  const executableArguments = attack === "none"
    ? ["-qq", "-f", "-e", "trace=all", "-o", effectTrace, resolver, ...resolverArguments]
    : resolverArguments;
  const result = spawnSync(executable, executableArguments,
    { encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } });
  if (attack !== "none") {
    const exactStderr = `REFUSED\t${expectedRefusal.get(attack)}\n`;
    if (result.status !== 2 || result.stdout !== "" || result.stderr !== exactStderr)
      throw new Error(`resolver accepted or mishandled ${attack}: status=${result.status} stdout=${result.stdout} stderr=${result.stderr}`);
    process.stdout.write(`[native-production-resolver-probe] REFUSED — ${attack}\n`);
    process.exitCode = 0;
  } else {
    if (result.status !== 0 || !result.stdout.startsWith(`OBSERVED\tdeploy.1\t${manifestDigest}\t`))
      throw new Error(`resolver probe failed: status=${result.status} stdout=${result.stdout} stderr=${result.stderr}`);
  const tracedEffects = readFileSync(effectTrace, "utf8");
  const allowedSyscalls = new Set(["arch_prctl", "brk", "close", "execve", "exit_group", "fchmod", "fcntl",
    "fstat", "fstatfs", "lseek", "memfd_create", "mmap", "mprotect", "munmap", "open", "openat2", "poll",
    "read", "rt_sigaction", "rt_sigprocmask", "set_tid_address", "sigaltstack", "statx", "write"]);
  const calls = [...tracedEffects.matchAll(/^(?:\d+\s+)?([a-z_][a-z0-9_]*)\(/gm)].map((match) => match[1]);
  const unexpectedSyscall = calls.find((call) => !allowedSyscalls.has(call));
  if (unexpectedSyscall) throw new Error(`resolver performed non-allowlisted syscall ${unexpectedSyscall}: ${tracedEffects}`);
  if (/\bopen(?:at2?)?\([^\n]*(?:O_WRONLY|O_RDWR|O_CREAT)/.test(tracedEffects))
    throw new Error(`resolver opened a pathname for writing: ${tracedEffects}`);
  if (/\/dev\/kvm|\/sys\/fs\/cgroup|credential|evidence/i.test(tracedEffects))
    throw new Error(`resolver touched authority-bearing or evidence state: ${tracedEffects}`);
  if ((tracedEffects.match(/\bexecve\s*\(/g) ?? []).length !== 1)
    throw new Error(`resolver process trace has unexpected exec count: ${tracedEffects}`);
  const fields = result.stdout.trim().split("\t");
  if (fields.length !== 6 || !/^[0-9a-f]{64}$/.test(fields[3]) || Number(fields[4]) !== manifest.length)
    throw new Error("resolver observation shape is malformed");
  const artifactId = { helper: "helper", trampoline: "trampoline", prober: "prober", provisioner: "provisioner.net", role: "role.net" };
  for (const kind of ["helper", "trampoline", "prober", "provisioner", "role"])
    if (!fields[5].includes(`${Buffer.from(artifactId[kind]).toString("hex")}:${Buffer.from(kind).toString("hex")}:${executableDigests[kind]}:`))
      throw new Error(`missing ${kind} identity`);
  const parity = nativeProductionResolutionTranscriptDigest({
    authorityRoot: rootIdentity(authoritySpec, authority), payloadRoot: rootIdentity(payloadSpec, payload), manifestLeaf: leafIdentity(manifestPath),
    deploymentId: "deploy.1", manifestDigest,
    artifacts: ["helper", "prober", "provisioner", "role", "trampoline"].map((kind) => ({ artifactId: artifactId[kind], kind,
      digest: executableDigests[kind], leaf: artifactLeafIdentity(join(payload, "artifacts/sha256", executableDigests[kind])),
      byteLength: BigInt(executableBytes[kind].length) })),
  });
  if (parity !== fields[3]) throw new Error(`TypeScript/Rust transcript divergence: ${parity} != ${fields[3]}`);
  process.stdout.write(`[native-production-resolver-probe] OK — ${fields[3]}\n`);
  }
} finally {
  for (const root of mounted.reverse()) spawnSync("/usr/bin/umount", [root], { stdio: "ignore" });
  rmSync(scratch, { recursive: true, force: true });
}
