import { constants, closeSync, existsSync, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { canonicalize } from "../spine/event.js";
import { ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";

export interface SoloReleaseObservation {
  readonly startupMs: number;
  readonly p95LatencyMs: number;
  readonly configurationDigest: string;
  readonly authorityDigest: string;
  readonly behaviorDigest: string;
  readonly installedSubjectDigest: string;
  readonly ownerCount: 1;
}

export interface SoloPerformanceObservation {
  readonly startupMs: number;
  readonly p95LatencyMs: number;
}

export interface SoloReleaseBaseline extends SoloReleaseObservation {
  readonly schemaVersion: 1;
  readonly startupCeilingMs: number;
  readonly p95LatencyCeilingMs: number;
  readonly baselineDigest: string;
}

export type SoloNonRegressionAdmission =
  | { readonly admitted: true; readonly baselineDigest: string }
  | { readonly admitted: false; readonly reasons: readonly string[] };

const HEX64 = /^[a-f0-9]{64}$/u;
const BASELINE_KEYS = ["authorityDigest", "baselineDigest", "behaviorDigest", "configurationDigest", "installedSubjectDigest", "ownerCount", "p95LatencyCeilingMs", "p95LatencyMs", "schemaVersion", "startupCeilingMs", "startupMs"].sort().join(",");

/** Capture one immutable, installed-subject-bound n=1 release baseline. */
export function captureSoloReleaseBaseline(
  observation: SoloReleaseObservation,
  ceilings: { readonly startupMs: number; readonly p95LatencyMs: number },
): SoloReleaseBaseline {
  const captured = captureObservation(observation);
  const startupCeilingMs = duration(ceilings.startupMs, "startup ceiling");
  const p95LatencyCeilingMs = duration(ceilings.p95LatencyMs, "latency ceiling");
  if (captured.startupMs > startupCeilingMs || captured.p95LatencyMs > p95LatencyCeilingMs) throw new Error("solo observation already exceeds its proposed ceiling");
  const body = { schemaVersion: 1 as const, ...captured, startupCeilingMs, p95LatencyCeilingMs };
  return Object.freeze({ ...body, baselineDigest: digest(body) });
}

/** One comparison returning every defect. It never benchmarks, retries, renews, or mutates the baseline. */
export function verifySoloNonRegression(baselineInput: SoloReleaseBaseline, currentInput: SoloReleaseObservation): SoloNonRegressionAdmission {
  let baseline: SoloReleaseBaseline;
  let current: SoloReleaseObservation;
  try { baseline = captureBaseline(baselineInput); current = captureObservation(currentInput); }
  catch (error) { return Object.freeze({ admitted: false, reasons: Object.freeze([error instanceof Error ? error.message : String(error)]) }); }
  const reasons: string[] = [];
  if (current.startupMs > baseline.startupCeilingMs) reasons.push(`startup ${current.startupMs}ms exceeds pinned ${baseline.startupCeilingMs}ms ceiling`);
  if (current.p95LatencyMs > baseline.p95LatencyCeilingMs) reasons.push(`p95 latency ${current.p95LatencyMs}ms exceeds pinned ${baseline.p95LatencyCeilingMs}ms ceiling`);
  if (current.configurationDigest !== baseline.configurationDigest) reasons.push("single-owner configuration identity changed");
  if (current.authorityDigest !== baseline.authorityDigest) reasons.push("single-owner authority identity changed");
  if (current.behaviorDigest !== baseline.behaviorDigest) reasons.push("single-owner behavior identity changed");
  if (current.installedSubjectDigest !== baseline.installedSubjectDigest) reasons.push("installed release subject changed");
  return reasons.length === 0
    ? Object.freeze({ admitted: true, baselineDigest: baseline.baselineDigest })
    : Object.freeze({ admitted: false, reasons: Object.freeze(reasons) });
}

/** Durable write-once carrier. Authenticity remains the release authority's responsibility. */
export class FileSoloReleaseBaselineStore {
  constructor(private readonly path: string) {}

  load(): SoloReleaseBaseline | undefined {
    let fd: number;
    try { fd = openSync(this.path, constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
    try {
      const stat = fstatSync(fd);
      // A crash after the atomic hard-link publication but before temporary-name cleanup can leave
      // two names for the same valid inode. Do not turn that recoverable state into a false loss.
      if (!stat.isFile() || stat.size < 2 || stat.size > 64 * 1024 || (stat.mode & 0o077) !== 0 || (process.getuid !== undefined && stat.uid !== process.getuid())) throw new Error("solo baseline carrier is unsafe");
      try { return captureBaseline(JSON.parse(readFileSync(fd, "utf8")) as SoloReleaseBaseline); }
      catch (error) { throw new Error(`solo baseline carrier is malformed or content-invalid: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
    } finally { closeSync(fd); }
  }

  pin(baselineInput: SoloReleaseBaseline): void {
    const baseline = captureBaseline(baselineInput);
    ensureDurableDir(NODE_IO, dirname(this.path));
    const temporary = join(dirname(this.path), `.${basename(this.path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
    let fd: number | undefined;
    try {
      fd = openSync(temporary, "wx", 0o600);
      writeFileSync(fd, `${canonicalize(baseline)}\n`, "utf8");
      fsyncSync(fd); closeSync(fd); fd = undefined;
      linkSync(temporary, this.path); // atomic create-without-replacement, including concurrent writers
      fsyncDir(NODE_IO, dirname(this.path));
      unlinkSync(temporary);
      fsyncDir(NODE_IO, dirname(this.path));
    } catch (error) {
      if (fd !== undefined) closeSync(fd);
      try { unlinkSync(temporary); } catch { /* absent */ }
      throw error;
    }
  }
}

export function soloReleaseIdentityDigest(value: unknown): string { return digest(value); }

/**
 * Construct the current n=1 contract from code-owned product identities plus externally observed performance and the
 * package/release measurement made by composition. Callers cannot assert authority/configuration/behavior identities.
 */
export function captureCanonicalSoloObservation(performance: SoloPerformanceObservation, installedSubjectDigest: string): SoloReleaseObservation {
  return captureObservation({
    startupMs: performance.startupMs,
    p95LatencyMs: performance.p95LatencyMs,
    ownerCount: 1,
    configurationDigest: digest({ schema: "keep.solo-configuration/v1", providerOptional: true, projects: true, frontDoor: true }),
    authorityDigest: digest({ schema: "keep.solo-authority/v1", owner: "implicit-local-owner", resolver: "omitted" }),
    behaviorDigest: digest({ schema: "keep.solo-behavior/v1", routes: "canonical-local-product", enterpriseActivation: false }),
    installedSubjectDigest,
  });
}

/** Measure exactly the package-declared shipped bytes, excluding repository/dependency/runtime state by construction. */
export function captureInstalledPackageSubjectDigest(packageRoot: string): string {
  const root = realpathSync(packageRoot);
  const manifestPath = join(root, "package.json");
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8")) as { files?: unknown };
  if (!Array.isArray(manifest.files) || manifest.files.length < 1 || manifest.files.length > 1_024 || manifest.files.some((entry) => typeof entry !== "string")) throw new Error("installed package manifest has no bounded explicit file set");
  // npm auto-includes conventional README/LICENSE files when present, but neither is mandatory for a valid package.
  const declared = ["package.json", ...["README.md", "LICENSE"].filter((path) => existsSync(join(root, path))), ...(manifest.files as string[])];
  const rows = new Map<string, string>();
  const visited = new Set<string>();
  let totalBytes = 0, totalFiles = 0;
  const visit = (operand: string): void => {
    const normalizedOperand = operand.replace(/[\\/]+$/u, "");
    if (normalizedOperand.length < 1 || isAbsolute(normalizedOperand) || normalizedOperand.includes("\0") || normalizedOperand.split(/[\\/]/u).some((part) => part === "" || part === "." || part === "..")) throw new Error("installed package manifest contains an unsafe path");
    const absolute = resolve(root, normalizedOperand), rel = relative(root, absolute).split(sep).join("/");
    if (rel === ".." || rel.startsWith("../")) throw new Error("installed package path escapes its root");
    if (visited.has(rel)) return;
    visited.add(rel);
    if (!existsSync(absolute)) throw new Error(`installed package is missing declared path ${rel}`);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`installed package contains a symbolic link at ${rel}`);
    if (stat.isDirectory()) {
      for (const name of readdirSync(absolute).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) visit(`${normalizedOperand}/${name}`);
      return;
    }
    if (!stat.isFile()) throw new Error(`installed package contains a special entry at ${rel}`);
    const fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = fstatSync(fd, { bigint: true }), bytes = readFileSync(fd), after = fstatSync(fd, { bigint: true });
      if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || BigInt(bytes.length) !== after.size) throw new Error(`installed package file changed while measured at ${rel}`);
      totalBytes += bytes.length; totalFiles += 1;
      if (totalFiles > 100_000 || totalBytes > 4 * 1024 * 1024 * 1024) throw new Error("installed package exceeds measurement bounds");
      const mode = Number(after.mode) & 0o111 ? "100755" : "100644";
      rows.set(rel, `${rel}\0${mode}\0${bytes.length}\0${createHash("sha256").update(bytes).digest("hex")}\0`);
    } finally { closeSync(fd); }
  };
  for (const operand of [...new Set(declared)].sort()) visit(operand);
  const measuredManifest = rows.get("package.json");
  const initialManifestDigest = createHash("sha256").update(manifestBytes).digest("hex");
  if (measuredManifest === undefined || !measuredManifest.endsWith(`${initialManifestDigest}\0`)) throw new Error("installed package manifest changed while measured");
  return createHash("sha256").update(`keep.installed-package-subject/v1\0${[...rows.entries()].sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map(([, row]) => row).join("")}`).digest("hex");
}

function captureObservation(input: SoloReleaseObservation): SoloReleaseObservation {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new Error("N=1 observation must be an object");
  const startupMs = duration(input.startupMs, "startup measurement"), p95LatencyMs = duration(input.p95LatencyMs, "latency measurement");
  if (input.ownerCount !== 1) throw new Error("N=1 observation must have exactly one owner");
  for (const [name, value] of [["configuration", input.configurationDigest], ["authority", input.authorityDigest], ["behavior", input.behaviorDigest], ["installed subject", input.installedSubjectDigest]] as const) {
    if (!HEX64.test(value)) throw new Error(`${name} digest must be lowercase SHA-256`);
  }
  return Object.freeze({ startupMs, p95LatencyMs, configurationDigest: input.configurationDigest, authorityDigest: input.authorityDigest, behaviorDigest: input.behaviorDigest, installedSubjectDigest: input.installedSubjectDigest, ownerCount: 1 });
}

function captureBaseline(input: SoloReleaseBaseline): SoloReleaseBaseline {
  if (input === null || typeof input !== "object" || Array.isArray(input) || Object.keys(input).sort().join(",") !== BASELINE_KEYS || input.schemaVersion !== 1) throw new Error("stored solo baseline has an invalid schema");
  const observation = captureObservation(input);
  const startupCeilingMs = duration(input.startupCeilingMs, "startup ceiling"), p95LatencyCeilingMs = duration(input.p95LatencyCeilingMs, "latency ceiling");
  if (observation.startupMs > startupCeilingMs || observation.p95LatencyMs > p95LatencyCeilingMs) throw new Error("stored solo baseline exceeds its ceilings");
  const body = { schemaVersion: 1 as const, ...observation, startupCeilingMs, p95LatencyCeilingMs };
  if (!HEX64.test(input.baselineDigest) || input.baselineDigest !== digest(body)) throw new Error("stored solo baseline digest mismatch");
  return Object.freeze({ ...body, baselineDigest: input.baselineDigest });
}

function duration(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer milliseconds`);
  return value;
}

function digest(value: unknown): string { return createHash("sha256").update(canonicalize(value)).digest("hex"); }
