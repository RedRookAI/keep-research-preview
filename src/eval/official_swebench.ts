/** Resource-gated materialization for official SWE-bench records. No network fetch is implicit. */
import { execFile } from "node:child_process";
import { mkdir, realpath, rm, writeFile, lstat } from "node:fs/promises";
import { join, relative, resolve, sep, isAbsolute } from "node:path";
import { promisify } from "node:util";
import type { EvalTask } from "./swebench_task.js";

const exec = promisify(execFile);
const ENV = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: "/nonexistent", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" };

export interface OfficialTaskMaterialization {
  readonly task: PublicOfficialTask;
  readonly projectDir: string;
  cleanup(): Promise<void>;
}
export type PublicOfficialTask = Omit<EvalTask, "testPatch" | "goldPatch">;

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function publicTask(task: EvalTask): PublicOfficialTask {
  const { testPatch: _hidden, goldPatch: _gold, ...visible } = task;
  return deepFreeze(structuredClone(visible));
}

/** Clone an operator-provided mirror into a NEW workspace (creation requests 0700;
 * platform permissions/umask apply) and pin the exact dataset commit. Hidden tests are not materialized here.
 * The workspace base is operator-owned; this is not an atomic defense against an
 * external actor replacing directory components during creation or cleanup. */
export async function materializeOfficialTask(task: EvalTask, mirrorDir: string, workspaceBase: string): Promise<OfficialTaskMaterialization> {
  if (!/^[0-9a-f]{40}$/u.test(task.baseCommit)) throw new Error("official SWE-bench materialization requires an exact 40-hex base commit");
  if (!task.testPatch) throw new Error("official SWE-bench task is missing test_patch");
  const mirror = await realpath(mirrorDir);
  await mkdir(workspaceBase, { recursive: true });
  const base = await realpath(workspaceBase);
  const safeId = task.instanceId.replace(/[^A-Za-z0-9._-]/gu, "_");
  const projectDir = resolve(base, safeId);
  const rel = relative(base, projectDir);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("official task workspace escapes its base");
  // Acquire before entering any cleanup catch. A failed clone gives us no right
  // to remove a preexisting file, directory (even empty), or symbolic link.
  try { await mkdir(projectDir, { mode: 0o700 }); }
  catch (error) {
    if ((error as { code?: string })?.code === "EEXIST") throw new Error("official task workspace already exists; refusing to reuse or remove it", { cause: error });
    throw error;
  }
  // safeId is one literal component beneath the already-canonical base. The
  // exclusive mkdir adds no symlink parent; do not follow a replacement with a
  // second realpath. Identity checks below are point-in-time, not an atomic jail.
  const owned = await lstat(projectDir, { bigint: true });
  if (!owned.isDirectory()) throw new Error("official task workspace identity changed during acquisition");
  let cleanupResult: Promise<void> | undefined;
  const cleanup = (): Promise<void> => cleanupResult ??= (async () => {
    let current;
    try { current = await lstat(projectDir, { bigint: true }); }
    catch (error) { if ((error as { code?: string })?.code === "ENOENT") return; throw error; }
    if (!current.isDirectory() || current.dev !== owned.dev || current.ino !== owned.ino) {
      throw new Error("official task workspace identity changed; refusing cleanup");
    }
    await rm(projectDir, { recursive: true, force: true });
  })(); // Fulfillment AND rejection are sticky: a second call never retries removal.
  try {
    await exec("git", ["clone", "--no-checkout", "--", mirror, projectDir], { env: ENV, maxBuffer: 32 * 1024 * 1024 });
    await exec("git", ["checkout", "--detach", task.baseCommit], { cwd: projectDir, env: ENV });
    const observed = (await exec("git", ["rev-parse", "HEAD"], { cwd: projectDir, env: ENV })).stdout.trim();
    if (observed !== task.baseCommit) throw new Error("official task checkout identity mismatch");
    return Object.freeze({ task: publicTask(task), projectDir, cleanup });
  } catch (error) {
    try { await cleanup(); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], "official materialization failed and cleanup was refused or failed"); }
    throw error;
  }
}

async function applyHiddenTests(task: EvalTask, projectDir: string): Promise<void> {
  const patchPath = join(projectDir, ".keep-hidden-tests.patch");
  await writeFile(patchPath, task.testPatch!, { encoding: "utf8", mode: 0o600, flag: "wx" });
  try { await exec("git", ["apply", "--index", "--whitespace=nowarn", patchPath], { cwd: projectDir, env: ENV, maxBuffer: 32 * 1024 * 1024 }); }
  finally { await rm(patchPath, { force: true }); }
}

/** The only complete official local-run path: solve on the exact public base, then materialize hidden tests and judge. */
export async function runOfficialTaskLocally<TSolution extends object, TJudgment>(input: {
  readonly task: EvalTask;
  readonly mirrorDir: string;
  readonly workspaceBase: string;
  readonly solve: (task: PublicOfficialTask, projectDir: string) => Promise<TSolution>;
  readonly judge: (task: EvalTask, projectDir: string, frozenSolution: Readonly<TSolution>) => Promise<TJudgment>;
}): Promise<{ readonly solution: Readonly<TSolution>; readonly judgment: TJudgment }> {
  const materialized = await materializeOfficialTask(input.task, input.mirrorDir, input.workspaceBase);
  let failed = false;
  let primaryError: unknown;
  try {
    const solution = deepFreeze(structuredClone(await input.solve(materialized.task, materialized.projectDir)));
    await applyHiddenTests(input.task, materialized.projectDir);
    const judgment = await input.judge(input.task, materialized.projectDir, solution);
    return Object.freeze({ solution, judgment });
  } catch (error) {
    failed = true; primaryError = error; throw error;
  } finally {
    try { await materialized.cleanup(); }
    catch (cleanupError) {
      if (failed) throw new AggregateError([primaryError, cleanupError], "official task failed and cleanup was refused or failed");
      throw cleanupError;
    }
  }
}

export interface OfficialRunPrerequisites { readonly ready: boolean; readonly missing: readonly string[]; }

/** A real run needs all three explicit resources; absence is a skip/refusal, never a synthetic score. */
export function officialRunPrerequisites(input: { containerRuntime: boolean; containerImage: boolean; remoteProvider: boolean }): OfficialRunPrerequisites {
  const missing = [!input.containerRuntime && "responding container runtime", !input.containerImage && "local SWE-bench image", !input.remoteProvider && "configured real provider"].filter((v): v is string => typeof v === "string");
  return Object.freeze({ ready: missing.length === 0, missing: Object.freeze(missing) });
}

export interface PrivateRunMeasurement {
  readonly runDate: string;
  readonly taskId: string;
  readonly providerClass: string;
  readonly model: string;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly costUsd: number;
  readonly resolved: boolean;
}
export interface PrivateDiagnosticsSink { write(record: Readonly<PrivateRunMeasurement>): Promise<void>; }
export type PrivateRunMilestone =
  | { readonly status: "unavailable"; readonly missing: readonly string[]; readonly score: null }
  | { readonly status: "completed"; readonly diagnostics: Readonly<PrivateRunMeasurement> };

function sanitizeMeasurement(raw: PrivateRunMeasurement): Readonly<PrivateRunMeasurement> {
  for (const [name, value] of [["promptTokens", raw.promptTokens], ["completionTokens", raw.completionTokens], ["costUsd", raw.costUsd]] as const) {
    if (!Number.isFinite(value) || value < 0) throw new Error(`invalid private-run ${name}`);
  }
  for (const [name, value] of [["runDate", raw.runDate], ["taskId", raw.taskId], ["providerClass", raw.providerClass], ["model", raw.model]] as const) {
    if (typeof value !== "string" || value.trim() === "") throw new Error(`invalid private-run ${name}`);
  }
  return Object.freeze({ runDate: raw.runDate, taskId: raw.taskId, providerClass: raw.providerClass, model: raw.model, promptTokens: raw.promptTokens, completionTokens: raw.completionTokens, costUsd: raw.costUsd, resolved: raw.resolved });
}

/** Execute only when every real resource exists; otherwise return an explicit null-score refusal without calling run. */
export async function executePrivateRunMilestone(input: {
  readonly prerequisites: OfficialRunPrerequisites;
  readonly run?: () => Promise<PrivateRunMeasurement>;
  readonly diagnosticsSink?: PrivateDiagnosticsSink;
}): Promise<PrivateRunMilestone> {
  if (!input.prerequisites.ready) return Object.freeze({ status: "unavailable", missing: Object.freeze([...input.prerequisites.missing]), score: null });
  if (!input.run || !input.diagnosticsSink) throw new Error("ready private run requires both an execution seam and durable diagnostics sink");
  const diagnostics = sanitizeMeasurement(await input.run());
  await input.diagnosticsSink.write(diagnostics);
  return Object.freeze({ status: "completed", diagnostics });
}
