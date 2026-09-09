/** Resource-gated materialization for official SWE-bench records. No network fetch is implicit. */
import { execFile } from "node:child_process";
import { mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
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

/** Clone an operator-provided mirror and pin the exact dataset commit. Hidden tests are not materialized here. */
export async function materializeOfficialTask(task: EvalTask, mirrorDir: string, workspaceBase: string): Promise<OfficialTaskMaterialization> {
  if (!/^[0-9a-f]{40}$/u.test(task.baseCommit)) throw new Error("official SWE-bench materialization requires an exact 40-hex base commit");
  if (!task.testPatch) throw new Error("official SWE-bench task is missing test_patch");
  const mirror = await realpath(mirrorDir);
  await mkdir(workspaceBase, { recursive: true });
  const base = await realpath(workspaceBase);
  const safeId = task.instanceId.replace(/[^A-Za-z0-9._-]/gu, "_");
  const projectDir = resolve(base, safeId);
  const rel = relative(base, projectDir);
  if (!rel || rel.startsWith("..") || rel.startsWith(sep)) throw new Error("official task workspace escapes its base");
  try {
    await exec("git", ["clone", "--no-checkout", "--", mirror, projectDir], { env: ENV, maxBuffer: 32 * 1024 * 1024 });
    await exec("git", ["checkout", "--detach", task.baseCommit], { cwd: projectDir, env: ENV });
    const observed = (await exec("git", ["rev-parse", "HEAD"], { cwd: projectDir, env: ENV })).stdout.trim();
    if (observed !== task.baseCommit) throw new Error("official task checkout identity mismatch");
    return Object.freeze({ task: publicTask(task), projectDir, cleanup: () => rm(projectDir, { recursive: true, force: true }) });
  } catch (error) {
    await rm(projectDir, { recursive: true, force: true });
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
  try {
    const solution = deepFreeze(structuredClone(await input.solve(materialized.task, materialized.projectDir)));
    await applyHiddenTests(input.task, materialized.projectDir);
    const judgment = await input.judge(input.task, materialized.projectDir, solution);
    return Object.freeze({ solution, judgment });
  } finally {
    await materialized.cleanup();
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
