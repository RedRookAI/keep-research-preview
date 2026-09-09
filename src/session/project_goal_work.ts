import { createHash } from "node:crypto";
import { isProjectId, type ProjectId } from "./project_id.js";
import type { NativeProjectCommand } from "./project_command.js";
import type { ProjectState } from "../autonomy/project_state.js";
import type { ProjectImplementationArtifact } from "../solve/project_loop_wiring.js";
import { projectImplementationDigest, type ProjectTestArtifact } from "../autonomy/project_test_stage.js";

export const GOAL_WORK_DOCUMENT = "native-goal-work-v1";
export const GOAL_PHASES = ["development", "qualification", "release"] as const;
export type GoalWorkPhase = typeof GOAL_PHASES[number];
export interface GoalWorkTask {
  readonly id: string;
  readonly goal: string;
  readonly kind: "goal" | "safeguard" | "hardening";
  readonly dependsOn: readonly string[];
  /** Named capabilities supplied by the host, never satisfied by a task's own label. */
  readonly requires: readonly string[];
  readonly due: GoalWorkPhase;
  readonly acceptance: "tested-proposal";
}
export interface GoalWorkDefinition {
  readonly objective: string;
  readonly tasks: readonly GoalWorkTask[];
  readonly maxTaskStarts: number;
}
export interface GoalTaskClaim { readonly jobId: string; readonly projectId?: ProjectId; }
export interface GoalTaskAcceptance {
  readonly jobId: string; readonly projectId: ProjectId; readonly checkpointRevision: number;
  readonly sourceDigest: string; readonly validationDigest: string;
  readonly kind: "tested-proposal";
}
export interface GoalWorkDocument {
  readonly schema: "keep.goal-work/v1";
  readonly creationId: string;
  readonly definition: GoalWorkDefinition;
  readonly binding: string;
  readonly principal: NativeProjectCommand["principal"];
  readonly phase: GoalWorkPhase;
  readonly active: boolean;
  readonly startsUsed: number;
  readonly claims: Readonly<Record<string, GoalTaskClaim>>;
  readonly accepted: Readonly<Record<string, GoalTaskAcceptance>>;
}
const ID = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,95}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA = /^[0-9a-f]{64}$/u;
function object(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("goal work must be an object");
  if (keys.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !keys.includes(key) && !optional.includes(key))) throw new Error("unknown or missing goal work field");
  return value as Record<string, unknown>;
}
function ids(value: unknown): asserts value is readonly string[] {
  if (!Array.isArray(value) || value.length > 4096 || value.some(id => typeof id !== "string" || !ID.test(id)) || new Set(value).size !== value.length) throw new Error("invalid goal work references");
}
export function captureGoalWorkDefinition(value: unknown): GoalWorkDefinition {
  // JSON capture strips caller aliases; the gateway accepts JSON, never executable objects.
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded ?? "") > 4 * 1024 * 1024) throw new Error("goal work definition exceeds 4 MiB");
  const row = object(JSON.parse(encoded), ["objective", "tasks", "maxTaskStarts"]);
  if (typeof row["objective"] !== "string" || !row["objective"].trim() || Buffer.byteLength(row["objective"]) > 900 * 1024) throw new Error("invalid persisted goal objective");
  const tasks = row["tasks"];
  if (!Array.isArray(tasks) || tasks.length < 1 || tasks.length > 4096) throw new Error("goal requires 1-4096 bounded task contracts");
  if (!Number.isSafeInteger(row["maxTaskStarts"]) || (row["maxTaskStarts"] as number) < 1 || (row["maxTaskStarts"] as number) > tasks.length) throw new Error("invalid shared goal dispatch budget");
  const byId = new Map<string, GoalWorkTask>();
  for (const input of tasks) {
    const t = object(input, ["id", "goal", "kind", "dependsOn", "requires", "due", "acceptance"]);
    if (typeof t["id"] !== "string" || !ID.test(t["id"]) || byId.has(t["id"]) || ["__proto__", "constructor", "prototype"].includes(t["id"])) throw new Error("invalid or duplicate task identity");
    if (typeof t["goal"] !== "string" || !t["goal"].trim() || Buffer.byteLength(t["goal"]) > 16 * 1024) throw new Error("invalid bounded task goal");
    if (!["goal", "safeguard", "hardening"].includes(String(t["kind"])) || !GOAL_PHASES.includes(t["due"] as GoalWorkPhase) || t["acceptance"] !== "tested-proposal") throw new Error("unsupported goal task contract");
    ids(t["dependsOn"]); ids(t["requires"]);
    byId.set(t["id"], t as unknown as GoalWorkTask);
  }
  const visited = new Set<string>(), pending = new Set<string>();
  const visit = (id: string): void => {
    if (pending.has(id)) throw new Error("goal task dependency cycle");
    if (visited.has(id)) return;
    const t = byId.get(id); if (!t) throw new Error("missing goal task dependency");
    pending.add(id); for (const dep of t.dependsOn) visit(dep); pending.delete(id); visited.add(id);
  };
  for (const id of byId.keys()) visit(id);
  return row as unknown as GoalWorkDefinition;
}
export function decodeGoalWork(value: string): GoalWorkDocument {
  if (Buffer.byteLength(value) > 8 * 1024 * 1024) throw new Error("goal work document exceeds custody bound");
  const d = object(JSON.parse(value), ["schema", "creationId", "definition", "binding", "principal", "phase", "active", "startsUsed", "claims", "accepted"]);
  if (d["schema"] !== "keep.goal-work/v1" || typeof d["creationId"] !== "string" || !UUID.test(d["creationId"]) || typeof d["binding"] !== "string" || !SHA.test(d["binding"]) || !GOAL_PHASES.includes(d["phase"] as GoalWorkPhase) || typeof d["active"] !== "boolean") throw new Error("invalid goal work identity/control");
  const definition = captureGoalWorkDefinition(d["definition"]), keys = definition.tasks.map(t => t.id);
  const claims = object(d["claims"], [], keys), accepted = object(d["accepted"], [], keys);
  if (!Number.isSafeInteger(d["startsUsed"]) || d["startsUsed"] !== Object.keys(claims).length || (d["startsUsed"] as number) > definition.maxTaskStarts) throw new Error("goal dispatch budget changed");
  for (const claim of Object.values(claims)) {
    const c = object(claim, ["jobId"], ["projectId"]);
    if (typeof c["jobId"] !== "string" || !UUID.test(c["jobId"]) || (c["projectId"] !== undefined && !isProjectId(c["projectId"] as string))) throw new Error("invalid goal task claim");
  }
  for (const [id, evidence] of Object.entries(accepted)) {
    const a = object(evidence, ["jobId", "projectId", "checkpointRevision", "sourceDigest", "validationDigest", "kind"]), c = claims[id] as GoalTaskClaim | undefined;
    if (!c || a["jobId"] !== c.jobId || a["projectId"] !== c.projectId || a["kind"] !== "tested-proposal" || !Number.isSafeInteger(a["checkpointRevision"]) || (a["checkpointRevision"] as number) < 1 || !SHA.test(String(a["sourceDigest"])) || !SHA.test(String(a["validationDigest"]))) throw new Error("invalid goal task acceptance");
  }
  return d as unknown as GoalWorkDocument;
}
export const goalWorkDigest = (value: unknown): string => createHash("sha256").update(JSON.stringify(value)).digest("hex");
/** Consume only a trusted canonical checkpoint, never a submitted model result. */
export function observeGoalTask(state: ProjectState | undefined, projectId: ProjectId, jobId: string, expectedGoal: string, expectedContext?: string): GoalTaskAcceptance | undefined {
  if (!state || state.projectId !== projectId || state.runId !== jobId || state.goal !== expectedGoal || state.artifacts["goal_work_context"] !== expectedContext || state.status !== "completed") return undefined;
  const implementation = state.artifacts["implement"] as ProjectImplementationArtifact | undefined;
  const test = state.artifacts["vet_artifact"] as ProjectTestArtifact | undefined;
  const receipt = implementation?.solve?.projectEditReceipt;
  if (!implementation || !test || !receipt || implementation.solve.solved !== true
    || receipt.applied !== true || receipt.testsExecuted !== true || !receipt.rollbackIds?.length
    || test.verdict !== "passed" || test.passed !== true || test.testsExecuted !== true || test.testsPassed !== true
    || test.isolation?.requirementMet !== true || test.isolation.executed !== true || test.discovered < 1 || test.passedCount !== test.discovered
    || test.issueId !== implementation.issue?.id || test.taskId !== implementation.task?.id || test.planStepId !== implementation.task?.planStepId
    || test.repositoryTreeSha256 !== implementation.repositoryTreeAfterSha256 || test.repositoryTreeSha256 !== receipt.repositoryTreeAfterSha256
    || test.repositoryExecutionManifestSha256 !== implementation.repositoryExecutionManifestSha256
    || !SHA.test(test.repositoryTreeSha256) || !SHA.test(test.repositoryExecutionManifestSha256)
    || test.implementationSha256 !== projectImplementationDigest(implementation)) return undefined;
  return { jobId, projectId, checkpointRevision: state.revision, sourceDigest: test.repositoryTreeSha256, validationDigest: goalWorkDigest(test), kind: "tested-proposal" };
}
export interface GoalWorkSelection { readonly selected?: string; readonly deferred: readonly string[]; readonly held: Readonly<Record<string, readonly string[]>>; }
/** Pure ordering of already bounded work; it never grants a capability or marks completion. */
export function selectGoalWork(d: GoalWorkDocument, capabilities: ReadonlySet<string>): GoalWorkSelection {
  const eligible = new Set<string>(), byId = new Map(d.definition.tasks.map(t => [t.id, t]));
  const include = (id: string): void => { if (eligible.has(id)) return; eligible.add(id); for (const dep of byId.get(id)!.dependsOn) include(dep); };
  for (const t of d.definition.tasks) if (GOAL_PHASES.indexOf(t.due) <= GOAL_PHASES.indexOf(d.phase)) include(t.id);
  const deferred: string[] = [], held: Record<string, readonly string[]> = {}, ready: GoalWorkTask[] = [];
  for (const t of d.definition.tasks) {
    if (d.accepted[t.id]) continue;
    if (!eligible.has(t.id)) { deferred.push(t.id); continue; }
    const reasons = [...t.dependsOn.filter(id => !d.accepted[id]).map(id => `dependency:${id}`), ...t.requires.filter(id => !capabilities.has(id)).map(id => `capability:${id}`)];
    if (d.claims[t.id]) reasons.push("original-task-claim-requires-observation");
    if (reasons.length > 0) held[t.id] = reasons; else ready.push(t);
  }
  // Hardening is deferred until its exposure phase, then becomes due protection.
  // Prerequisites inherit that urgency, including future-labelled prerequisites.
  const urgent = new Set<string>();
  const mark = (id: string): void => { if (urgent.has(id)) return; urgent.add(id); for (const dep of byId.get(id)!.dependsOn) mark(dep); };
  for (const t of d.definition.tasks) if (eligible.has(t.id) && t.kind !== "goal" && !d.accepted[t.id]) mark(t.id);
  const rank = { safeguard: 0, goal: 1, hardening: 0 };
  ready.sort((a, b) => Number(urgent.has(b.id)) - Number(urgent.has(a.id)) || rank[a.kind] - rank[b.kind] || a.id.localeCompare(b.id));
  const selected = d.active && d.startsUsed < d.definition.maxTaskStarts ? ready[0]?.id : undefined;
  return { ...(selected === undefined ? {} : { selected }), deferred, held };
}
