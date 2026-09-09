import { createHash } from "node:crypto";

import type { ModelProvider } from "../gateway/gateway.js";
import type { AdmittedEditPlan, AdmittedEditPlanningContext, EditPlan, Issue, SearchReplaceEdit } from "../solve/issue_model.js";
import { planEdits } from "../solve/edit_planner.js";
import type { Workspace } from "../solve/workspace.js";
import type { ProjectTask } from "./decomposition_stage.js";
import { projectRepositoryTreeSha256, type ProjectLocalizationArtifact } from "./project_localization.js";
import type { ProjectState } from "./project_loop.js";
import type { ProjectPlanArtifact } from "./plan_stage.js";

const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_EDITS = 8;
const MAX_EDIT_CHARS = 32_000;

export class ProjectEditAdmissionError extends Error {
  constructor(readonly capability: "bounded-edit-context", message: string) {
    super(message);
    this.name = "ProjectEditAdmissionError";
  }
}

/** Planning-only port. It intentionally has no workspace write capability. */
export interface ProjectEditPlanner {
  prepare(issue: Issue, task: ProjectTask, state: ProjectState, context?: AdmittedEditPlanningContext): Promise<AdmittedEditPlan>;
}

function sha256(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

function exactRecord(value: unknown, label: string, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has unexpected fields`);
  return value as Record<string, unknown>;
}

function boundedString(value: unknown, label: string, min: number, max: number): string {
  if (typeof value !== "string" || value.length < min || value.length > max || value.includes("\0")) throw new Error(`${label} must be ${min}-${max} characters without NUL bytes`);
  return value;
}

/** Strict, fail-closed parser: one invalid or unauthorized member rejects the whole proposal. */
export function parseProjectEditPlan(text: string, allowedFiles: ReadonlySet<string>): EditPlan {
  const normalized = text.trim();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES || normalized.startsWith("```") || !normalized.startsWith("{") || !normalized.endsWith("}")) throw new Error("model edit plan must be one bounded raw JSON object");
  let decoded: unknown;
  try { decoded = JSON.parse(normalized); } catch { throw new Error("model edit plan is not valid JSON"); }
  const root = exactRecord(decoded, "model edit plan", ["rationale", "edits"]);
  const rationale = boundedString(root["rationale"], "model edit rationale", 1, 4_096);
  if (!Array.isArray(root["edits"]) || root["edits"].length < 1 || root["edits"].length > MAX_EDITS) throw new Error(`model edit plan must contain 1-${MAX_EDITS} edits`);
  const edits = root["edits"].map((value, index): SearchReplaceEdit => {
    const row = exactRecord(value, `model edit ${index + 1}`, ["file", "search", "replace", "intent"]);
    const file = boundedString(row["file"], `model edit ${index + 1} file`, 1, 512);
    if (!allowedFiles.has(file)) throw new Error(`model edit ${index + 1} targets file outside the admitted plan step: ${file}`);
    const search = boundedString(row["search"], `model edit ${index + 1} search`, 1, MAX_EDIT_CHARS);
    const replace = boundedString(row["replace"], `model edit ${index + 1} replacement`, 0, MAX_EDIT_CHARS);
    if (search === replace) throw new Error(`model edit ${index + 1} does not change content`);
    return Object.freeze({ file, search, replace, intent: boundedString(row["intent"], `model edit ${index + 1} intent`, 1, 2_048) });
  });
  return Object.freeze({ rationale, edits: Object.freeze(edits) });
}

function admittedFiles(state: ProjectState, task: ProjectTask, issue: Issue): readonly string[] {
  const plan = state.artifacts["plan"] as Partial<ProjectPlanArtifact> | undefined;
  if (plan?.schemaVersion !== 1 || !Array.isArray(plan.steps) || !Array.isArray(plan.evidence)) throw new Error("editing requires the persisted vetted plan");
  const complete = plan as ProjectPlanArtifact;
  const step = complete.steps.find((row) => row.id === task.planStepId);
  if (!step) throw new Error(`editing task references missing plan step: ${task.planStepId}`);
  const evidence = new Map(complete.evidence.map((row) => [row.id, row]));
  const files = step.evidenceRefs.map((id) => evidence.get(id)).filter((row) => row?.kind === "repository-file")
    .map((row) => row!.sourceId).filter((path): path is string => typeof path === "string" && path.length > 0);
  const unique = [...new Set(files)].sort();
  if (unique.length === 0) throw new Error(`plan step ${step.id} authorizes no repository files`);
  const operatorText = `${issue.text}\n${task.objective}`;
  const explicitlyNamed = unique.filter((path) => operatorText.includes(path));
  return Object.freeze(explicitlyNamed.length > 0 ? explicitlyNamed : unique);
}

export function buildModelProjectEditPlanner(model: ModelProvider, workspace: Workspace, repositoryRef: string,
  options: { readonly prepareGoalCheck?: boolean } = {}): ProjectEditPlanner {
  return {
    async prepare(issue, task, state, context): Promise<AdmittedEditPlan> {
      if (issue.repoRef !== repositoryRef) throw new Error(`edit repository ${issue.repoRef} is outside the bound repository ${repositoryRef}`);
      const persistedPlan = state.artifacts["plan"] as Partial<ProjectPlanArtifact> | undefined;
      const localization = (state.artifacts["project_localization"] ?? persistedPlan?.localization) as Partial<ProjectLocalizationArtifact> | undefined;
      if (localization?.schemaVersion !== 1 || localization.repositoryRef !== repositoryRef || !Array.isArray(localization.selected)) throw new Error("configured-model editing requires persisted repository localization");
      const files = await workspace.files(repositoryRef);
      const repositoryTreeSha256 = projectRepositoryTreeSha256(files);
      if (repositoryTreeSha256 !== localization.repositoryTreeSha256) throw new Error("repository changed after localization; re-localization is required before editing");
      const byPath = new Map(files.map((file) => [file.path, file.content]));
      for (const selected of localization.selected) {
        const content = byPath.get(selected.path);
        if (content === undefined || sha256(content) !== selected.contentSha256) throw new Error(`localized file changed before editing: ${selected.path}`);
      }
      const allowedFiles = admittedFiles(state, task, issue);
      const admittedContents = allowedFiles.map((path) => {
        const content = byPath.get(path);
        if (content === undefined) throw new Error(`admitted repository file disappeared before editing: ${path}`);
        return { path, sha256: sha256(content) };
      });
      const generation = { model: model.name, tokensIn: 0, tokensOut: 0 };
      const observedModel: ModelProvider = {
        name: model.name, isLocal: model.isLocal, embed: texts => model.embed(texts),
        generate: async request => {
          const result = await model.generate(request);
          generation.model = result.model;
          generation.tokensIn += result.tokensIn;
          generation.tokensOut += result.tokensOut;
          return result;
        },
      };
      const plan = await planEdits(issue, {
        suspects: allowedFiles.map(path => ({ path, score: 1, isTest: false })), stages: ["bm25"],
      }, files, observedModel, {
        maxTokens: 4_000, parsePlan: parseProjectEditPlan,
        ...(options.prepareGoalCheck ? { prepareGoalCheck: true } : {}),
        taskContext: `Satisfy only this admitted task and its criteria; preserve unrelated behavior. Produce 1-8 edits, each with a nonempty intent.\nADMITTED_TASK=${JSON.stringify(task)}`,
        hints: { taskRole: "repository_edit", difficulty: "hard", structuredOutput: true, ...(state.projectId === undefined ? {} : { projectId: state.projectId }) },
        ...(context ? { signal: context.signal, reserveCall: context.reserveCall, observe: context.observe } : {}),
        ...(context?.reserveEmbedding === undefined ? {} : { reserveEmbedding: context.reserveEmbedding }),
        ...(context?.memoryContext === undefined ? {} : { memoryContext: context.memoryContext }),
        ...(context?.assertAuthority === undefined ? {} : { assertAuthority: context.assertAuthority }),
      });
      if (plan.edits.length === 0) throw new ProjectEditAdmissionError("bounded-edit-context", plan.rationale);
      const allowedFileSha256 = Object.freeze(Object.fromEntries(admittedContents.map((file) => [file.path, file.sha256])));
      return Object.freeze({
        schemaVersion: 1, mechanism: "project-edit-stage", repositoryRef, repositoryTreeSha256,
        allowedFiles, allowedFileSha256, taskId: task.id, planStepId: task.planStepId,
        generation: Object.freeze(generation), plan,
      });
    },
  };
}
