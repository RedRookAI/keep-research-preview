import { createHash } from "node:crypto";
import { DOMAIN_WORKFLOW_KINDS, type DomainWorkflowKind } from "../autonomy/project_state.js";
import type { ProjectId } from "./project_id.js";
import { parseTaskMemorySelection, type TaskMemorySelection } from "../memory/task_context.js";

export class NativeProjectCommandUnavailableError extends Error {
  constructor(readonly reason: "custody" | "authority") {
    super(`native project command unavailable: ${reason}`);
    this.name = "NativeProjectCommandUnavailableError";
  }
}

/** Data, never serialized code or a persisted role/credential. */
export interface NativeProjectCommand {
  readonly binding: string;
  readonly principal: { readonly kind: "human" | "agent"; readonly id: string; readonly tenant?: string; readonly grantId?: string };
  readonly goal: string;
  /** Overall objective/constraints, distinct from the current task's requested action. */
  readonly goalContext?: string;
  readonly posture?: "autonomous" | "policy-calibrated" | "approval-required";
  readonly domainWorkflowKind?: DomainWorkflowKind;
  readonly memoryContext?: TaskMemorySelection;
}
const SHA256 = /^[0-9a-f]{64}$/u;
const digest = (value: string): string => createHash("sha256").update(value).digest("hex");
export const commandDocumentName = (jobId: string): string => `job-command-${jobId}`;
export function encodeProjectCommand(command: NativeProjectCommand, jobId: string, projectId: ProjectId): { value: string; digest: string } {
  const value = JSON.stringify({ schema: "keep.native-project-command/v1", jobId, projectId, command });
  const hash = digest(value);
  decodeProjectCommand(value, hash, jobId, projectId);
  return { value, digest: hash };
}
export function decodeProjectCommand(value: string, expectedDigest: string, jobId: string, projectId: ProjectId): NativeProjectCommand {
  // JSON may expand an admitted goal's control characters sixfold. Preserve the
  // public 900 KiB objective plus internal task context, within the 8 MiB ceiling.
  // Additional bounded selection data (including JSON-escaped agent identity), no memory text.
  if (Buffer.byteLength(value) > (6 * 932 + 40) * 1024 || !SHA256.test(expectedDigest) || digest(value) !== expectedDigest) throw new Error("project command digest/size mismatch");
  const row = JSON.parse(value) as Record<string, unknown>;
  if (!row || Object.keys(row).sort().join(",") !== "command,jobId,projectId,schema" || row["schema"] !== "keep.native-project-command/v1" || row["jobId"] !== jobId || row["projectId"] !== projectId) throw new Error("project command identity mismatch");
  const c = row["command"] as NativeProjectCommand;
  const text = (s: unknown): s is string => typeof s === "string" && s.length > 0 && Buffer.byteLength(s) <= 1024 && !/[\u0000-\u001f\u007f]/u.test(s);
  if (!c || typeof c !== "object" || Object.keys(c).some(k => !["binding", "principal", "goal", "goalContext", "posture", "domainWorkflowKind", "memoryContext"].includes(k))
    || typeof c.binding !== "string" || !SHA256.test(c.binding) || typeof c.goal !== "string" || !c.goal.trim() || Buffer.byteLength(c.goal) > 900 * 1024
    || (c.goalContext !== undefined && (typeof c.goalContext !== "string" || !c.goalContext.trim() || Buffer.byteLength(c.goalContext) > 900 * 1024))
    || Buffer.byteLength(c.goal) + Buffer.byteLength(c.goalContext ?? "") > 932 * 1024
    || (c.posture !== undefined && !["autonomous", "policy-calibrated", "approval-required"].includes(c.posture))
    || (c.domainWorkflowKind !== undefined && !DOMAIN_WORKFLOW_KINDS.includes(c.domainWorkflowKind))) throw new Error("invalid native project command");
  const p = c.principal;
  if (!p || typeof p !== "object" || Object.keys(p).some(k => !["kind", "id", "tenant", "grantId"].includes(k))
    || !["human", "agent"].includes(p.kind) || !text(p.id) || (p.tenant !== undefined && !text(p.tenant))
    || (p.kind === "agent" ? !text(p.grantId) : p.grantId !== undefined)) throw new Error("invalid project command principal reference");
  if (c.memoryContext !== undefined) return { ...c, memoryContext: parseTaskMemorySelection(c.memoryContext) };
  return c;
}
