import { OWNER, type Principal } from "../identity/rbac.js";
import type { ProjectSessionManager } from "../session/project_session_manager.js";
import type { MemoryPartitionScope } from "./persistence.js";

/** Shared resource rules only. Callers must resolve and authorize the live principal on each use. */
export function resolveMemoryScope(input: {
  readonly principal: Principal;
  readonly target: { readonly scope: unknown; readonly projectId?: unknown; readonly agentId?: unknown };
  readonly personalMode: boolean;
  readonly boundTenant?: string;
  readonly manager?: ProjectSessionManager;
  readonly read: boolean;
  readonly controlOperation?: boolean;
  readonly humanParent: (principal: Principal) => string | undefined;
}): MemoryPartitionScope | undefined {
  const { principal, target } = input;
  if (input.boundTenant !== undefined && principal.tenant !== input.boundTenant) return undefined;
  const tenant = principal.tenant === undefined ? {} : { tenantId: principal.tenant };
  if (target.scope === "user") {
    if (principal.kind === "agent" || target.projectId !== undefined || target.agentId !== undefined) return undefined;
    return { ownerId: principal.id, kind: "user", ...tenant };
  }
  if (target.scope === "global") {
    if (!input.personalMode || principal.kind !== "human" || target.projectId !== undefined || target.agentId !== undefined) return undefined;
    return { ownerId: OWNER.id, kind: "global" };
  }
  if (target.scope !== "project" && target.scope !== "agent") return undefined;
  let projectId: string | undefined;
  if (target.projectId !== undefined || target.scope === "project") {
    if (typeof target.projectId !== "string") return undefined;
    const project = input.manager?.list().find(record => record.id === target.projectId && record.tenant === principal.tenant);
    if (!project || input.manager?.quarantine(project.id) !== undefined || (!input.read && !input.controlOperation && project.lifecycle === "archived")) return undefined;
    projectId = project.id;
  }
  if (target.scope === "project") {
    if (target.agentId !== undefined) return undefined;
    return { ownerId: `project:${projectId!}`, kind: "project", projectId: projectId!, ...tenant };
  }
  const agentId = target.agentId ?? (principal.kind === "agent" ? principal.id : undefined);
  if (typeof agentId !== "string" || !agentId || (principal.kind === "agent" && agentId !== principal.id)) return undefined;
  const ownerId = principal.kind === "agent" ? input.humanParent(principal) : principal.kind === "human" ? principal.id : undefined;
  if (ownerId === undefined) return undefined;
  return { ownerId, kind: "agent", agentId, ...tenant, ...(projectId === undefined ? {} : { projectId }) };
}
