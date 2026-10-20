import { createHash, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { KeepApp } from "../compose.js";
import { OWNER, can, type Principal } from "../identity/rbac.js";
import type { DelegatedAgentPrincipal } from "../identity/delegation_registry.js";
import type { NativeProjectCommand } from "../session/project_command.js";
import { projectRepositoryOutcomes } from "../solve/governed_local_merge.js";

/** Owner-created admission data. A token or self-asserted role is never serialized here. */
export interface RestrictedClientProfile {
  readonly schema: "keep.openclaw-client/v1";
  readonly clientId: string;
  readonly agentId: string;
  readonly grantId: string;
  readonly expiresAt: number;
  readonly bearerSha256: string;
  readonly commandBinding: string;
}
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export function readRestrictedClientProfile(path: string): RestrictedClientProfile {
  if (!isAbsolute(path)) throw new Error("restricted client profile requires an absolute owner-controlled path");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 4096 || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new Error("restricted client profile must be a private owned regular file");
    const value = JSON.parse(readFileSync(fd, "utf8")) as RestrictedClientProfile;
    if (!value || Object.keys(value).sort().join(",") !== "agentId,bearerSha256,clientId,commandBinding,expiresAt,grantId,schema"
      || value.schema !== "keep.openclaw-client/v1" || ![value.clientId, value.agentId, value.grantId].every(id => typeof id === "string" && SAFE_ID.test(id))
      || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= 0 || !SHA256.test(value.bearerSha256) || !SHA256.test(value.commandBinding)) throw new Error("invalid restricted client profile");
    return Object.freeze(value);
  } finally { closeSync(fd); }
}

export function matchesRestrictedBearer(authorization: string | undefined, profile: RestrictedClientProfile): boolean {
  if (!authorization || !/^Bearer [a-f0-9]{64}$/u.test(authorization)) return false;
  const actual = createHash("sha256").update(authorization.slice(7)).digest();
  return timingSafeEqual(actual, Buffer.from(profile.bearerSha256, "hex"));
}

/** Both admission and human handoff recheck the durable grant and immutable n=1 parent. */
export function restrictedClientPrincipal(app: KeepApp, profile: RestrictedClientProfile, now = Date.now()): DelegatedAgentPrincipal {
  if (app.projectGenerationApprovalRequired !== true || app.identity !== undefined || app.tenantDeployment !== undefined || profile.expiresAt <= now || profile.commandBinding !== app.projectRuntime?.commandBinding) throw new Error("restricted client configuration or expiry changed");
  const principal = app.authorization.restorePrincipal(profile.grantId);
  const attribution = principal && app.authorization.attribution(principal);
  if (!principal || principal.id !== profile.agentId || principal.tenant !== undefined || principal.delegatedBy !== OWNER.id
    || attribution?.humanPrincipalId !== OWNER.id || !can(app.authorization, principal, "change.solve")) throw new Error("restricted client delegation is unavailable");
  return principal;
}

export function ownsRestrictedCommand(profile: RestrictedClientProfile, command: NativeProjectCommand): boolean {
  return command.binding === profile.commandBinding && command.principal.kind === "agent" && command.principal.id === profile.agentId
    && command.principal.grantId === profile.grantId && command.principal.tenant === undefined && command.posture === "approval-required"
    && command.memoryContext === undefined && command.domainWorkflowKind === undefined && command.goalContext === undefined;
}

export function assertRestrictedCurrent(app: KeepApp, path: string, expected: RestrictedClientProfile): void {
  const current = readRestrictedClientProfile(path);
  if ((Object.keys(expected) as (keyof RestrictedClientProfile)[]).some(key => current[key] !== expected[key])) throw new Error("restricted client profile changed");
  restrictedClientPrincipal(app, current);
}

export function assertRestrictedHuman(app: KeepApp, profile: RestrictedClientProfile, human: Principal, command: NativeProjectCommand): void {
  restrictedClientPrincipal(app, profile);
  if (!ownsRestrictedCommand(profile, command) || human.kind !== "human" || human.id !== OWNER.id || human.tenant !== undefined || !can(app.authorization, human, "review.approve")) throw new Error("human cannot approve this delegated command");
}

/** A deliberate projection, never the session/history or arbitrary audit route. */
export function restrictedProjectStatus(app: KeepApp, profile: RestrictedClientProfile, jobId: string): Record<string, unknown> | undefined {
  restrictedClientPrincipal(app, profile);
  const job = app.projectRuntime?.job(jobId);
  if (!job || !app.projectManager) return undefined;
  const command = app.projectRuntime!.commandForJob(jobId, job.projectId);
  if (!ownsRestrictedCommand(profile, command)) return undefined;
  const state = app.projectManager.session(job.projectId).lastCheckpoint();
  const implementation = state?.artifacts["implement"] as { solve?: { proposalEvidence?: { checks?: { testsPassed?: boolean; vettingCleared?: boolean }; rollback?: { patchSha256?: string } } } } | undefined;
  const proposal = implementation?.solve?.proposalEvidence;
  const repository = projectRepositoryOutcomes(app.spine, jobId);
  const vetoed = app.spine.replay().some(event => event.type === "identity.action" && event.actor === "governed-local-merge"
    && event.payload["runId"] === jobId && event.payload["event"] === "local_merge.refused" && event.payload["decision"] === "veto");
  const generationDecision = app.spine.replay().filter(event => event.type === "identity.action" && event.actor === "openclaw-client"
    && event.payload["runId"] === jobId && event.payload["event"] === "openclaw.human-generation-decision" && typeof event.payload["approved"] === "boolean"
    && typeof event.payload["decisionId"] === "string" && state?.consumedSignals.includes(`approval:${event.payload["decisionId"]}:${event.payload["approved"] ? "approved" : "declined"}`)).at(-1);
  const clip = (value: string | undefined) => value?.slice(0, 4096);
  return { projectId: job.projectId, jobId: job.id,
    job: { state: job.state, reason: clip(job.reason), cancellationRequested: job.cancellationRequested === true },
    run: state?.runId === jobId ? { status: state.status, stage: state.stage, wait: state.wait === undefined ? null : {
      kind: state.wait.kind, reason: clip(state.wait.reason), ...(state.wait.kind === "approval" ? { decisionId: state.wait.decisionId } : {}),
    } } : null,
    proposal: { available: proposal !== undefined, digest: proposal?.rollback?.patchSha256 ?? null,
      checks: proposal?.checks ? { testsPassed: proposal.checks.testsPassed ?? null, vettingCleared: proposal.checks.vettingCleared ?? null } : null },
    review: { vetoed, latestDecision: repository.latestDecision, generationDecision: generationDecision === undefined ? null : generationDecision.payload["approved"] ? "approved" : "declined" },
    delivery: { workspace: repository.workspace.status, source: repository.source.merge.status, revert: repository.source.revert.status },
  };
}
