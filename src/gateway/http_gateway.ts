/**
 * P1 — HEADLESS GATEWAY (the reachability foundation).
 *
 * Keep's engine is deep but, until now, unreachable: no surface a user can touch. This is the foundation every
 * client (CLI, web UI, phone app, chat channels, MCP) talks to — a local HTTP surface that exposes the ALREADY-
 * COMPOSED app (`composeKeep`) as a token-authed API. It invents no engine behavior: it wraps `frontDoor.handle` /
 * `resolveOffer`, `autonomyLoop.runProject`, and the `ProjectSessionManager`.
 *
 * Architecture mirrors `review_server`/`review_web`: a PURE request handler (`handleGatewayRequest`) owns routing +
 * auth and is unit-tested WITHOUT a socket; a thin `startGatewayServer` owns only the socket (binding, body, token).
 *
 * Four hard properties (each disproof-backed):
 *   - ZERO-DEP: only `node:*` builtins — the engine's 2-devDep discipline holds (a UI framework would be a SEPARATE
 *     client package, never here).
 *   - TOKEN-AUTHED: every mutating route requires the token; an unauthenticated caller never drives a run.
 *   - COMPOSED: wraps `composeKeep`'s surfaces; no reimplementation of the front door or the loop.
 *   - DURABLE: job identity and project checkpoints survive the gateway. Interrupted callbacks are classified
 *     for reconciliation; a durable handle is not a promise of detached-worker survival or automatic replay.
 *
 * Both-tracks: binds 127.0.0.1 by DEFAULT (never 0.0.0.0) so n=1 is safe out of the box; host/token/port are
 * configurable for an org deployment (behind TLS, an explicit choice). SEAM: a WebSocket/SSE live event stream and
 * the richer session routes (switch/background) layer on next; P1 is the request/response + project spine.
 */

import { createServer, type IncomingMessage } from "node:http";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { KeepApp } from "../compose.js";
import { GOAL_PHASES, GOAL_WORK_DOCUMENT, type GoalWorkPhase } from "../session/project_goal_work.js";
import { ALL_PERMISSIONS, can, OWNER, type Principal, type Permission } from "../identity/rbac.js";
import { auditTrail } from "../review/review_core.js";
import { exportTenantAudit } from "../audit/tenant_audit_export.js";
import { memoryStore, memoryRecall, memoryUpdate, memoryForget, memoryCorrect, memoryList, memoryReview, memoryPurge, executeDurableMemoryMutation, deliverMemoryAdmissions, type DurableMemoryMutation, type MemoryFilter } from "../memory/memory_tools.js";
import { MemoryStore } from "../memory/store.js";
import type { MemoryPartitionScope } from "../memory/persistence.js";
import { adoptOpenClawSkill } from "../compat/openclaw_adapter.js";
import { memoryCurrentWithSourcesAt, memoryPrivateUseAllowed, type MemoryKind, type MemoryScope, type TrustTier } from "../memory/model.js";
import { publishSkill, installSkill, listRegistry, type GateVerdict, type SkillPackage } from "../registry/skill_registry.js";
import { EnvelopeForbiddenSinkCheck } from "../loop/skill_validator_defaults.js";
import type { DistilledSkill } from "../loop/skill_distiller.js";
import { DOMAIN_WORKFLOW_KINDS, type DomainWorkflowKind } from "../autonomy/project_state.js";
import { asProjectId } from "../session/project_id.js";
import { capabilityInvocationDigest, decideEffectMediation } from "../ecosystem/capability_port.js";
import type { CapabilityIdentity } from "../reference/reference_registry.js";
import type { FleetAdmissionHandle, FleetAdmissionRequest } from "../fleet/fleet_lifecycle.js";
import { canonicalize } from "../spine/event.js";
import { resolveMemoryScope } from "../memory/scope.js";
import { parseTaskMemorySelection, TaskMemoryUnavailableError, TASK_MEMORY_COPY_NOTICE, type TaskMemorySelection } from "../memory/task_context.js";
import { NativeProjectCommandUnavailableError, type NativeProjectCommand } from "../session/project_command.js";
import { localCostTraceView } from "../observability/fleet_telemetry.js";
import { AUDIENCE_PERFORMANCE_DOCUMENT, AUDIENCE_SOURCES, type AudienceSource, type GenerationCandidate, type PerformanceItem } from "../learning/audience_performance.js";
import { presentAdaptiveText, type AdaptiveBehavior } from "../learning/outcome_adaptation.js";
import { ProjectSessionConflictError } from "../session/project_session_persistence.js";
import { ProjectSubmissionConflictError } from "../session/project_job_journal.js";
import { ProjectSubmissionUncertainError, type ProjectJobContext } from "../session/project_runtime.js";
import type { IdentityLayer } from "../review/review_web.js";

export interface GatewayRequest {
  readonly method: string;
  readonly path: string;
  readonly query: Record<string, string>;
  readonly headers: Record<string, string>;
  readonly body: string;
}

export interface GatewayResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

export interface GatewaySecurity {
  readonly token: string;
  readonly workerControl?: { readonly id: string; readonly state: () => "running" | "paused" | "stopping"; readonly requestStop: () => boolean; readonly setPaused?: (paused: boolean) => boolean };
  /** Map an authenticated request to a principal (org RBAC). Absent → OWNER (n=1, zero-friction). */
  readonly principalFor?: (req: GatewayRequest) => Principal | undefined;
  /** Organization login/session boundary. Mutually exclusive with an injected principal resolver. */
  readonly identity?: IdentityLayer;
}

const PRINCIPAL_KINDS = new Set(["human", "agent", "service"]);
const PRINCIPAL_ROLES = new Set(["owner", "maintainer", "reviewer", "operator", "viewer", "agent"]);
const SAFE_TENANT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const PERSONAL_TENANT_SENTINEL = "keep.n1.default";

function resolvedEnterprisePrincipal(value: unknown): Principal | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const row = value as Record<string, unknown>;
  if (typeof row["id"] !== "string" || row["id"].length < 1 || row["id"].length > 512 || /[\u0000-\u001f\u007f]/u.test(row["id"])) return undefined;
  if (typeof row["kind"] !== "string" || !PRINCIPAL_KINDS.has(row["kind"])) return undefined;
  if (typeof row["role"] !== "string" || !PRINCIPAL_ROLES.has(row["role"])) return undefined;
  if (typeof row["tenant"] !== "string" || !SAFE_TENANT.test(row["tenant"]) || row["tenant"] === PERSONAL_TENANT_SENTINEL) return undefined;
  if (row["displayName"] !== undefined && (typeof row["displayName"] !== "string" || row["displayName"].length > 512)) return undefined;
  return value as Principal;
}

function json(status: number, obj: unknown): GatewayResponse {
  return { status, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: JSON.stringify(obj) };
}

/** Preserve a recognizable project label without letting a large or multiline goal violate the registry bound. */
function projectNameFromGoal(goal: string): string {
  const normalized = goal.replace(/[\u0000-\u001f\u007f]+/gu, " ").replace(/\s+/gu, " ").trim() || "Keep project";
  if (Buffer.byteLength(normalized, "utf8") <= 4_096) return normalized;
  let name = "";
  for (const character of normalized) {
    if (Buffer.byteLength(`${name}${character}…`, "utf8") > 4_096) break;
    name += character;
  }
  return `${name.trimEnd()}…`;
}

/** Enterprise credentials are header-only; the loopback n=1 page retains its bootstrapping query-token path. */
function isAuthed(req: GatewayRequest, token: string, allowQueryToken: boolean): boolean {
  const auth = req.headers["authorization"];
  const expected = Buffer.from(`Bearer ${token}`), observed = Buffer.from(auth ?? "");
  if (observed.length === expected.length && timingSafeEqual(observed, expected)) return true;
  return allowQueryToken && req.query["token"] === token;
}

function parseBody(body: string): Record<string, unknown> | null {
  if (body.trim() === "") return {};
  try {
    const v = JSON.parse(body);
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function audienceFailure(error: unknown): GatewayResponse {
  if (error instanceof ProjectSessionConflictError) return json(409, { error: "audience corpus changed concurrently; reload and retry" });
  const message = error instanceof Error ? error.message : "";
  if (/persisted|document store|unavailable|authenticate|no such project/u.test(message)) return json(409, { error: "audience corpus state is unavailable; reset or retry with current project state" });
  const safeValidation = /^(?:unsupported audience|metric |performance |audience |generation |bounded |hostile |stale |no user-provided|project document would)/u.test(message);
  return json(400, { error: safeValidation ? message : "audience corpus request is invalid" });
}

function adaptationFailure(error: unknown): GatewayResponse {
  if (error instanceof ProjectSessionConflictError || /adaptation document conflict|CAS conflict/u.test(error instanceof Error ? error.message : "")) return json(409, { error: "adaptation changed concurrently; reload and retry" });
  const message = error instanceof Error ? error.message : "";
  if (/persisted|document store|unavailable|authenticate|no such project/u.test(message)) return json(409, { error: "adaptation state is unavailable for this project" });
  const safeValidation = /^(?:adaptive |candidate |an adaptation|no candidate|subject |the fixed|the selected|only observed|outcome |duplicate |unbound |quality |regressed |experiment |assignment |adaptation random)/u.test(message);
  return json(400, { error: safeValidation ? message : "adaptation request is invalid" });
}

/**
 * The PURE gateway handler — routing + auth over the composed app. No socket, so it is fully unit-testable.
 */
/**
 * The install safety gate — the SAME contract a locally-learned skill passes. Prefers the composed CEGIS
 * `SkillValidator`; falls back to the deterministic `EnvelopeForbiddenSinkCheck` reference monitor when no oracle is
 * composed. Either way a forbidden-sink skill pushed over the wire is REJECTED — the wire is never a bypass.
 */
function buildInstallGate(app: KeepApp): (skill: DistilledSkill) => Promise<GateVerdict> {
  const validator = app.skillValidator;
  if (validator) {
    return async (skill) => { const r = validator.validate(skill); return { ok: r.verdict === "validated", verdict: r.verdict, reason: r.reason }; };
  }
  const monitor = new EnvelopeForbiddenSinkCheck();
  return async (skill) => { const bad = monitor.check(skill); return bad ? { ok: false, verdict: "rejected-unsafe", reason: bad } : { ok: true, verdict: "validated" }; };
}

export async function handleGatewayRequest(app: KeepApp, req: GatewayRequest, sec: GatewaySecurity): Promise<GatewayResponse> {
  // Liveness is unauthenticated (a client checks the gateway is up before sending the token).
  if (req.method === "GET" && req.path === "/health") return json(200, { ok: true });

  // TOKEN-AUTHED: everything else requires the token. No unauthenticated caller drives a run.
  if (!isAuthed(req, sec.token, sec.principalFor === undefined && sec.identity === undefined)) return json(401, { error: "unauthorized" });

  if (sec.identity !== undefined && sec.principalFor !== undefined) return json(500, { error: "gateway identity configuration is ambiguous" });
  const boundTenant = app.tenantDeployment?.rootAdmission.tenantId;
  const refuseTenantBoundary = (status: number): GatewayResponse => {
    app.spine.stage({ type: "identity.action", actor: "gateway-rbac", payload: {
      event: "tenant_boundary_refused", tenant: boundTenant, reason: "request identity does not match the admitted tenant deployment",
    } });
    return json(status, { error: status === 404 ? "not found" : "forbidden", reason: "request identity is outside this tenant deployment" });
  };
  // A tenant-specific process owns one repository/workspace authority. A valid
  // role in another tenant cannot use it, and missing identity must not select OWNER.
  if (boundTenant !== undefined && sec.identity === undefined && sec.principalFor === undefined) return refuseTenantBoundary(403);
  if (sec.identity !== undefined && req.method === "POST" && req.path === "/auth/session") {
    const body = parseBody(req.body); const assertion = body?.["assertion"];
    if (typeof assertion !== "string" || assertion.length < 1 || assertion.length > 16_384) return json(400, { error: "identity assertion is invalid" });
    const verified = await sec.identity.provider.verify(assertion, Date.now());
    if (verified === null) return json(401, { error: "identity assertion was not verified" });
    const principal = resolvedEnterprisePrincipal(sec.identity.registry.resolve(verified));
    if (principal === undefined) return json(403, { error: "verified identity has no admitted organization principal" });
    if (boundTenant !== undefined && principal.tenant !== boundTenant) return refuseTenantBoundary(403);
    const session = sec.identity.sessions.create(principal, Date.now());
    return json(200, { session: session.id, expiresByPolicy: true });
  }

  // PRINCIPAL-AWARE: the token maps to a principal (n=1 → OWNER, zero-friction; org → the resolver's principal).
  let resolvedPrincipal: Principal | undefined;
  try { resolvedPrincipal = sec.identity !== undefined
    ? resolvedEnterprisePrincipal(sec.identity.sessions.get(req.headers["x-keep-session"], Date.now())?.principal)
    : sec.principalFor === undefined ? undefined : resolvedEnterprisePrincipal(sec.principalFor(req)); }
  catch { return json(403, { error: "forbidden", reason: "authenticated principal could not be resolved" }); }
  if ((sec.principalFor !== undefined || sec.identity !== undefined) && resolvedPrincipal === undefined) return json(403, { error: "forbidden", reason: "authenticated principal could not be resolved" });
  const principal: Principal = resolvedPrincipal ?? OWNER;
  if (boundTenant !== undefined && principal.tenant !== boundTenant) return refuseTenantBoundary(req.method === "GET" ? 404 : 403);
  const personalMode = sec.principalFor === undefined && sec.identity === undefined;
  const tenant = personalMode ? undefined : principal.tenant!;
  const skillRegistry = personalMode ? app.registryStore : app.tenantRegistry.forTenant(tenant);
  const visibleProject = (record: { readonly tenant?: string }): boolean => personalMode || record.tenant === principal.tenant;
  // Gate a mutating route by permission, recording every allow/deny to the spine (auditable). null → allowed.
  const gate = (perm: Permission): GatewayResponse | null => {
    const allow = can(app.authorization, principal, perm);
    app.spine.stage({ type: "identity.action", actor: "gateway-rbac", payload: { event: "rbac_check", who: principal.id, role: principal.role, action: perm, allow, ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }) } });
    const attribution = allow ? app.authorization.attribution(principal) : undefined;
    if (attribution !== undefined) app.spine.stage({ type: "identity.action", actor: "gateway", payload: {
      event: "principal.action", action: perm, ...attribution, ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }),
    } });
    return allow ? null : json(403, { error: "forbidden", reason: `role '${principal.role}' may not '${perm}'` });
  };

  if (req.method === "POST" && req.path === "/delegation/issue") {
    if (personalMode || sec.identity === undefined) return json(404, { error: "not found" });
    const denied = gate("rbac.admin"); if (denied) return denied;
    const body = parseBody(req.body); if (body === null) return json(400, { error: "invalid json" });
    const agentId = body["agentId"], grantId = body["grantId"], expiresAt = body["expiresAt"], permissions = body["permissions"];
    if (typeof agentId !== "string" || typeof grantId !== "string" || !Number.isSafeInteger(expiresAt) || !Array.isArray(permissions) || permissions.length < 1 || permissions.some((value) => typeof value !== "string" || !ALL_PERMISSIONS.includes(value as Permission))) return json(400, { error: "bounded agentId, grantId, expiresAt and permissions are required" });
    try {
      const agent = await app.authorization.issue(principal, agentId, permissions as Permission[], Number(expiresAt), Date.now(), grantId);
      const session = sec.identity.sessions.create(agent, Date.now());
      return json(200, { grantId: agent.grantId, agentId: agent.id, session: session.id, expiresAt });
    } catch (error) { return json(400, { error: error instanceof Error ? error.message : "delegation refused" }); }
  }
  if (req.method === "POST" && req.path === "/delegation/revoke") {
    if (personalMode) return json(404, { error: "not found" });
    const denied = gate("rbac.admin"); if (denied) return denied;
    const body = parseBody(req.body); if (body === null || typeof body["grantId"] !== "string") return json(400, { error: "grantId is required" });
    try { return json(200, { grantId: body["grantId"], revoked: await app.authorization.revoke(body["grantId"]) }); }
    catch (error) { return json(400, { error: error instanceof Error ? error.message : "delegation revocation refused" }); }
  }

  if (req.method === "GET" && req.path === "/observability/costs") {
    const denied = gate("audit.view"); if (denied) return denied;
    const traceId = req.query["traceId"];
    if (traceId !== undefined && (traceId.length === 0 || Buffer.byteLength(traceId, "utf8") > 256 || traceId.includes("\0"))) return json(400, { error: "invalid traceId" });
    const offset = req.query["offset"] === undefined ? 0 : Number(req.query["offset"]);
    const limit = req.query["limit"] === undefined ? 100 : Number(req.query["limit"]);
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) return json(400, { error: "invalid observability page" });
    const tenantSpans = app.observability.recorder.all(tenant);
    const spans = traceId === undefined
      ? tenantSpans
      : app.observability.recorder.trace(traceId).filter((span) => tenant === undefined || span.tenant === tenant);
    return json(200, localCostTraceView(spans, { offset, limit }));
  }

  if (req.method === "GET" && req.path === "/observability/exports") {
    const denied = gate("audit.view"); if (denied) return denied;
    return json(200, { destinations: app.fleetTelemetry?.list(tenant) ?? [] });
  }

  if (req.method === "POST" && req.path === "/observability/export") {
    if (app.fleetTelemetry === undefined) return json(501, { error: "private telemetry export is not configured" });
    const denied = gate("audit.export"); if (denied) return denied;
    const b = parseBody(req.body);
    if (b === null || typeof b["destinationId"] !== "string" || typeof b["purpose"] !== "string") return json(400, { error: "destinationId and purpose are required" });
    const traceId = b["traceId"];
    if (traceId !== undefined && typeof traceId !== "string") return json(400, { error: "invalid traceId" });
    const result = await app.fleetTelemetry.export({
      destinationId: b["destinationId"], purpose: b["purpose"], actor: principal.id,
      ...(tenant === undefined ? {} : { tenant }), ...(traceId === undefined ? {} : { traceId }),
      ...(b["offset"] === undefined ? {} : { offset: Number(b["offset"]) }), ...(b["limit"] === undefined ? {} : { limit: Number(b["limit"]) }),
    });
    return json(result.status === "completed" ? 200 : result.status === "held" ? 409 : result.status === "unreconciled" ? 202 : 502, { result });
  }

  if (req.method === "GET" && req.path === "/observability/export/outstanding") {
    if (app.fleetTelemetry === undefined) return json(200, { outstanding: [] });
    const denied = gate("audit.export"); if (denied) return denied;
    return json(200, { outstanding: app.fleetTelemetry.outstanding(tenant) });
  }

  if (req.method === "POST" && req.path === "/observability/export/reconcile") {
    if (app.fleetTelemetry === undefined) return json(501, { error: "private telemetry export is not configured" });
    const denied = gate("audit.export"); if (denied) return denied;
    const b = parseBody(req.body);
    if (b === null || typeof b["exportId"] !== "string" || (b["outcome"] !== "delivered" && b["outcome"] !== "failed") || typeof b["evidenceId"] !== "string") return json(400, { error: "exportId, outcome, and evidenceId are required" });
    const reconciled = await app.fleetTelemetry.reconcile({ exportId: b["exportId"], outcome: b["outcome"], evidenceId: b["evidenceId"], actor: principal.id, ...(tenant === undefined ? {} : { tenant }) });
    return reconciled ? json(200, { reconciled: true }) : json(404, { error: "outstanding telemetry export not found or reconciliation could not be sealed" });
  }

  // The desktop surface: a self-contained page (zero server-side deps) that talks to the JSON routes below.
  // Token-scoped like the review server — the page is served only WITH the token, and bakes it in for fetches.
  if (req.method === "GET" && (req.path === "/" || req.path === "/index.html")) {
    return { status: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" }, body: renderGatewayPage(sec.token) };
  }

  if (req.method === "POST" && req.path === "/client/sign") {
    if (!app.clientSigning) return json(501, { error: "client signing is not configured" });
    const denied = gate("config.write"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null) return json(400, { error: "invalid json" });
    const platform = b["platform"], binaryBase64 = b["binaryBase64"], distribution = b["distribution"];
    if (!(platform === "desktop" || platform === "ios" || platform === "android") || typeof binaryBase64 !== "string" || distribution !== "private-development-only") return json(400, { error: "bounded private client signing input required" });
    try { return json(200, await app.clientSigning.sign({ platform, binaryBase64, distribution })); }
    catch (error) { return json(409, { error: (error as Error).message }); }
  }

  if (req.method === "POST" && req.path === "/message") {
    const denied = gate("review.view"); if (denied) return denied;
    const frontDoor = personalMode ? app.frontDoor : app.frontDoorForSubject?.(tenant!);
    if (frontDoor === undefined) return json(501, { error: "front door not composed" });
    const b = parseBody(req.body);
    if (b === null) return json(400, { error: "invalid json" });
    const result = await frontDoor.handle(String(b["message"] ?? ""), { subject: tenant ?? "keep.n1.default" });
    return json(200, { result });
  }

  if (req.method === "POST" && req.path === "/offer") {
    const denied = gate("review.approve"); if (denied) return denied;
    const frontDoor = personalMode ? app.frontDoor : app.frontDoorForSubject?.(tenant!);
    if (frontDoor === undefined) return json(501, { error: "front door not composed" });
    const b = parseBody(req.body);
    if (b === null) return json(400, { error: "invalid json" });
    frontDoor.resolveOffer(Boolean(b["accepted"]), tenant ?? "keep.n1.default");
    return json(200, { ok: true });
  }

  if (req.path.startsWith("/project/adaptation")) {
    if (app.projectManager === undefined || app.outcomeAdaptation === undefined) return json(501, { error: "project adaptation is not configured" });
    const body = req.method === "POST" ? parseBody(req.body) : undefined;
    if (req.method === "POST" && body === null) return json(400, { error: "invalid json" });
    const requiredPermission = req.method === "GET" || (req.path === "/project/adaptation/present" && typeof body?.["assignmentId"] !== "string") ? "adaptation.read"
      : req.path === "/project/adaptation/propose" || req.path === "/project/adaptation/abandon" || req.path === "/project/adaptation/reset" ? "adaptation.manage"
      : "adaptation.observe";
    const adaptationDenied = gate(requiredPermission); if (adaptationDenied) return adaptationDenied;
    const rawProjectId = req.method === "GET" ? req.query["projectId"] : body?.["projectId"];
    if (typeof rawProjectId !== "string") return json(400, { error: "invalid projectId" });
    let projectId; try { projectId = asProjectId(rawProjectId); } catch { return json(400, { error: "invalid projectId" }); }
    const project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
    if (project === undefined) return json(404, { error: "project not found" });
    if (project.lifecycle === "archived" && req.method !== "GET") return json(409, { error: "project is archived and read-only" });

    if (req.method === "GET" && req.path === "/project/adaptation") {
      const documentRevision = app.projectManager.session(projectId).resolveDocumentVersioned("outcome-adaptation").revision;
      try { return json(200, { projectId, documentRevision, behavior: app.outcomeAdaptation(projectId).current(), regime: "fixed-horizon-one-sided-t95-with-variance-floor", outcomeProvenance: "delegated-observer-report-after-recorded-exposure", routing: { preferredModelAdvisory: true, effortIsRequestedAndCapabilityClamped: true } }); }
      catch (error) { const failed = adaptationFailure(error); return json(failed.status, { ...(JSON.parse(failed.body) as Record<string, unknown>), documentRevision }); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/propose") {
      if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "adaptation candidates require an authenticated human principal" });
      const candidate = body!["candidate"];
      if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) return json(400, { error: "candidate is required" });
      try {
        const experimentId = app.outcomeAdaptation(projectId).propose(candidate as AdaptiveBehavior);
        app.spine.stage({ type: "identity.action", actor: "outcome-adaptation", payload: { event: "adaptation.proposed", projectId, experimentId, actor: principal.id } });
        return json(200, { projectId, experimentId });
      } catch (error) { return adaptationFailure(error); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/abandon") {
      if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "adaptation abandonment requires an authenticated human principal" });
      if (typeof body!["experimentId"] !== "string") return json(400, { error: "experimentId is required" });
      try {
        const decision = app.outcomeAdaptation(projectId).abandon(body!["experimentId"]);
        app.spine.stage({ type: "identity.action", actor: "outcome-adaptation", payload: { event: "adaptation.abandoned", projectId, experimentId: body!["experimentId"], actor: principal.id, reason: decision.reason } });
        return json(200, { projectId, decision });
      } catch (error) { return adaptationFailure(error); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/reset") {
      if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "adaptation reset requires an authenticated human principal" });
      if (body!["confirm"] !== true || !Number.isSafeInteger(body!["expectedRevision"]) || (body!["expectedRevision"] as number) < 1) return json(400, { error: "confirm=true and a positive expectedRevision are required" });
      try {
        const reset = app.resetOutcomeAdaptation!(projectId, body!["expectedRevision"] as number);
        app.spine.stage({ type: "identity.action", actor: "outcome-adaptation", payload: { event: "adaptation.reset", projectId, priorDocumentRevision: body!["expectedRevision"], actor: principal.id, reset } });
        return json(200, { projectId, reset });
      } catch (error) { return adaptationFailure(error); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/assign") {
      if (!personalMode && principal.kind !== "agent") return json(403, { error: "forbidden", reason: "enterprise assignments require a delegated product observer" });
      if (typeof body!["subjectId"] !== "string") return json(400, { error: "subjectId is required" });
      try {
        const assignment = app.outcomeAdaptation(projectId).assign(body!["subjectId"]);
        app.spine.stage({ type: "identity.action", actor: "outcome-adaptation", payload: { event: "adaptation.assigned", projectId, experimentId: assignment.experimentId, assignmentId: assignment.assignmentId, arm: assignment.arm, behaviorVersion: assignment.behaviorVersion, observer: principal.id } });
        return json(200, { projectId, assignment });
      } catch (error) { return adaptationFailure(error); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/outcome") {
      if (!personalMode && principal.kind !== "agent") return json(403, { error: "forbidden", reason: "enterprise outcomes require a delegated product observer" });
      if (typeof body!["assignmentId"] !== "string" || typeof body!["outcomeId"] !== "string" || typeof body!["observedAt"] !== "number" || typeof body!["quality"] !== "number" || typeof body!["regressed"] !== "boolean") return json(400, { error: "assignmentId, outcomeId, observedAt, quality, and regressed are required" });
      try {
        const decision = app.outcomeAdaptation(projectId).observe({ assignmentId: body!["assignmentId"], outcomeId: body!["outcomeId"], observedAt: body!["observedAt"], quality: body!["quality"], regressed: body!["regressed"], evidence: "observed-product" });
        app.spine.stage({ type: "identity.action", actor: "outcome-adaptation", payload: { event: `adaptation.${decision.kind}`, projectId, assignmentId: body!["assignmentId"], outcomeIdDigest: app.projectAuditDigest!(projectId, "adaptation-outcome", body!["outcomeId"] as string), observer: principal.id, outcomeProvenance: "delegated-observer-report-after-recorded-exposure", reason: decision.reason } });
        return json(200, { projectId, decision });
      } catch (error) { return adaptationFailure(error); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/live-outcome") {
      if (!personalMode && principal.kind !== "agent") return json(403, { error: "forbidden", reason: "enterprise outcomes require a delegated product observer" });
      if (typeof body!["outcomeId"] !== "string" || typeof body!["observedAt"] !== "number" || typeof body!["quality"] !== "number" || typeof body!["regressed"] !== "boolean") return json(400, { error: "outcomeId, observedAt, quality, and regressed are required" });
      try {
        const decision = app.outcomeAdaptation(projectId).observeLive({ outcomeId: body!["outcomeId"], observedAt: body!["observedAt"], quality: body!["quality"], regressed: body!["regressed"], evidence: "observed-product" });
        app.spine.stage({ type: "identity.action", actor: "outcome-adaptation", payload: { event: `adaptation.live-${decision.kind}`, projectId, outcomeIdDigest: app.projectAuditDigest!(projectId, "adaptation-live-outcome", body!["outcomeId"] as string), observer: principal.id, outcomeProvenance: "delegated-observer-report", reason: decision.reason } });
        return json(200, { projectId, decision });
      } catch (error) { return adaptationFailure(error); }
    }
    if (req.method === "POST" && req.path === "/project/adaptation/present") {
      if (typeof body!["content"] !== "string" || Buffer.byteLength(body!["content"], "utf8") > 1_048_576) return json(400, { error: "bounded content is required" });
      if (body!["assignmentId"] !== undefined && typeof body!["assignmentId"] !== "string") return json(400, { error: "assignmentId must be a string" });
      try {
        const adaptation = app.outcomeAdaptation(projectId);
        const behavior = typeof body!["assignmentId"] === "string" ? adaptation.expose(body!["assignmentId"]) : adaptation.current();
        return json(200, { projectId, behaviorVersion: behavior.prompt.version, presentation: presentAdaptiveText(body!["content"], behavior.voice) });
      } catch (error) { return adaptationFailure(error); }
    }
    return json(404, { error: "not found" });
  }

  if (req.method === "POST" && req.path === "/project/audience-export") {
    if (app.projectManager === undefined || app.audiencePerformanceFor === undefined) return json(501, { error: "project audience corpus not composed" });
    const denied = gate("audience.import"); if (denied) return denied;
    if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "owned audience exports require an authenticated human principal" });
    const b = parseBody(req.body); if (b === null) return json(400, { error: "invalid json" });
    if (typeof b["projectId"] !== "string") return json(400, { error: "invalid projectId" });
    let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
    const project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
    if (project === undefined) return json(404, { error: "project not found" });
    if (project.lifecycle === "archived") return json(409, { error: "project is archived and read-only" });
    const raw = b["item"];
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return json(400, { error: "audience export item is required" });
    const item = raw as Record<string, unknown>;
    const source = item["source"];
    const metrics = item["metrics"];
    const attributes = item["attributes"];
    if (!AUDIENCE_SOURCES.includes(source as AudienceSource)
      || typeof item["id"] !== "string" || typeof item["text"] !== "string"
      || (item["title"] !== undefined && typeof item["title"] !== "string")
      || (item["exportId"] !== undefined && typeof item["exportId"] !== "string")
      || (item["observedAt"] !== undefined && typeof item["observedAt"] !== "number")
      || metrics === null || typeof metrics !== "object" || Array.isArray(metrics)
      || (attributes !== undefined && (!Array.isArray(attributes) || attributes.some((value) => typeof value !== "string")))) {
      return json(400, { error: "invalid audience export item" });
    }
    const normalized: PerformanceItem = {
      source: source as AudienceSource, id: item["id"], text: item["text"], metrics: metrics as Record<string, number>,
      ...(typeof item["title"] === "string" ? { title: item["title"] } : {}),
      ...(Array.isArray(attributes) ? { attributes: attributes as string[] } : {}),
      ...(typeof item["exportId"] === "string" ? { exportId: item["exportId"] } : {}),
      ...(typeof item["observedAt"] === "number" ? { observedAt: item["observedAt"] } : {}),
    };
    try {
      const result = app.audiencePerformanceFor(projectId).ingest(normalized, { id: principal.id, kind: principal.kind });
      app.spine.stage({ type: "identity.action", actor: "audience-performance", payload: { event: "audience.imported", projectId, actor: principal.id, source: normalized.source, exportId: normalized.exportId ?? null, itemDigest: result.itemDigest, priorDigest: result.priorDigest ?? null, itemCount: result.items } });
      return json(200, { ok: true, projectId, ...result });
    }
    catch (error) { return audienceFailure(error); }
  }

  if (req.method === "POST" && req.path === "/project/audience-reset") {
    if (app.projectManager === undefined) return json(501, { error: "project audience corpus not composed" });
    const denied = gate("audience.reset"); if (denied) return denied;
    if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "audience corpus reset requires an authenticated human principal" });
    const b = parseBody(req.body); if (b === null || typeof b["projectId"] !== "string" || b["confirm"] !== true) return json(400, { error: "projectId and confirm=true are required" });
    let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
    const project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
    if (project === undefined) return json(404, { error: "project not found" });
    if (project.lifecycle === "archived") return json(409, { error: "project is archived and read-only" });
    try {
      const session = app.projectManager.session(projectId); const priorRevision = session.resolveDocumentVersioned(AUDIENCE_PERFORMANCE_DOCUMENT).revision;
      const reset = session.forgetDocumentVersioned(AUDIENCE_PERFORMANCE_DOCUMENT, priorRevision);
      app.spine.stage({ type: "identity.action", actor: "audience-performance", payload: { event: "audience.reset", projectId, actor: principal.id, priorDocumentRevision: priorRevision, reset } });
      return json(200, { projectId, reset });
    }
    catch (error) { return audienceFailure(error); }
  }

  if (req.method === "POST" && req.path === "/project/audience-forget") {
    if (app.projectManager === undefined || app.audiencePerformanceFor === undefined) return json(501, { error: "project audience corpus not composed" });
    const denied = gate("audience.erase"); if (denied) return denied;
    if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "audience erasure requires an authenticated human principal" });
    const b = parseBody(req.body); if (b === null || typeof b["projectId"] !== "string" || typeof b["id"] !== "string" || !AUDIENCE_SOURCES.includes(b["source"] as AudienceSource)) return json(400, { error: "projectId, source, and id are required" });
    let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
    const project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
    if (project === undefined) return json(404, { error: "project not found" });
    if (project.lifecycle === "archived") return json(409, { error: "project is archived and read-only" });
    try {
      const result = app.audiencePerformanceFor(projectId).forget(b["source"] as AudienceSource, b["id"]);
      app.spine.stage({ type: "identity.action", actor: "audience-performance", payload: { event: "audience.item-erased", projectId, actor: principal.id, source: b["source"], itemIdDigest: createHash("sha256").update(b["id"]).digest("hex"), removed: result.removed, itemCount: result.items } });
      return json(200, { projectId, ...result });
    } catch (error) { return audienceFailure(error); }
  }

  if (req.method === "GET" && req.path === "/project/audience-search") {
    if (app.projectManager === undefined || app.audiencePerformanceFor === undefined) return json(501, { error: "project audience corpus not composed" });
    const denied = gate("audience.read"); if (denied) return denied;
    if (typeof req.query["projectId"] !== "string") return json(400, { error: "invalid projectId" });
    let projectId; try { projectId = asProjectId(req.query["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
    const project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
    if (project === undefined) return json(404, { error: "project not found" });
    const query = req.query["q"]?.trim() ?? "";
    const k = req.query["limit"] === undefined ? 5 : Number(req.query["limit"]);
    if (!query || Buffer.byteLength(query, "utf8") > 4_096 || !Number.isSafeInteger(k) || k < 1 || k > 100) return json(400, { error: "bounded search query required" });
    try { return json(200, { projectId, hits: app.audiencePerformanceFor(projectId).search(query, k) }); }
    catch (error) { return audienceFailure(error); }
  }

  if (req.method === "POST" && req.path === "/project/audience-rank") {
    if (app.projectManager === undefined || app.audiencePerformanceFor === undefined) return json(501, { error: "project audience corpus not composed" });
    const denied = gate("audience.read"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null) return json(400, { error: "invalid json" });
    if (typeof b["projectId"] !== "string") return json(400, { error: "invalid projectId" });
    let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
    const project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
    if (project === undefined) return json(404, { error: "project not found" });
    const metric = typeof b["metric"] === "string" ? b["metric"].trim() : "";
    const source = b["source"];
    const candidates = b["candidates"];
    if (!metric || Buffer.byteLength(metric, "utf8") > 128 || (source !== undefined && !AUDIENCE_SOURCES.includes(source as AudienceSource)) || !Array.isArray(candidates)
      || candidates.some((candidate) => candidate === null || typeof candidate !== "object" || Array.isArray(candidate))) return json(400, { error: "bounded metric and candidates are required" });
    if (b["higherIsBetter"] !== undefined && typeof b["higherIsBetter"] !== "boolean") return json(400, { error: "higherIsBetter must be boolean" });
    try {
      const corpus = app.audiencePerformanceFor(projectId);
      const analysis = corpus.analyze(metric, b["higherIsBetter"] !== false, source as AudienceSource | undefined);
      return json(200, { projectId, metric, causal: false, analysis, ranked: corpus.rankCandidates(candidates as GenerationCandidate[], metric, b["higherIsBetter"] !== false, source as AudienceSource | undefined, analysis) });
    } catch (error) { return audienceFailure(error); }
  }

  if ((req.method === "GET" && req.path === "/project/goal") || (req.method === "POST" && ["/project/goal", "/project/goal/advance", "/project/goal/control"].includes(req.path))) {
    if (!app.projectRuntime || !app.projectManager) return json(503, { error: "durable project runtime not available" });
    const denied = gate(req.method === "GET" ? "audit.view" : req.path.endsWith("/control") ? "config.write" : "change.solve"); if (denied) return denied;
    const b = req.method === "GET" ? req.query : parseBody(req.body);
    if (!b) return json(400, { error: "invalid json" });
    const grantId = app.authorization.attribution(principal)?.grantId;
    try {
      if (req.method === "POST" && req.path === "/project/goal") {
        if (Object.keys(b).some(k => !["definition", "idempotencyKey", "active"].includes(k)) || typeof b["active"] !== "boolean"
          || typeof b["idempotencyKey"] !== "string" || !/^[A-Za-z0-9._:-]{16,128}$/u.test(b["idempotencyKey"])) return json(400, { error: "goal requires definition, active boolean and 16-128 character idempotencyKey" });
        if (principal.kind !== "human" && principal.kind !== "agent") return json(403, { error: "goal requires a human or delegated agent" });
        const digest = (value: unknown): string => createHash("sha256").update(canonicalize(value)).digest("hex");
        const projectId = await app.projectRuntime.createGoalWork({ keyDigest: digest(["keep.goal-work.create/v1", principal.tenant ?? null, principal.kind, principal.id, b["idempotencyKey"]]), requestDigest: digest(b) }, b["definition"], {
          kind: principal.kind, id: principal.id, ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }), ...(grantId === undefined ? {} : { grantId }),
        }, b["active"]);
        // Activation is persistent. Normal workers continue through their existing heartbeat.
        return json(202, app.projectRuntime.goalWork(projectId));
      }
      if (Object.keys(b).some(k => !(req.path.endsWith("/control") ? ["projectId", "expectedRevision", "active", "phase"] : ["projectId"]).includes(k)) || typeof b["projectId"] !== "string") return json(400, { error: "invalid goal request" });
      const projectId = asProjectId(b["projectId"]);
      if (!app.projectManager.list().some(record => record.id === projectId && visibleProject(record))) return json(404, { error: "project not found" });
      const view = app.projectRuntime.goalWork(projectId);
      if (req.method === "GET") return json(200, view);
      // A same-tenant caller must not borrow the stored creator's authority.
      const creator = view.document.principal;
      if (creator.id !== principal.id || creator.kind !== principal.kind || creator.tenant !== principal.tenant || creator.grantId !== grantId) return json(403, { error: "goal mutation requires its creating principal" });
      if (req.path.endsWith("/control")) {
        if (!Number.isSafeInteger(b["expectedRevision"]) || typeof b["active"] !== "boolean" || !GOAL_PHASES.includes(b["phase"] as GoalWorkPhase)) return json(400, { error: "control requires expectedRevision, active and phase" });
        app.projectRuntime.setGoalWorkControl(projectId, b["expectedRevision"] as number, b["active"], b["phase"] as GoalWorkPhase);
        return json(200, app.projectRuntime.goalWork(projectId));
      }
      return json(202, await app.projectRuntime.advanceGoalWork(projectId));
    } catch (error) {
      if (error instanceof ProjectSubmissionUncertainError) return json(409, { error: "goal creation needs reconciliation; retain the original key", status: "reconciliation-required" });
      return json(409, { error: "goal request refused: invalid contract, stale state or unavailable authority/configuration" });
    }
  }

  if (req.method === "POST" && req.path === "/project") {
    if (app.autonomyLoop === undefined || app.projectManager === undefined) return json(501, { error: "autonomy loop not composed" });
    if (app.projectRuntime === undefined) return json(503, { error: "durable project runtime not available" });
    const denied = gate("change.solve"); if (denied) return denied;
    const b = parseBody(req.body);
    if (b === null) return json(400, { error: "invalid json" });
    const postureValue = b["posture"];
    let memoryContext: TaskMemorySelection | undefined;
    if (b["memoryContext"] !== undefined) {
      try { memoryContext = parseTaskMemorySelection(b["memoryContext"]); } catch { return json(400, { error: "invalid task memory selection; explicit configured-provider consent required" }); }
      if (!app.taskMemoryForCommand || b["domainWorkflowKind"] !== undefined) return json(501, { error: "selected task memory executor is unavailable" });
      const denied = gate("memory.read"); if (denied) return denied;
      if (principal.kind !== "human" && principal.kind !== "agent") return json(403, { error: "task memory requires a human or delegated agent principal" });
      if (memoryContext.scope === "project" && b["projectId"] === undefined) return json(400, { error: "project memory requires the existing admitted projectId" });
    }
    if (b["background"] !== undefined && typeof b["background"] !== "boolean") return json(400, { error: "background must be boolean" });
    const idempotencyKey = b["idempotencyKey"];
    if (idempotencyKey !== undefined && (b["background"] !== true || typeof idempotencyKey !== "string" || !/^[A-Za-z0-9._:-]{16,128}$/u.test(idempotencyKey))) {
      return json(400, { error: "idempotencyKey requires background=true and 16-128 ASCII letters, digits, '.', '_', ':' or '-'" });
    }
    const posture = postureValue === "autonomous" || postureValue === "policy-calibrated" || postureValue === "approval-required" ? postureValue : undefined;
    const domainValue = b["domainWorkflowKind"];
    if (domainValue !== undefined && (typeof domainValue !== "string" || !DOMAIN_WORKFLOW_KINDS.includes(domainValue as DomainWorkflowKind))) {
      return json(400, { error: "invalid domainWorkflowKind" });
    }
    const domainWorkflowKind = domainValue as DomainWorkflowKind | undefined;
    if (!app.autonomyLoop.supportsStrategy(domainWorkflowKind)) return json(501, { error: domainWorkflowKind === undefined ? "software project solver not composed" : `domain workflow ${domainWorkflowKind} not composed` });
    if (typeof b["goal"] !== "string" || b["goal"].trim().length === 0 || Buffer.byteLength(b["goal"], "utf8") > 900 * 1024) return json(400, { error: "goal must be a non-empty string no larger than 900 KiB" });
    const goal = b["goal"];
    if (idempotencyKey !== undefined) {
      if (b["projectId"] !== undefined) {
        if (typeof b["projectId"] !== "string") return json(400, { error: "invalid projectId" });
        let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
        if (!app.projectManager.list().some(record => record.id === projectId && visibleProject(record))) return json(404, { error: "project not found" });
      }
      // Hash structured authenticated identity, never trust caller-supplied scope/digests.
      // The whole canonical body binds all present options and remains secret-free in the journal.
      const digest = (value: unknown): string => createHash("sha256").update(canonicalize(value)).digest("hex");
      try {
        const tracked = await app.projectRuntime.submitOnce({
          keyDigest: digest(["keep.project.submission/v1", principal.tenant ?? null, principal.kind, principal.id, idempotencyKey]),
          requestDigest: digest(b),
        }, () => {
          // Coordination may have awaited another process; revocation remains authoritative.
          if (!can(app.authorization, principal, "change.solve")) throw new Error("project submission authority was revoked");
          let project;
          if (b["projectId"] === undefined) {
            project = app.projectManager!.create({ name: "Keep project", ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }) });
            app.projectManager!.session(project.id).append("user", goal);
          } else {
            if (typeof b["projectId"] !== "string") throw new Error("invalid projectId");
            const projectId = asProjectId(b["projectId"]);
            project = app.projectManager!.list().find(record => record.id === projectId && visibleProject(record));
            if (project === undefined) throw new Error("project not found");
          }
          const binding = app.projectRuntime!.commandBinding;
          const grantId = app.authorization.attribution(principal)?.grantId;
          if (binding !== undefined && principal.kind !== "human" && principal.kind !== "agent") throw new Error("durable project command requires a human or delegated agent");
          return { projectId: project.id, ...(binding === undefined ? {} : { command: { binding, goal,
            principal: { kind: principal.kind as "human" | "agent", id: principal.id, ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }), ...(grantId === undefined ? {} : { grantId }) },
            ...(posture === undefined ? {} : { posture }), ...(domainWorkflowKind === undefined ? {} : { domainWorkflowKind }),
            ...(memoryContext === undefined ? {} : { memoryContext }),
          } }), run: (context: ProjectJobContext) => app.autonomyLoop!.runManagedProject(project.id, goal, {
            runId: context.jobId, signal: context.signal, trackActivity: context.trackActivity, ...(posture === undefined ? {} : { posture }),
            ...(domainWorkflowKind === undefined ? {} : { domainWorkflowKind }),
          }) };
        }, 1, "autonomy project run");
        void tracked.completion?.catch(() => undefined);
        if (!app.projectManager.list().some(record => record.id === tracked.projectId && visibleProject(record))) return json(404, { error: "project not found" });
        return json(202, { projectId: tracked.projectId, jobId: tracked.jobId, runId: tracked.jobId, status: tracked.replayed ? "observed" : "accepted", replayed: tracked.replayed, ...(memoryContext ? { memoryCopyNotice: TASK_MEMORY_COPY_NOTICE } : {}) });
      } catch (error) {
        if (error instanceof TaskMemoryUnavailableError || error instanceof NativeProjectCommandUnavailableError) return json(409, { error: error.message });
        if (error instanceof ProjectSubmissionConflictError) return json(409, { error: error.message });
        if (error instanceof ProjectSubmissionUncertainError) return json(409, { error: error.message, jobId: error.jobId, status: "reconciliation-required" });
        throw error;
      }
    }
    let project;
    let created = false;
    if (b["projectId"] === undefined) {
      project = app.projectManager.create({ name: "Keep project", ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }) });
      created = true;
    } else {
      if (typeof b["projectId"] !== "string") return json(400, { error: "invalid projectId" });
      let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
      project = app.projectManager.list().find((record) => record.id === projectId && visibleProject(record));
      if (project === undefined) return json(404, { error: "project not found" });
    }
    if (created) app.projectManager.session(project.id).append("user", goal);
    let run;
    try {
      let command: NativeProjectCommand | undefined;
      if (app.projectRuntime.commandBinding !== undefined || memoryContext !== undefined) {
        const binding = app.projectRuntime.commandBinding;
        if (!binding) return json(501, { error: "durable task memory command execution is unavailable" });
        const grantId = app.authorization.attribution(principal)?.grantId;
        command = { binding, goal, ...(memoryContext === undefined ? {} : { memoryContext }),
          principal: { id: principal.id, kind: principal.kind as "human" | "agent", ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }), ...(grantId === undefined ? {} : { grantId }) },
          ...(domainWorkflowKind === undefined ? {} : { domainWorkflowKind }),
          ...(posture === undefined ? {} : { posture }) };
      }
      const tracked = app.projectRuntime.submitTracked(project.id, 1, context => app.autonomyLoop!.runManagedProject(project.id, goal, {
        signal: context.signal,
        trackActivity: context.trackActivity,
        ...(b["background"] === true ? { runId: context.jobId } : {}),
        ...(posture === undefined ? {} : { posture }),
        ...(domainWorkflowKind === undefined ? {} : { domainWorkflowKind }),
      }), "autonomy project run", command);
      if (b["background"] === true) {
        // Runtime owns completion and its durable failure record; losing this response
        // does not cancel the work. This is not a detached OS-worker survival promise.
        void tracked.completion.catch(() => undefined);
        return json(202, { projectId: project.id, jobId: tracked.jobId, runId: tracked.jobId, status: "accepted", ...(memoryContext ? { memoryCopyNotice: TASK_MEMORY_COPY_NOTICE } : {}) });
      }
      run = await tracked.completion;
    } catch (error) {
      if (error instanceof TaskMemoryUnavailableError || error instanceof NativeProjectCommandUnavailableError) return json(409, { error: error.message });
      if (!created && error instanceof Error && /already bound/u.test(error.message)) return json(409, { error: error.message });
      throw error;
    }
    const implementation = run.state.artifacts["implement"] as { solve?: { proposalEvidence?: { rollback?: { patchSha256?: string } } } } | undefined;
    const proposalDigest = implementation?.solve?.proposalEvidence?.rollback?.patchSha256;
    return json(200, { projectId: project.id, runId: run.state.runId, revision: run.state.revision, status: run.state.status, note: run.state.note ?? null, wait: run.state.wait ?? null, proposal: proposalDigest !== undefined, ...(proposalDigest ? { proposalDigest } : {}), ...(memoryContext ? { memoryCopyNotice: TASK_MEMORY_COPY_NOTICE } : {}) });
  }

  if (req.method === "POST" && req.path === "/project/resume") {
    if (app.autonomyLoop === undefined || app.projectManager === undefined) return json(501, { error: "autonomy loop not composed" });
    if (app.projectRuntime === undefined) return json(503, { error: "durable project runtime not available" });
    const b = parseBody(req.body);
    if (b === null) return json(400, { error: "invalid json" });
    const approval = b["approval"] as Record<string, unknown> | undefined;
    const policy = b["policy"] as Record<string, unknown> | undefined;
    const reconciliation = b["reconciliation"] as Record<string, unknown> | undefined;
    const capability = b["capability"] as Record<string, unknown> | undefined;
    const input = {
      ...(typeof b["addSteps"] === "number" ? { addSteps: b["addSteps"] } : {}),
      ...(approval && typeof approval["decisionId"] === "string" && typeof approval["approved"] === "boolean" ? { approval: { decisionId: approval["decisionId"], approved: approval["approved"] } } : {}),
      ...(policy && typeof policy["policyId"] === "string" && typeof policy["proceed"] === "boolean" ? { policy: { policyId: policy["policyId"], proceed: policy["proceed"] } } : {}),
      ...(reconciliation && typeof reconciliation["effectId"] === "string" && typeof reconciliation["resolved"] === "boolean" && typeof reconciliation["evidenceId"] === "string" ? { reconciliation: { effectId: reconciliation["effectId"], resolved: reconciliation["resolved"], evidenceId: reconciliation["evidenceId"] } } : {}),
      ...(capability && typeof capability["capability"] === "string" && typeof capability["evidenceId"] === "string" ? { capability: { capability: capability["capability"], evidenceId: capability["evidenceId"] } } : {}),
    };
    const runId = String(b["runId"] ?? "");
    const project = app.projectManager.list().find((record) => visibleProject(record) && app.projectManager!.quarantine(record.id) === undefined && app.projectManager!.session(record.id).boundRunId() === runId);
    if (project === undefined) return json(404, { error: "project run is not bound to a durable project" });
    const denied = gate(app.autonomyLoop.resumePermission(runId, input)); if (denied) return denied;
    const memoryForResume = () => {
      const original = app.projectRuntime!.job(runId, new Set([project.id]));
      const prior = app.projectManager!.session(project.id).lastCheckpoint();
      if (original?.commandDigest === undefined) {
        if (prior?.artifacts["software_operation"] !== undefined) throw new NativeProjectCommandUnavailableError("custody");
        if (prior?.artifacts["memory_context_required"] === true) throw new TaskMemoryUnavailableError("custody");
        return undefined;
      }
      let command: NativeProjectCommand;
      try { command = app.projectRuntime!.commandForJob(runId, project.id); } catch { throw new NativeProjectCommandUnavailableError("custody"); }
      const ref = command.principal, grantId = app.authorization.attribution(principal)?.grantId;
      if (ref.id !== principal.id || ref.kind !== principal.kind || ref.tenant !== principal.tenant || ref.grantId !== grantId) {
        throw new NativeProjectCommandUnavailableError("authority");
      }
      if (command.memoryContext === undefined) {
        if (prior?.artifacts["memory_context_required"] === true) throw new TaskMemoryUnavailableError("custody");
        return undefined;
      }
      if (!can(app.authorization, principal, "memory.read")) throw new TaskMemoryUnavailableError("authority");
      if (!app.taskMemoryForCommand) throw new TaskMemoryUnavailableError("custody");
      const capability = app.taskMemoryForCommand(command, project.id);
      if (prior?.artifacts["memory_context_required"] === true) capability.restore!(prior.artifacts["memory_dependency"]);
      return capability;
    };
    let run;
    try {
      memoryForResume(); // Refuse before the new resume job is admitted.
      run = await app.projectRuntime.submit(project.id, 1, context => {
        const memoryContext = memoryForResume(); // Fresh original principal and source fence at execution.
        return app.autonomyLoop!.resumeManagedProject(project.id, runId, input, { signal: context.signal, trackActivity: context.trackActivity,
          ...(memoryContext === undefined ? {} : { memoryContext }) });
      }, "autonomy project resume");
    } catch (error) {
      if (error instanceof TaskMemoryUnavailableError || error instanceof NativeProjectCommandUnavailableError) return json(409, { error: error.message });
      throw error;
    }
    const implementation = run.state.artifacts["implement"] as { solve?: { proposalEvidence?: { rollback?: { patchSha256?: string } } } } | undefined;
    const proposalDigest = implementation?.solve?.proposalEvidence?.rollback?.patchSha256;
    return json(200, { projectId: project.id, runId: run.state.runId, revision: run.state.revision, status: run.state.status, note: run.state.note ?? null, wait: run.state.wait ?? null, proposal: proposalDigest !== undefined, ...(proposalDigest ? { proposalDigest } : {}) });
  }

  if (req.method === "GET" && req.path === "/project") {
    if (app.projectManager === undefined) return json(501, { error: "autonomy loop not composed" });
    const denied = gate("audit.view"); if (denied) return denied;
    const runId = String(req.query["runId"] ?? "");
    const record = app.projectManager.list().find((row) => visibleProject(row) && app.projectManager!.quarantine(row.id) === undefined && app.projectManager!.session(row.id).boundRunId() === runId);
    if (!record) return json(404, { error: "project not found" });
    const project = app.projectManager.session(record.id).lastCheckpoint();
    if (!project || project.runId !== runId) return json(404, { error: "project checkpoint not found" });
    const implementation = project.artifacts["implement"] as { solve?: { proposalEvidence?: unknown } } | undefined;
    const session = app.projectManager.session(record.id);
    return json(200, {
      projectId: record.id,
      project,
      proposal: implementation?.solve?.proposalEvidence ?? null,
      session: { record, history: session.history(), checkpoint: session.lastCheckpoint() ?? null, budget: { ...session.budget } },
    });
  }

  if (req.method === "POST" && req.path === "/project/merge") {
    if (app.projectMerge === undefined || app.projectManager === undefined) return json(501, { error: "local project merge not composed" });
    const b = parseBody(req.body); if (b === null) return json(400, { error: "invalid json" });
    const runId = typeof b["runId"] === "string" ? b["runId"].trim() : "";
    const decision = b["decision"];
    const proposalDigest = b["proposalDigest"];
    if (!runId || (decision !== "approve" && decision !== "veto") || typeof proposalDigest !== "string" || !/^[0-9a-f]{64}$/u.test(proposalDigest)) return json(400, { error: "runId, decision (approve|veto), and exact proposalDigest required" });
    const record = app.projectManager.list().find((row) => visibleProject(row) && app.projectManager!.quarantine(row.id) === undefined && app.projectManager!.session(row.id).boundRunId() === runId);
    if (!record) return json(404, { error: "project not found" });
    if (record.lifecycle === "archived") return json(409, { error: "project is archived and read-only" });
    const denied = gate(decision === "approve" ? "review.approve" : "review.decline"); if (denied) return denied;
    return json(200, await app.projectMerge.decide(runId, decision, proposalDigest));
  }

  if (req.method === "POST" && req.path === "/project/revert") {
    if (app.projectMerge === undefined || app.projectManager === undefined) return json(501, { error: "local project merge not composed" });
    const denied = gate("review.approve"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null || typeof b["runId"] !== "string" || b["runId"].trim() === "") return json(400, { error: "runId required" });
    const runId = b["runId"].trim();
    const record = app.projectManager.list().find((row) => visibleProject(row) && app.projectManager!.quarantine(row.id) === undefined && app.projectManager!.session(row.id).boundRunId() === runId);
    if (!record) return json(404, { error: "project not found" });
    if (record.lifecycle === "archived") return json(409, { error: "project is archived and read-only" });
    return json(200, await app.projectMerge.revert(runId));
  }

  if (req.method === "GET" && req.path === "/projects") {
    if (app.autonomyLoop === undefined) return json(200, { projects: [], active: null });
    const denied = gate("audit.view"); if (denied) return denied;
    const projects = app.autonomyLoop.manager.list().filter(visibleProject).map((r) => {
      const quarantined = app.autonomyLoop!.manager.quarantine(r.id) ?? null;
      const session = quarantined === null ? app.autonomyLoop!.manager.session(r.id) : undefined;
      const checkpoint = session?.lastCheckpoint();
      const runId = session?.boundRunId() ?? null;
      const firstGoal = quarantined === null
        ? session!.history().find((entry) => entry.role === "user")?.text
        : undefined;
      const implementation = checkpoint?.artifacts["implement"] as { solve?: { proposalEvidence?: unknown } } | undefined;
      const decision = runId === null ? null : app.spine.replay().map((event) => event.payload as Record<string, unknown>).find((payload) => typeof payload["event"] === "string" && String(payload["event"]).startsWith("local_merge.") && payload["runId"] === runId)?.["event"] ?? null;
      const goal = app.projectRuntime !== undefined && session?.resolveDocumentVersioned(GOAL_WORK_DOCUMENT).value !== undefined
        ? app.projectRuntime.goalWork(r.id) : undefined;
      // A read-only projection of retained work, not execution or whole-goal completion.
      const goalWork = goal === undefined ? undefined : {
        active: goal.document.active, phase: goal.document.phase,
        totalTasks: goal.document.definition.tasks.length, acceptedTasks: Object.keys(goal.document.accepted).length,
        deferredTasks: goal.selection.deferred.length, heldTasks: Object.keys(goal.selection.held).length,
        nextTaskId: goal.selection.selected ?? null,
      };
      return { id: String(r.id), name: firstGoal === undefined ? r.name : projectNameFromGoal(firstGoal), lifecycle: r.lifecycle, quarantined, runId, status: checkpoint?.status ?? null, proposal: implementation?.solve?.proposalEvidence !== undefined, decision, ...(goalWork === undefined ? {} : { goalWork }) };
    });
    const active = app.autonomyLoop.manager.active();
    return json(200, { projects, active: active !== undefined && projects.some((project) => project.id === active) ? String(active) : null });
  }

  if ((req.method === "GET" && req.path === "/worker/status") || (req.method === "POST" && ["/worker/stop", "/worker/pause", "/worker/resume"].includes(req.path))) {
    if (sec.workerControl === undefined) return json(404, { error: "native worker control is not composed" });
    const denied = gate(req.method === "GET" ? "audit.view" : "serve"); if (denied) return denied;
    if (req.method === "POST") {
      const body = parseBody(req.body);
      if (body?.["workerId"] !== sec.workerControl.id) return json(409, { error: "worker identity mismatch" });
      if (req.path === "/worker/stop") {
        if (!sec.workerControl.requestStop()) return json(409, { error: "worker has active requests or owned work; cancel and reconcile before stopping" });
      } else if (!sec.workerControl.setPaused?.(req.path === "/worker/pause")) return json(409, { error: "worker dispatch control unavailable or stopping" });
    }
    return json(req.method === "GET" ? 200 : 202, { workerId: sec.workerControl.id, state: sec.workerControl.state(), pid: process.pid });
  }

  if (req.method === "POST" && req.path === "/project/cancel") {
    if (app.projectRuntime === undefined) return json(503, { error: "durable project runtime not available" });
    const denied = gate("change.solve"); if (denied) return denied;
    const body = parseBody(req.body);
    if (body === null || typeof body["jobId"] !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(body["jobId"])) return json(400, { error: "invalid jobId" });
    const visibleIds = new Set(app.projectManager?.list().filter(visibleProject).map(record => record.id) ?? []);
    const job = await app.projectRuntime.cancel(body["jobId"], visibleIds);
    return job === undefined ? json(404, { error: "job not found" }) : json(202, { job });
  }

  if (req.method === "GET" && req.path === "/project/jobs") {
    if (app.projectRuntime === undefined) return json(503, { error: "durable project runtime not available" });
    const denied = gate("audit.view"); if (denied) return denied;
    const visibleIds = new Set(app.projectManager?.list().filter(visibleProject).map((record) => record.id) ?? []);
    if (req.query["jobId"] !== undefined) {
      const job = app.projectRuntime.job(req.query["jobId"], visibleIds);
      return job === undefined ? json(404, { error: "job not found" }) : json(200, { job, activities: app.projectRuntime.activities(job.id, visibleIds) ?? [] });
    }
    return json(200, { jobs: app.projectRuntime.jobs(visibleIds), status: app.projectRuntime.status(visibleIds) });
  }

  if (req.method === "POST" && (req.path === "/project/archive" || req.path === "/project/delete")) {
    if (app.projectRuntime === undefined) return json(503, { error: "durable project runtime not available" });
    const denied = gate("config.write"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null || typeof b["projectId"] !== "string") return json(400, { error: "invalid projectId" });
    let projectId; try { projectId = asProjectId(b["projectId"]); } catch { return json(400, { error: "invalid projectId" }); }
    const record = app.projectManager?.list().find((candidate) => candidate.id === projectId && visibleProject(candidate));
    if (record === undefined) return json(404, { error: "project not found" });
    try { req.path === "/project/archive" ? app.projectRuntime.archive(projectId) : app.projectRuntime.delete(projectId); }
    catch (error) { return json(409, { error: (error as Error).message }); }
    return json(200, { projectId, lifecycle: app.projectManager?.lifecycle(projectId) ?? "deleted" });
  }

  if (req.method === "GET" && req.path === "/veto") {
    if (app.vetoQueue === undefined) return json(200, { digest: null });
    const denied = gate("review.view"); if (denied) return denied;
    return json(200, { digest: app.vetoQueue.digest(Date.now(), tenant) });
  }

  if (req.method === "POST" && req.path === "/veto/approve") {
    if (app.vetoQueue === undefined) return json(501, { error: "no veto queue" });
    const denied = gate("review.approve"); if (denied) return denied;
    const b = parseBody(req.body);
    if (b === null) return json(400, { error: "invalid json" });
    const approved = app.vetoQueue.approve(String(b["id"] ?? ""), tenant);
    return json(200, { ok: approved !== null, runnable: approved !== null && app.vetoQueue.runnable(String(b["id"] ?? "")) });
  }

  if (req.method === "POST" && req.path === "/veto/decline") {
    if (app.vetoQueue === undefined) return json(501, { error: "no veto queue" });
    const denied = gate("review.decline"); if (denied) return denied;
    const b = parseBody(req.body);
    if (b === null) return json(400, { error: "invalid json" });
    const vetoed = app.vetoQueue.veto(String(b["id"] ?? ""), Date.now(), tenant);
    return json(200, { ok: vetoed });
  }

  if (req.method === "GET" && req.path === "/audit") {
    const denied = gate("audit.view"); if (denied) return denied;
    return json(200, { trail: auditTrail(app, String(req.query["id"] ?? ""), principal.tenant) });
  }

  if (req.method === "GET" && req.path === "/audit/export") {
    const denied = gate("audit.export"); if (denied) return denied;
    const after = req.query["after"] === undefined ? 0 : Number(req.query["after"]);
    const limit = req.query["limit"] === undefined ? 100 : Number(req.query["limit"]);
    let rows;
    try { rows = exportTenantAudit(app.spine, tenant, { after, limit }); }
    catch { return json(400, { error: "invalid audit export page" }); }
    return json(200, {
      scope: tenant === undefined ? "complete-local-spine" : "explicit-tenant-attribution",
      completeness: tenant === undefined ? "complete" : "only-events-carrying-resolved-tenant-attribution",
      rows,
      nextAfter: rows.length === limit ? after + rows.length : null,
    });
  }

  if (req.method === "GET" && req.path === "/fleet/operation") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate("audit.view"); if (denied) return denied;
    if (Object.keys(req.query).length !== 1 || typeof req.query["operationId"] !== "string") return json(400, { error: "exact operationId required" });
    const operation = await app.fleetLifecycle.inspect(req.query["operationId"], tenant ?? PERSONAL_TENANT_SENTINEL,
      principal.kind === "human" ? undefined : principal.id);
    return operation === undefined ? json(404, { error: "fleet operation not found" }) : json(200, { operation });
  }

  if (req.method === "GET" && req.path === "/fleet/active") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate(principal.kind === "agent" ? "change.solve" : "review.view"); if (denied) return denied;
    const active = (await app.fleetLifecycle.activeCoordinated(tenant ?? PERSONAL_TENANT_SENTINEL)).filter((handle) => principal.kind !== "agent" || handle.agent === principal.id);
    return json(200, { active });
  }

  if (req.method === "GET" && req.path === "/fleet/integrity") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate("audit.view"); if (denied) return denied;
    return json(200, await app.fleetLifecycle.integrityStatus(tenant));
  }

  if (req.method === "POST" && req.path === "/fleet/invoke") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const b = parseBody(req.body); if (b === null || typeof b["capabilityId"] !== "string" || typeof b["operation"] !== "string" || b["args"] === null || typeof b["args"] !== "object" || Array.isArray(b["args"])) return json(400, { error: "invalid fleet capability invocation" });
    const capability = app.infra.capabilities.describe(b["capabilityId"], tenant);
    if (capability === undefined) return json(404, { error: "fleet capability not found" });
    if (capability.fleet === undefined) return json(409, { error: "fleet capability lacks an admitted server-owned resource profile" });
    const admissionRequest: GatewayRequest = { ...req, path: "/fleet/admit", body: JSON.stringify({ ...b, capability: b["operation"] }) };
    const boundSecurity: GatewaySecurity = personalMode ? { token: sec.token } : { token: sec.token, principalFor: () => principal };
    const admissionResponse = await handleGatewayRequest(app, admissionRequest, boundSecurity);
    if (admissionResponse.status !== 200) return admissionResponse;
    const admitted = JSON.parse(admissionResponse.body) as { result: { proceed: boolean; reasons?: readonly string[]; handle?: FleetAdmissionHandle }; mediation: unknown };
    if (!admitted.result.proceed || admitted.result.handle === undefined) return admissionResponse;
    let effect: Awaited<ReturnType<typeof app.infra.capabilities.invoke>>;
    try {
      effect = await app.infra.capabilities.invoke({ capabilityId: b["capabilityId"], operation: b["operation"], args: b["args"] as Record<string, unknown>, auditArgs: "digest" }, { requireVerified: true, confirm: b["confirmed"] === true, ...(tenant === undefined ? {} : { tenant }), fleetPermit: admitted.result.handle });
    } catch {
      effect = { ok: false, held: false, error: "capability invocation rejected; outcome unknown" };
    }
    // Only the hub can establish non-dispatch. An adapter failure (even a
    // claimed hold) leaves its durable reservation charged across restart.
    if (effect.ok !== true && effect.held !== true) return json(409, {
      admission: admitted.result, mediation: admitted.mediation, effect,
      operationId: admitted.result.handle.operationId, settlement: "uncertain",
      error: "fleet effect outcome unknown; reconciliation required, do not retry with a new operation identity",
    });
    try {
      const settled = effect.ok ? await app.fleetLifecycle.commit(admitted.result.handle) : await app.fleetLifecycle.release(admitted.result.handle);
      if (!settled) return json(503, { error: "fleet effect settlement indeterminate", operationId: admitted.result.handle.operationId, effect, settlement: "uncertain" });
    } catch { return json(503, { error: "fleet effect settlement indeterminate", operationId: admitted.result.handle.operationId, effect, settlement: "uncertain" }); }
    return json(200, { admission: admitted.result, mediation: admitted.mediation, effect, settlement: effect.ok ? "committed" : "released" });
  }

  if (req.method === "POST" && req.path === "/fleet/admit") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate("change.solve"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null) return json(400, { error: "invalid json" });
    const confirmed = b["confirmed"] === true, declassify = b["declassify"] === true;
    if ((confirmed || declassify) && principal.kind !== "human") return json(403, { error: "forbidden", reason: "only a human may confirm or declassify a fleet effect" });
    if (confirmed || declassify) { const confirmationDenied = gate("review.approve"); if (confirmationDenied) return confirmationDenied; }
    let mediation;
    try { mediation = decideEffectMediation(b["capability"] as CapabilityIdentity, { confirmed }); }
    catch { return json(400, { error: "invalid capability identity" }); }
    let argsBytes: string;
    try { argsBytes = canonicalize(b["args"]); }
    catch { return json(400, { error: "invalid capability arguments" }); }
    if (argsBytes === undefined || Buffer.byteLength(argsBytes, "utf8") > 128 * 1024) return json(400, { error: "invalid capability arguments" });
    const argsDigest = createHash("sha256").update(argsBytes).digest("hex");
    const parentHandles = b["parents"] === undefined ? [] : b["parents"];
    let upstream;
    try { upstream = await app.fleetLifecycle.provenanceForCoordinated(parentHandles as readonly FleetAdmissionHandle[], tenant ?? PERSONAL_TENANT_SENTINEL); }
    catch { return json(404, { error: "fleet provenance parent not found" }); }
    const provenance = [...upstream, { agent: principal.id, taint: "untrusted" as const, source: `gateway:${mediation.id}` }]
      .map((hop) => declassify && hop.taint === "untrusted" ? { ...hop, taint: "trusted" as const, declassifiedBy: principal.id } : hop);
    const capabilityId = typeof b["capabilityId"] === "string" ? b["capabilityId"] : undefined;
    const descriptor = capabilityId === undefined ? undefined : app.infra.capabilities.describe(capabilityId, tenant);
    if (capabilityId !== undefined && descriptor === undefined) return json(404, { error: "fleet capability not found" });
    if (capabilityId !== undefined && descriptor?.fleet === undefined) return json(409, { error: "fleet capability lacks an admitted server-owned resource profile" });
    const profile = descriptor?.fleet;
    const targetArgument = profile?.targetArgument ?? "target";
    const args = b["args"] as Record<string, unknown>;
    const targetValue = Object.hasOwn(args, targetArgument) ? args[targetArgument] : args;
    let targetBytes: string;
    try { targetBytes = canonicalize(targetValue); } catch { return json(400, { error: "invalid capability target" }); }
    const resourceDomain = profile?.resourceDomain ?? mediation.id.split(".", 1)[0] ?? mediation.id;
    const resource = `domain:${resourceDomain}:target:${createHash("sha256").update(targetBytes).digest("hex")}`;
    const amount = profile?.admissionUnits ?? Math.max(1, Math.ceil(Buffer.byteLength(argsBytes, "utf8") / 4096));
    const effectDigest = descriptor === undefined
      ? createHash("sha256").update("keep.fleet-reservation/v1\0").update(canonicalize({ mediation: mediation.id, args: b["args"], tenant: tenant ?? PERSONAL_TENANT_SENTINEL })).digest("hex")
      : capabilityInvocationDigest({ capabilityId: capabilityId!, operation: b["operation"] as string, args, auditArgs: "digest" }, descriptor, tenant);
    const parentDigest = createHash("sha256").update(canonicalize((parentHandles as readonly FleetAdmissionHandle[]).map((handle) => handle.admissionDigest))).digest("hex");
    let result;
    try {
      result = await app.fleetLifecycle.admit({
        operationId: b["operationId"], tenant: tenant ?? PERSONAL_TENANT_SENTINEL, agent: principal.id,
        amount, gateAutoProceed: mediation.route === "allow", writeSet: [resource], inverseDependsOn: [resource],
        externalSink: mediation.effect === "external", provenance, effectDigest, basis: {
          model: app.gateway.providerName, input: argsDigest, retrieval: parentDigest, tool: mediation.id,
          policy: app.fleetLifecycle.policyIdentity(), operator: principal.id, infrastructure: app.capabilities.profileDigest,
          specification: "keep.fleet-gateway/v1",
        },
      } as FleetAdmissionRequest);
    } catch (error) {
      if ((error as Error).message.startsWith("fleet admission indeterminate:")) return json(503, { error: "fleet admission indeterminate", operationId: b["operationId"] });
      throw error;
    }
    return json(200, { result, mediation });
  }

  if (req.method === "POST" && req.path === "/fleet/settle") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate("change.solve"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null || (b["outcome"] !== "commit" && b["outcome"] !== "release")) return json(400, { error: "invalid fleet settlement" });
    const handle = b["handle"] as FleetAdmissionHandle;
    if (handle === null || typeof handle !== "object" || handle.tenant !== (tenant ?? PERSONAL_TENANT_SENTINEL) || handle.agent !== principal.id) return json(404, { error: "fleet admission not found" });
    let settled;
    try { settled = await app.fleetLifecycle.reconcile(handle, b["outcome"]); }
    catch (error) { if ((error as Error).message.startsWith("fleet settlement indeterminate:")) return json(503, { error: "fleet settlement indeterminate", operationId: handle.operationId }); throw error; }
    return settled ? json(200, { settled: true }) : json(404, { error: "fleet admission not found" });
  }

  if (req.method === "POST" && req.path === "/fleet/reconcile") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    if (principal.kind !== "human") return json(403, { error: "forbidden", reason: "operator fleet reconciliation requires a human principal" });
    const denied = gate("review.approve"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null || (b["outcome"] !== "commit" && b["outcome"] !== "release")) return json(400, { error: "invalid fleet reconciliation" });
    const handle = b["handle"] as FleetAdmissionHandle;
    if (handle === null || typeof handle !== "object" || handle.tenant !== (tenant ?? PERSONAL_TENANT_SENTINEL)) return json(404, { error: "fleet admission not found" });
    try {
      const settled = await app.fleetLifecycle.reconcileAsOperator(handle, b["outcome"]);
      return settled ? json(200, { settled: true, by: principal.id }) : json(404, { error: "fleet admission not found" });
    } catch (error) {
      if ((error as Error).message.startsWith("fleet settlement indeterminate:")) return json(503, { error: "fleet settlement indeterminate", operationId: handle.operationId });
      throw error;
    }
  }

  if (req.method === "POST" && req.path === "/fleet/recover") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate("change.solve"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null) return json(400, { error: "invalid json" });
    const recovered = await app.fleetLifecycle.recover(String(b["operationId"] ?? ""), tenant ?? PERSONAL_TENANT_SENTINEL, principal.id);
    return recovered.status === "absent" ? json(404, { error: "fleet admission not found" }) : json(200, recovered);
  }

  if (req.method === "POST" && req.path === "/fleet/policy") {
    if (app.fleetLifecycle === undefined) return json(501, { error: "fleet lifecycle not composed" });
    const denied = gate("config.write"); if (denied) return denied;
    const b = parseBody(req.body); if (b === null || b["policy"] === undefined) return json(400, { error: "invalid fleet policy" });
    try { await app.fleetLifecycle.rotatePolicy(b["policy"] as never); }
    catch (error) { return json(409, { error: "fleet policy rotation refused", reason: (error as Error).message }); }
    return json(200, { policy: app.fleetLifecycle.configurationStatus() });
  }

  if (req.method === "POST" && req.path === "/skill/publish") {
    if (skillRegistry === undefined) return json(501, { error: "no skill registry" });
    const denied = gate("skill.publish"); if (denied) return denied;
    const b = parseBody(req.body);
    const skill = b?.["skill"] as DistilledSkill | undefined;
    if (!skill || typeof skill !== "object") return json(400, { error: "skill required" });
    const pkg = publishSkill(skill, String(principal.id));
    skillRegistry.put(pkg);
    return json(200, { ok: true, id: pkg.skill.id, contentHash: pkg.contentHash });
  }

  if (req.method === "POST" && req.path === "/skill/install") {
    if (skillRegistry === undefined) return json(501, { error: "no skill registry" });
    const denied = gate("skill.install"); if (denied) return denied;
    const b = parseBody(req.body);
    const pkg = b?.["pkg"] as SkillPackage | undefined;
    if (!pkg || typeof pkg !== "object") return json(400, { error: "pkg required" });
    const result = await installSkill(pkg, { store: skillRegistry, gate: buildInstallGate(app) });
    return result.ok ? json(200, { ok: true, id: result.pkg.skill.id }) : json(422, { ok: false, reason: result.reason, detail: result.detail });
  }

  // ─── M5-REVET: ADOPT an OpenClaw skill (warn-first, bespoke-by-default). Never a silent import: ALWAYS returns the
  //     security warning + a bespoke Keep spec. A raw foreign skill is published ONLY when the caller acknowledges the
  //     risk AND it clears the SAME forbidden-sink gate. ───
  if (req.method === "POST" && req.path === "/skill/adopt-openclaw") {
    if (skillRegistry === undefined) return json(501, { error: "no skill registry" });
    const denied = gate("skill.install"); if (denied) return denied;
    const b = parseBody(req.body);
    const artifact = b?.["skill"];
    if (typeof artifact !== "string" && (artifact === null || typeof artifact !== "object")) {
      return json(422, { ok: false, reason: "expected `skill` to be a SKILL.md string or a legacy manifest object" });
    }
    const ack = b?.["acknowledgeRisk"] === true;
    const result = adoptOpenClawSkill(artifact as string | Record<string, unknown>, { acknowledgeRisk: ack });
    if (result.rejected) return json(422, { ok: false, warning: result.warning, reason: result.rejected, signature: result.signature });
    // DEFAULT (or gate-rejected foreign): return the warning + bespoke recommendation, publish NOTHING foreign.
    if (!result.rawSkill) {
      return json(200, { ok: true, adopted: false, warning: result.warning, bespokeSpec: result.bespokeSpec, recommendation: result.recommendation, signature: result.signature, unsupported: result.unsupported, ...(result.rawRejected ? { rawRejected: result.rawRejected } : {}) });
    }
    // OVERRIDE honored: the acknowledged, gate-passed foreign skill is published (the warning still rides along).
    const pkg = publishSkill(result.rawSkill, `${principal.id}:openclaw-adopt-acknowledged`);
    skillRegistry.put(pkg);
    return json(200, { ok: true, adopted: true, warning: result.warning, id: pkg.skill.id, contentHash: pkg.contentHash, signature: result.signature, unsupported: result.unsupported });
  }

  if (req.method === "GET" && req.path === "/skills") {
    if (skillRegistry === undefined) return json(501, { error: "no skill registry" });
    const denied = gate("audit.view"); if (denied) return denied;
    return json(200, { skills: listRegistry(skillRegistry).map((p) => ({ id: p.skill.id, name: p.skill.name, origin: p.origin, contentHash: p.contentHash })) });
  }

  // Explicit durable manual-memory opt-in. Scope comes from existing identity/project
  // authority, never a request-supplied owner or tenant. Legacy ephemeral tools remain below.
  if (req.path === "/memory/durable" || req.path === "/memory/durable/init") {
    const body = req.method === "POST" ? parseBody(req.body) : undefined;
    if (req.method !== "GET" && req.method !== "POST") return json(405, { error: "method not allowed" });
    const init = req.path.endsWith("/init");
    if (init && req.method !== "POST") return json(405, { error: "initialization requires POST" });
    const targetValue = req.method === "GET" ? req.query : body?.["target"];
    if (!targetValue || typeof targetValue !== "object" || Array.isArray(targetValue)) return json(400, { error: "memory target required" });
    const target = targetValue as Record<string, unknown>;
    const targetFields = req.method === "GET" ? ["scope", "projectId", "agentId", "action", "id", "kind", "tier", "includeRetired"] : ["scope", "projectId", "agentId"];
    if (Object.keys(target).some(key => !targetFields.includes(key))) return json(400, { error: "caller-selected owner/tenant or unknown memory target is forbidden" });
    const kind = target["scope"] ?? "user";
    if (!["user", "project", "agent", "global"].includes(String(kind))) return json(400, { error: "invalid memory scope" });
    const command = body?.["command"] as DurableMemoryMutation | undefined;
    const consolidate = !init && command?.action === "consolidate";
    const read = !init && (req.method === "GET" || command?.action === "recall");
    const controlOperation = !init && (command?.action === "erase" || command?.action === "hold");
    const permission: Permission = init ? "memory.write" : read ? "memory.read" : command?.action === "hold" ? "config.write" : command?.action === "forget" || command?.action === "purge" || command?.action === "erase" ? "memory.forget" : "memory.write";
    const denied = gate(permission); if (denied) return denied;
    if (consolidate) { const readDenied = gate("memory.read"); if (readDenied) return readDenied; }
    if (!init && command?.action === "hold" && principal.kind !== "human") return json(403, { error: "registered memory holds require human configuration authority" });
    if (init && (principal.kind !== "human" || body?.["retain"] !== true)) return json(400, { error: "a human must explicitly consent to retained manual memory (retain=true)" });
    const actorIdentity = { id: principal.id, kind: principal.kind, tenant: principal.tenant };
    const resolveScope = (): MemoryPartitionScope | undefined => {
      let current: Principal | undefined;
      try { current = personalMode ? OWNER : sec.identity !== undefined
        ? resolvedEnterprisePrincipal(sec.identity.sessions.get(req.headers["x-keep-session"], Date.now())?.principal)
        : resolvedEnterprisePrincipal(sec.principalFor?.(req)); } catch { return undefined; }
      if (!current || current.id !== actorIdentity.id || current.kind !== actorIdentity.kind || current.tenant !== actorIdentity.tenant || !can(app.authorization, current, permission)
        || (consolidate && !can(app.authorization, current, "memory.read"))) return undefined;
      return resolveMemoryScope({ principal: current, target: { scope: kind, projectId: target["projectId"], agentId: target["agentId"] },
        personalMode, ...(boundTenant === undefined ? {} : { boundTenant }), ...(app.projectManager === undefined ? {} : { manager: app.projectManager }),
        read, controlOperation, humanParent: actor => app.authorization.attribution(actor)?.humanPrincipalId });
    };
    const scope = resolveScope();
    if (!scope) return json(403, { error: "memory target is outside current resource authority" });
    const authorized = (): boolean => { const current = resolveScope(); return current !== undefined && canonicalize(current) === canonicalize(scope); };
    const initId = "keep.memory.initialize/v1";
    const initDigest = createHash("sha256").update(canonicalize({ schema: initId, scope, purpose: "explicit-manual-memory" })).digest("hex");
    try {
      const partition = app.memoryCustody.partition(scope);
      if (init) {
        const view = app.memoryCustody.initialize(scope);
        const existing = partition.lookupCommand(initId, initDigest);
        if (existing.disposition !== "committed") {
          if (view.revision !== 0 || existing.disposition !== "absent") return json(409, { error: "memory initialization requires reconciliation" });
          const committed = partition.commit(initId, 0, [], { requestDigest: initDigest, result: { initialized: true }, events: [{ id: `memory-admission:${randomUUID()}`,
            payload: { event: "memory.retention-consented", actorId: principal.id, actorKind: principal.kind, role: principal.role, permission: "memory.write", operationId: initId,
              terminalDisposition: "committed", scope, purpose: "explicit-manual-memory", ...(tenant === undefined ? {} : { tenant }) } }] });
          if (committed.disposition !== "committed") return json(409, committed);
        }
        const audit = await deliverMemoryAdmissions(partition, app.spine);
        if (!authorized()) return json(403, { disposition: "committed-withheld", reason: "authorization-revoked" });
        return json(200, { initialized: true, scope, audit, note: "Manual memory only; retirement is not cryptographic erasure. Full erasure/backup qualification remains pending." });
      }
      const consent = partition.lookupCommand(initId, initDigest);
      if (consent.disposition !== "committed") return json(409, { error: "memory is not initialized or established custody is unavailable; initialize explicitly or reconcile, never reset" });
      const consentEventId = consent.command.events.find(event => event.payload["event"] === "memory.retention-consented")?.id;
      if (consentEventId === undefined) return json(409, { error: "memory retention evidence requires reconciliation" });
      if (req.method === "GET") {
        const view = partition.read(); const working = MemoryStore.fromPartition(view, app.spine, app.gateway, Date.now, undefined, app.memoryRetentionPolicy);
        let result: unknown;
        if (req.query["action"] === "review") result = memoryReview(working, req.query["id"] ?? "");
        else if (req.query["action"] === "list") result = memoryList(working, {
          ...(req.query["kind"] === undefined ? {} : { kind: req.query["kind"] as MemoryKind }),
          ...(req.query["tier"] === undefined ? {} : { tier: req.query["tier"] as TrustTier }),
        }, req.query["includeRetired"] === "true");
        else return json(400, { error: "durable memory GET supports list or review" });
        if (!authorized()) return json(403, { error: "memory authorization was revoked" });
        if (result === null && view.erasures?.some(erasure => erasure.id === req.query["id"])) return json(410, { error: "memory deletion admitted; metadata erasure, outside copies and media sanitization remain pending", erasure: view.erasures.find(erasure => erasure.id === req.query["id"]) });
        return json(result === null ? 404 : 200, { revision: view.revision, result });
      }
      const operationId = body?.["operationId"];
      if (typeof operationId !== "string" || !operationId || Buffer.byteLength(operationId) > 4096 || /[\u0000-\u001f\u007f]/u.test(operationId) || command === undefined) return json(400, { error: "a stable bounded operationId and command are required" });
      const receiptId = createHash("sha256").update(canonicalize(["keep.memory.request/v1", scope, principal.kind, principal.id, app.authorization.attribution(principal)?.grantId ?? null, operationId])).digest("hex");
      const outcome = await executeDurableMemoryMutation({ partition, spine: app.spine, gateway: app.gateway, authorize: authorized,
        admission: { actorId: principal.id, actorKind: principal.kind, role: principal.role, permission },
        ...(app.memoryRetentionPolicy === undefined ? {} : { retentionPolicy: app.memoryRetentionPolicy }),
        consentEventId,
      }, receiptId, command);
      const result = { ...outcome, operationId, receiptId };
      if (result.disposition === "committed" && command.action === "recall") {
        const view = partition.read(); const entries = new Map(view.entries.map(row => [row.lesson.id, row.lesson]));
        const refs = (result.result as { hits: { id: string; kind: MemoryKind; importance: number }[] }).hits;
        const now = Date.now();
        const hits = refs.flatMap(ref => {
          const lesson = entries.get(ref.id);
          if (!lesson && view.erasures?.some(erasure => erasure.id === ref.id)) return [];
          if (!lesson) throw new Error("recalled item authority unavailable");
          if (!memoryCurrentWithSourcesAt(lesson, now, entries) || !memoryPrivateUseAllowed(lesson, now, entries, app.memoryRetentionPolicy)) return [];
          return [{ ...ref, content: lesson.content, provenanceEventId: lesson.provenanceEventId,
            ...(lesson.custody === undefined ? {} : { custody: lesson.custody }) }];
        });
        if (!authorized()) return json(403, { disposition: "committed-withheld", operationId, reason: "authorization-revoked" });
        // Coverage describes the original selection, not a newly executed search.
        // Text is reconstructed from current item/source authority above on every replay.
        const retrieval = (result.result as { retrieval?: unknown }).retrieval;
        return json(200, { ...result, result: { hits, ...(retrieval === undefined ? {} : { retrieval }) } });
      }
      return json(result.disposition === "committed" ? 200 : result.disposition === "withheld" ? 410 : result.disposition === "committed-withheld" || (result.disposition === "rejected" && result.reason === "unauthorized") ? 403 : 409, result);
    } catch { return json(409, { error: "memory custody unavailable; preserve the original operation and reconcile established state" }); }
  }

  // ─── M3: manual memory tools (RBAC-gated; forget/correct are supersede-not-delete) ───
  if (req.method === "POST" && req.path === "/memory") {
    const denied = gate("memory.write"); if (denied) return denied;
    const b = parseBody(req.body);
    const content = typeof b?.["content"] === "string" ? (b["content"] as string) : "";
    if (!content) return json(400, { error: "content required" });
    if (tenant !== undefined && ((b?.["scope"] !== undefined && b["scope"] !== "project") || b?.["agentId"] !== undefined)) {
      return json(400, { error: "tenant memory writes are confined to the resolved tenant project scope" });
    }
    const res = await memoryStore(app.secondBrain.memory, {
      content,
      ...(typeof b?.["kind"] === "string" ? { kind: b["kind"] as MemoryKind } : {}),
      ...(tenant !== undefined ? { scope: "project" as const, projectId: tenant } : {
        ...(typeof b?.["scope"] === "string" ? { scope: b["scope"] as MemoryScope } : {}),
        ...(typeof b?.["agentId"] === "string" ? { agentId: b["agentId"] as string } : {}),
      }),
    });
    return res ? json(200, { ok: true, id: res.id }) : json(422, { ok: false, reason: "rejected-at-ingestion" });
  }
  if (req.method === "GET" && req.path === "/memory") {
    const denied = gate("memory.read"); if (denied) return denied;
    const q = String(req.query["q"] ?? "");
    const agentId = req.query["agentId"] !== undefined ? String(req.query["agentId"]) : undefined;
    const hits = await memoryRecall(app.secondBrain.memory, { query: q, ...(agentId !== undefined ? { agentId } : {}), ...(tenant === undefined ? {} : { projectId: tenant }) });
    return json(200, { hits });
  }
  if (req.method === "POST" && req.path === "/memory/update") {
    const denied = gate("memory.write"); if (denied) return denied;
    const b = parseBody(req.body);
    const ok = memoryUpdate(app.secondBrain.memory, String(b?.["id"] ?? ""), Number(b?.["importance"] ?? 0), tenant);
    return json(ok ? 200 : 404, { ok });
  }
  if (req.method === "POST" && req.path === "/memory/forget") {
    const denied = gate("memory.forget"); if (denied) return denied;
    const b = parseBody(req.body);
    const ok = memoryForget(app.secondBrain.memory, String(b?.["id"] ?? ""), tenant);
    return json(ok ? 200 : 404, { ok, note: "retired (supersede-not-delete) — provenance retained" });
  }
  if (req.method === "POST" && req.path === "/memory/correct") {
    const denied = gate("memory.write"); if (denied) return denied;
    const b = parseBody(req.body);
    const res = await memoryCorrect(app.secondBrain.memory, String(b?.["id"] ?? ""), String(b?.["content"] ?? ""), tenant);
    return res ? json(200, { ok: true, ...res }) : json(404, { ok: false });
  }

  // ─── M4: memory curation (list / review / purge) ───
  if (req.method === "GET" && req.path === "/memory/list") {
    const denied = gate("memory.read"); if (denied) return denied;
    const filter: MemoryFilter = {
      ...(req.query["kind"] !== undefined ? { kind: String(req.query["kind"]) as MemoryKind } : {}),
      ...(req.query["scope"] !== undefined ? { scope: String(req.query["scope"]) as MemoryScope } : {}),
      ...(req.query["tier"] !== undefined ? { tier: String(req.query["tier"]) as TrustTier } : {}),
    };
    return json(200, { memories: memoryList(app.secondBrain.memory, filter, req.query["includeRetired"] === "true", tenant) });
  }
  if (req.method === "GET" && req.path === "/memory/review") {
    const denied = gate("memory.read"); if (denied) return denied;
    const detail = memoryReview(app.secondBrain.memory, String(req.query["id"] ?? ""), tenant);
    return detail ? json(200, detail) : json(404, { error: "no such memory" });
  }
  if (req.method === "POST" && req.path === "/memory/purge") {
    const denied = gate("memory.forget"); if (denied) return denied;
    const b = parseBody(req.body);
    const filter: MemoryFilter = {
      ...(typeof b?.["kind"] === "string" ? { kind: b["kind"] as MemoryKind } : {}),
      ...(typeof b?.["scope"] === "string" ? { scope: b["scope"] as MemoryScope } : {}),
      ...(typeof b?.["tier"] === "string" ? { tier: b["tier"] as TrustTier } : {}),
    };
    const res = memoryPurge(app.secondBrain.memory, filter, tenant);
    return res ? json(200, { ok: true, ...res, note: "bulk-retired (supersede-not-delete)" })
               : json(400, { ok: false, error: "an explicit filter (kind/scope/tier) is required — no unbounded purge" });
  }

  return json(404, { error: "not found" });
}

export interface GatewayServerOptions {
  readonly worker?: { readonly id: string; readonly onStopped: () => void };
  readonly port?: number; // default 7788; 0 = ephemeral (tests)
  readonly host?: string; // default 127.0.0.1 — NEVER default to 0.0.0.0
  readonly token?: string; // injectable for tests; default: 24 random bytes
  readonly maxBodyBytes?: number;
  /** Required for shared enterprise listeners; absent intentionally selects the local n=1 owner contract. */
  readonly principalFor?: GatewaySecurity["principalFor"];
  readonly identity?: IdentityLayer;
}

export interface GatewayServerHandle {
  readonly origin: string;
  readonly port: number;
  readonly token: string;
  close(): Promise<void>;
}

/** Thin socket adapter around the pure handler. Owns only binding, body, and the per-instance token. */
export function startGatewayServer(app: KeepApp, opts: GatewayServerOptions = {}): Promise<GatewayServerHandle> {
  const host = opts.host ?? "127.0.0.1";
  const token = opts.token ?? randomBytes(24).toString("hex");
  const maxBody = opts.maxBodyBytes ?? 1_000_000;
  let activeRequests = 0, stopping = false;
  const workerControl = opts.worker === undefined ? undefined : { id: opts.worker.id, state: () => stopping ? "stopping" as const : app.projectRuntime?.paused ? "paused" as const : "running" as const,
    setPaused: (paused: boolean) => {
      if (stopping || app.projectRuntime === undefined) return false;
      if (paused) app.projectRuntime.pauseDispatch(); else app.projectRuntime.resumeDispatch();
      return true;
    },
    requestStop: () => {
      const status = app.projectRuntime?.status();
      if (stopping || activeRequests !== 1 || status === undefined || status.running !== 0 || status.queued !== 0) return false;
      stopping = true; // Same event-loop turn: close admission before draining the listener.
      setImmediate(() => server.close(() => opts.worker!.onStopped())); return true;
    },
  };

  const server = createServer((req, res) => {
    if (stopping) { res.writeHead(503, { "content-type": "text/plain" }); res.end("Worker is stopping"); return; }
    activeRequests++;
    (async () => {
      let body: string;
      try {
        body = await collectBody(req, maxBody);
      } catch {
        res.writeHead(413, { "content-type": "text/plain" }); res.end("Request too large."); return;
      }
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const url = new URL(req.url ?? "/", `http://${host}:${port}`);
      const query: Record<string, string> = {};
      for (const [k, v] of url.searchParams) query[k] = v;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k.toLowerCase()] = v;
      const greq: GatewayRequest = { method: req.method ?? "GET", path: url.pathname, query, headers, body };
      const resp = await handleGatewayRequest(app, greq, { token, ...(workerControl ? { workerControl } : {}), ...(opts.principalFor ? { principalFor: opts.principalFor } : {}), ...(opts.identity ? { identity: opts.identity } : {}) });
      res.writeHead(resp.status, { ...resp.headers });
      res.end(resp.body);
    })().catch(() => { if (!res.headersSent) { res.writeHead(500, { "content-type": "text/plain" }); res.end("Internal error."); } }).finally(() => { activeRequests--; });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 7788, host, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({
        origin: `http://${host}:${port}`,
        port,
        token,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

function collectBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}


/**
 * The served desktop surface — ONE self-contained HTML string (inline CSS + browser-native fetch, no framework, no
 * build step). It renders the project list (the spine of the page), a message box with the reply, and any predictor
 * offer with accept/decline — all by calling the SAME gateway JSON routes the CLI uses. The token is baked in so the
 * page's fetches authenticate; the JSON routes still 401 without it.
 */
export function renderGatewayPage(token: string): string {
  const tok = JSON.stringify(token);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Keep</title>
<style>
:root{color-scheme:light dark}
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
main{max-width:760px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8a8f98;font-size:13px;margin:0 0 20px}
.panel{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:16px;margin:0 0 16px}
.panel h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:#8a8f98;margin:0 0 10px}
#projects div{padding:6px 0;border-bottom:1px solid #22262f}#projects .none{color:#8a8f98;border:0}
textarea{width:100%;box-sizing:border-box;background:#0f1115;color:#e6e6e6;border:1px solid #2a2f3a;border-radius:8px;padding:10px;font:inherit;resize:vertical}
button{background:#3b82f6;color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer;margin-top:8px}
button.ghost{background:#262b36}
#reply{white-space:pre-wrap;margin-top:12px}
#offer{margin-top:12px;padding:12px;border:1px dashed #3b82f6;border-radius:8px;display:none}
</style></head><body><main>
<h1>Keep</h1><p class="sub">Your safe, self-hostable build agent. Bound to your machine.</p>
<div class="panel"><h2>Projects</h2><div id="projects"><div class="none">Loading…</div></div></div>
<div class="panel" id="vetoPanel" style="display:none"><h2>Awaiting your OK</h2><div id="veto"></div></div>
<div class="panel"><h2>Message</h2>
<textarea id="msg" rows="2" placeholder="Ask Keep to do something…"></textarea>
<div><button id="send">Send</button> <button id="start" class="ghost">Start as project</button></div>
<div id="reply"></div>
<div id="offer"><span id="offerText"></span><div><button id="accept">Accept</button> <button id="decline" class="ghost">Decline</button></div></div>
</div>
<script>
var TOKEN=${tok};
function api(method,path,body){return fetch(path,{method:method,headers:{authorization:"Bearer "+TOKEN,"content-type":"application/json"},body:body?JSON.stringify(body):undefined}).then(function(r){return r.json()})}
function loadProjects(){api("GET","/projects").then(function(d){var el=document.getElementById("projects");if(!d.projects||!d.projects.length){el.innerHTML='<div class="none">No projects yet.</div>';return}el.innerHTML=d.projects.map(function(p){return '<div>'+(p.id===d.active?"\u2605 ":"")+esc(p.name)+' \u2014 '+esc(p.lifecycle)+'</div>'}).join("")})}
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return c==="&"?"&amp;":c==="<"?"&lt;":c===">"?"&gt;":c==='"'?"&quot;":"&#39;"})}
function showOffer(o){var box=document.getElementById("offer");if(!o){box.style.display="none";return}document.getElementById("offerText").textContent=o.text;box.style.display="block"}
document.getElementById("send").onclick=function(){var m=document.getElementById("msg").value;api("POST","/message",{message:m}).then(function(d){document.getElementById("reply").textContent=d.result?d.result.say:"";showOffer(d.result&&d.result.offer)})}
document.getElementById("start").onclick=function(){var m=document.getElementById("msg").value;api("POST","/project",{goal:m}).then(function(d){document.getElementById("reply").textContent="Project: "+d.status+(d.note?" \u2014 "+d.note:"");loadProjects();loadVeto()})}
document.getElementById("accept").onclick=function(){api("POST","/offer",{accepted:true}).then(function(){showOffer(null)})}
document.getElementById("decline").onclick=function(){api("POST","/offer",{accepted:false}).then(function(){showOffer(null)})}
function loadVeto(){api("GET","/veto").then(function(d){var panel=document.getElementById("vetoPanel");var el=document.getElementById("veto");if(!d.digest||!d.digest.entries||!d.digest.entries.length){panel.style.display="none";return}panel.style.display="block";el.innerHTML=d.digest.entries.map(function(e){return '<div>'+esc(e.line)+' <button data-a="'+esc(e.id)+'">Approve</button> <button class="ghost" data-d="'+esc(e.id)+'">Veto</button></div>'}).join("");el.querySelectorAll("button[data-a]").forEach(function(b){b.onclick=function(){api("POST","/veto/approve",{id:b.getAttribute("data-a")}).then(loadVeto)}});el.querySelectorAll("button[data-d]").forEach(function(b){b.onclick=function(){api("POST","/veto/decline",{id:b.getAttribute("data-d")}).then(loadVeto)}})})}
loadProjects();loadVeto();
</script></main></body></html>`;
}
