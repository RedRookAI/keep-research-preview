/**
 * The `keep` CLI core (Increment S0) — the runnable surface, back-of-house first.
 *
 * A thin, zero-dependency client over the composed KeepApp + the pipeline + the spine. It is deliberately
 * split into a testable CORE (this file — pure over an injectable CliIO + CliDeps) and a thin entrypoint
 * (keep.ts) that wires real stdin/stdout and a real pipeline. This mirrors Keep's port discipline: the surface
 * renders and gates on the real engine; it never re-implements policy.
 *
 * SOTA basis (2026-08-05, Round 2 surface research): the engineer surface is terminal-native (OpenCode/Codex/
 * Aider/Pi); the winning review pattern is an EXPLICIT diff-review that "forces the human-code-review muscle"
 * (Codex); the durable approval record must be a structured, queryable value, not a screenshot (Edilec). So the
 * review decision is recorded to the SPINE — an auditable, replayable record (the SOC 2 / EU-AI-Act artifact),
 * not a transient prompt. Zero runtime deps (Node built-ins only), which also keeps the surface from rotting in
 * a churning ecosystem.
 *
 * The human merge gate is untouched: `solve` proposes and records a review.pending; only a human `review`
 * decision approves or declines. Keep never merges.
 */

import type { MemoryDetail, MemorySummary } from "../memory/memory_tools.js";
import { parseTaskMemorySelection, type TaskMemorySelection } from "../memory/task_context.js";
import type { KeepApp } from "../compose.js";
import type { Issue } from "../solve/issue_model.js";
import type { SolveToPrResult } from "../pipeline/keep_pipeline.js";
import type { PrManifest } from "../git/pull_request.js";
import type { DecisionBrief } from "../pipeline/decision_brief.js";
import type { ForecastVerdict } from "../pipeline/consequence_forecast.js";
import { assembleDecisionPacket, renderPacket, type AssembleInputs } from "./decision_packet.js";
import { recordReviewPending, type SolveFn } from "../loop/review_intake.js";
import { renderNonEngineerView } from "../review/non_engineer_view.js";
import { authorizeSecurityCritical } from "../identity/security_gate.js";
import { computeResolutionEconomics, renderResolutionCurve } from "../resolve/resolution_curve.js";
import { computeMonitor, renderMonitor } from "../monitor/solve_monitor.js";
import { OWNER } from "../identity/rbac.js";
import { DOMAIN_WORKFLOW_KINDS, type DomainWorkflowKind } from "../autonomy/project_state.js";
import { listPendingReviews as listPending, needsDecision, getPacketInputs, isDecided, auditTrail, applyReviewDecision } from "../review/review_core.js";
import { startReviewServer, type ReviewServerHandle } from "../review/review_server.js";
import { handleGatewayRequest, startGatewayServer, type GatewayRequest, type GatewayResponse, type GatewayServerHandle } from "../gateway/http_gateway.js";
import { randomBytes, randomUUID } from "node:crypto";

/** Injectable I/O so the core is testable without a real terminal. */
export interface CliIO {
  write(text: string): void;
  /** Ask the human a question and await their (already newline-stripped) answer. */
  prompt(question: string): Promise<string>;
}

/** The pipeline seam. The entrypoint wires a real KeepPipeline.solveIssueToPR; tests wire a fake. */
// SolveFn + the review intake are canonical in loop/review_intake.js (avoids a barrel-export clash).

export interface CliDeps {
  readonly app: KeepApp;
  /** Absent → `solve` explains that a provider/repo must be configured (honest, no fake success). */
  readonly solve?: SolveFn;
  readonly clock?: () => number;
  readonly version?: string;
  /** Reads a local file (for `keep ingest`). Injectable for tests; the entrypoint wires node:fs. */
  readonly readFile?: (path: string) => string;
  /** Starts the web review UI (for `keep serve`). Injectable for tests; defaults to the real localhost server. */
  readonly serveReviews?: (app: KeepApp, opts: { port?: number }) => Promise<ReviewServerHandle>;
  /** Route a gateway request. Default: in-process handleGatewayRequest against deps.app (n=1). Remote track: an HTTP client. */
  readonly gateway?: (req: GatewayRequest) => Promise<GatewayResponse>;
  /** The gateway token (in-process: a local formality; remote: the real per-instance token). */
  readonly gatewayToken?: string;
  /** Expected token for the in-process gateway; distinct from the presented token. */
  readonly gatewayExpectedToken?: string;
  /** Starts the gateway server (for `keep serve --gateway`). Injectable for tests; defaults to the real localhost server. */
  readonly serveGateway?: (app: KeepApp, opts: { port?: number; host?: string; token?: string; identity?: NonNullable<KeepApp["identity"]> }) => Promise<GatewayServerHandle>;
  /** Durable token store — n=1 reuses the same token so a paired client stays paired across restarts. */
  readonly tokenStore?: { load(): string | undefined; save(token: string): void };
}

export interface CliResult {
  readonly command: string;
  readonly exitCode: number;
}

export type GatewayCliDeps = Pick<CliDeps, "gateway" | "gatewayToken" | "gatewayExpectedToken" | "readFile"> & { readonly app?: KeepApp };
/** Remote operation surface deliberately requires no local app/provider/repository. */
export async function runGatewayCli(argv: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const command = argv[0] ?? "help", rest = argv.slice(1);
  try {
    switch (command) {
      case "memory": return await cmdMemory(rest, io, deps);
      case "project": return await cmdProject(rest, io, deps);
      case "projects": return await cmdProjects(io, deps);
      case "merge": return await cmdProjectMerge(rest, io, deps);
      case "revert": return await cmdProjectRevert(rest, io, deps);
      case "worker": {
        if (!(rest[0] === "status" && rest.length === 1) && !(["stop", "pause", "resume"].includes(rest[0] ?? "") && rest.length === 2)) throw new Error("Usage: keep worker status | keep worker stop|pause|resume <worker-id>");
        const response = await gatewayCall(deps, rest[0] === "status" ? "GET" : "POST", "/worker/" + rest[0], rest[0] === "status" ? undefined : { workerId: rest[1] });
        io.write(response.body); return { command, exitCode: response.status === 200 || response.status === 202 ? 0 : 1 };
      }
      default: throw new Error("remote gateway mode supports project, projects, merge, revert, worker and memory commands");
    }
  } catch (error) { io.write(`Gateway operation failed: ${(error as Error).message}. A failed observation is not permission to repeat a mutation under a new key.`); return { command, exitCode: 1 }; }
}

export const DEFAULT_VERSION = "0.1.0-pre-hetzner";

export const USAGE = `keep — safe, auditable, self-hostable build automation

Usage: keep <command> [args]

Commands:
  doctor               Validate installed project readiness without calls or mutation.
  provider configure   Save a non-secret local/external, owner/organization provider profile.
  provider show        Show the active non-secret provider profile.
  encoder configure    Save a separate non-secret semantic encoder profile (docs/semantic-memory.md).
  encoder show         Show KEEP_ENCODER_PROFILE; configuring an encoder does not grant document consent.
  memory-retention configure  Save an explicit private-source retention policy (docs/semantic-memory.md).
  message <text>       Send Keep a message and get its reply (the conversational surface).
  provider-check [text] Verify the configured model path through release admission and the egress broker.
  project <goal>       Start a project; optional --posture=autonomous|policy-calibrated|approval-required.
                       Opt in to retained context with --memory=user|project|agent|global
                       --memory-processing=configured-provider; --project=<id> selects an existing project.
  project goal         Persist a goal work list: create --spec=<json-file> --idempotency-key=<key> [--activate]; show|advance <id>.
                       --background --idempotency-key=<stable-key> returns a durable job ID.
  project job <id>     Observe one job and its owned activities; project cancel <id> requests cancellation.
  worker status|stop|pause|resume  Control <worker-id>; stop requires idle, pause affects new dispatch only.
  serve --gateway --project-worker [--detach]  Run the configured native solver independently of clients.
  project resume <id>  Resume with --approve=<decision>, --decline=<decision>, --add-steps=N,
                       --capability=<name> --evidence=<id>, or --reconcile=<effect> --evidence=<id>.
  project jobs [<id>]  Show durable background jobs, optionally for one project.
  project quarantine [<id>] Show projects whose durable session could not be restored.
  project archive <id> Make a project read-only after its queued/running work has settled.
  project delete <id>  Crypto-shred a project after its queued/running work has settled.
  merge <id> <decision> Approve or veto a project's governed merge decision.
  revert <id>          Revert a project's accepted merge through the recovery controller.
  projects             List your projects (across sessions).
  offer accept|decline Respond to a suggestion Keep offered on your last message.
  onboard              Set up Keep by answering a few short questions (no config files).
  memory init --retain Initialize explicit durable manual memory (default private user scope).
  memory ... --durable Store/recall/list/review/update/forget/correct/purge retained memory.
  memory consolidate <source-id> <source-id> ... [--query=<task>]  Create a partial cited extractive view (2–8 sources).
                       --scope=project --project=<id> selects an existing shared project.
                       Reuse --operation-id=<id> after an uncertain mutation; never reset custody.
                       Durable store: --use-until=<epoch-ms> stops use at that time; erasure is separate.
                       Store/correct: --private-purpose=<id> retains exact private source only under host policy.
                       erase <id>: revoke its local key; outside copies remain pending.
                       hold <id> --hold-id=<ref> [--release]: register/release a named retention hold.
  solve <description>  Describe a goal; Keep proposes a reviewed change (never merges).
  status               List changes waiting for your review.
  review [<id>]        Review a proposed change and approve or decline it (add --plain for a
                       plain-language view for non-engineers).
  ingest <src> <file>  Ingest tracker payloads from a JSON file (no-webhook / air-gapped path).
  serve [--port=N]     Open a plain-language web page to review changes (for non-engineers).
  resolution           Show the resolution moat's honest economics (verified vs deferred, cost, escalation).
  monitor              Show every ticket in flight — what's solving, stuck, or needs your decision.
  calibration [...]    See/authorize reduced-escalation proposals (authorize needs --step-up); record outcomes.
  audit <id>           Show the plain-language history of a change.
  version              Print the Keep version.
  help                 Show this help.

Keep proposes; you dispose. Nothing is ever merged without your approval.`;

/** Commands that are intentionally available before configuration, composition, or state creation. */
export function runStaticCli(argv: readonly string[], write: (text: string) => void, version = DEFAULT_VERSION): CliResult | undefined {
  const command = (argv[0] ?? "help").toLowerCase();
  if (command === "help" || command === "--help" || command === "-h") { write(USAGE); return { command: "help", exitCode: 0 }; }
  if (command === "version" || command === "--version" || command === "-v") { write(`keep ${version}`); return { command: "version", exitCode: 0 }; }
  return undefined;
}

/** Route an argv (already stripped of node + script) to a subcommand. */
export async function runCli(argv: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const command = (argv[0] ?? "help").toLowerCase();
  const rest = argv.slice(1);
  try {
    const staticResult = runStaticCli(argv, (text) => io.write(text), deps.version);
    if (staticResult) return staticResult;
    switch (command) {
      case "message":
        return await cmdMessage(rest, io, deps);
      case "provider-check":
        return await cmdProviderCheck(rest, io, deps);
      case "project":
        return await cmdProject(rest, io, deps);
      case "projects":
        return await cmdProjects(io, deps);
      case "merge":
        return await cmdProjectMerge(rest, io, deps);
      case "revert":
        return await cmdProjectRevert(rest, io, deps);
      case "offer":
        return await cmdOffer(rest, io, deps);
      case "onboard":
        return await cmdOnboard(io, deps);
      case "solve":
        return await cmdSolve(rest, io, deps);
      case "status":
        return cmdStatus(rest, io, deps);
      case "memory":
        return await cmdMemory(rest, io, deps);
      case "review":
        return await cmdReview(rest, io, deps);
      case "audit":
        return cmdAudit(rest, io, deps);
      case "calibration":
        return cmdCalibration(rest, io, deps);
      case "ingest":
        return await cmdIngest(rest, io, deps);
      case "serve":
        return await cmdServe(rest, io, deps);
      case "resolution":
        return cmdResolution(io, deps);
      case "monitor":
        return cmdMonitor(io, deps);
      default:
        io.write(`Unknown command: ${command}\n\n${USAGE}`);
        return { command, exitCode: 2 };
    }
  } catch (err) {
    io.write(`Something went wrong: ${(err as Error).message}`);
    return { command, exitCode: 1 };
  }
}

async function cmdProviderCheck(rest: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const prompt = rest.join(" ").trim() || "Return a short Keep provider health acknowledgement.";
  const result = await deps.app.gateway.generate({ prompt, maxTokens: 64 });
  io.write(`${result.model}: ${result.text}`);
  return { command: "provider-check", exitCode: 0 };
}

// ─── reachability commands: real clients of the gateway surface (P2) ───

/** Route a request through the gateway handler — in-process by default (n=1), or an injected remote client (org). */
async function gatewayCall(deps: GatewayCliDeps, method: string, path: string, body?: unknown, query: Record<string, string> = {}): Promise<GatewayResponse> {
  const token = deps.gatewayToken ?? "keep-local";
  const call = deps.gateway ?? ((req: GatewayRequest) => { if (deps.app === undefined) throw new Error("gateway client or local app is required"); return handleGatewayRequest(deps.app, req, { token: deps.gatewayExpectedToken ?? "keep-local" }); });
  return call({ method, path, query, headers: { authorization: `Bearer ${token}` }, body: body !== undefined ? JSON.stringify(body) : "" });
}

function gatewayFailure(action: string, response: GatewayResponse): string {
  let reason: string | undefined;
  try { const body = JSON.parse(response.body) as { error?: unknown; reason?: unknown }; const value = body.error ?? body.reason; if (typeof value === "string" && value.length <= 1_024 && !value.includes("\0")) reason = value; } catch { /* generic fallback */ }
  return `${action} (status ${response.status})${reason ? `: ${reason}` : "."}`;
}

async function cmdMessage(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const message = rest.join(" ").trim();
  if (!message) { io.write('Tell me something, e.g.  keep message "add a login button"'); return { command: "message", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "POST", "/message", { message });
  if (resp.status === 501) { io.write("The conversational surface isn't available in this build (no memory configured). Try `keep onboard`."); return { command: "message", exitCode: 2 }; }
  if (resp.status !== 200) { io.write(`Couldn't send that (status ${resp.status}).`); return { command: "message", exitCode: 1 }; }
  const { result } = JSON.parse(resp.body) as { result: { say: string; offer?: { text: string } } };
  io.write(result.say);
  if (result.offer) io.write(`\n💡 ${result.offer.text}\n   (respond with:  keep offer accept   |   keep offer decline)`);
  return { command: "message", exitCode: 0 };
}

async function cmdProject(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  if (rest[0] === "goal") {
    const action = rest[1], arg = (name: string): string | undefined => rest.find(value => value.startsWith(`--${name}=`))?.slice(name.length + 3);
    let response: GatewayResponse;
    if (action === "create" && arg("spec") && arg("idempotency-key") && deps.readFile) {
      const content = deps.readFile(arg("spec")!);
      if (Buffer.byteLength(content) > 4 * 1024 * 1024) throw new Error("goal specification exceeds 4 MiB");
      response = await gatewayCall(deps, "POST", "/project/goal", { definition: JSON.parse(content), idempotencyKey: arg("idempotency-key"), active: rest.includes("--activate") });
    } else if ((action === "show" || action === "advance") && rest[2]) {
      response = action === "show" ? await gatewayCall(deps, "GET", "/project/goal", undefined, { projectId: rest[2] }) : await gatewayCall(deps, "POST", "/project/goal/advance", { projectId: rest[2] });
    } else if (action === "control" && rest[2] && arg("revision") && arg("phase") && ["true", "false"].includes(arg("active") ?? "")) {
      response = await gatewayCall(deps, "POST", "/project/goal/control", { projectId: rest[2], expectedRevision: Number(arg("revision")), phase: arg("phase"), active: arg("active") === "true" });
    } else {
      io.write("Usage: keep project goal create --spec=<json-file> --idempotency-key=<key> [--activate] | show|advance <project-id> | control <project-id> --revision=<n> --phase=development|qualification|release --active=true|false");
      return { command: "project", exitCode: 2 };
    }
    io.write(response.body); return { command: "project", exitCode: response.status === 200 || response.status === 202 ? 0 : 1 };
  }
  if (rest[0] === "job" || rest[0] === "cancel") {
    if (rest.length !== 2 || !/^[0-9a-f-]{36}$/iu.test(rest[1]!)) { io.write("Usage: keep project job|cancel <job-id>"); return { command: "project", exitCode: 2 }; }
    const response = rest[0] === "job" ? await gatewayCall(deps, "GET", "/project/jobs", undefined, { jobId: rest[1]! }) : await gatewayCall(deps, "POST", "/project/cancel", { jobId: rest[1] });
    io.write(response.body); return { command: "project", exitCode: response.status === 200 || response.status === 202 ? 0 : 1 };
  }
  if (rest[0] === "resume") return cmdProjectResume(rest.slice(1), io, deps);
  if (rest[0] === "jobs") return cmdProjectJobs(rest.slice(1), io, deps);
  if (rest[0] === "quarantine") return cmdProjectQuarantine(rest.slice(1), io, deps);
  if (rest[0] === "archive" || rest[0] === "delete") return cmdProjectLifecycle(rest[0], rest.slice(1), io, deps);
  const postureArg = rest.find((arg) => arg.startsWith("--posture="));
  const postureValue = postureArg?.slice("--posture=".length);
  if (postureValue !== undefined && postureValue !== "autonomous" && postureValue !== "policy-calibrated" && postureValue !== "approval-required") {
    io.write("Invalid posture. Use autonomous, policy-calibrated, or approval-required."); return { command: "project", exitCode: 2 };
  }
  const domainArg = rest.find((arg) => arg.startsWith("--domain="));
  const domainWorkflowKind = domainArg?.slice("--domain=".length);
  if (domainWorkflowKind !== undefined && !DOMAIN_WORKFLOW_KINDS.includes(domainWorkflowKind as DomainWorkflowKind)) {
    io.write("Invalid domain. Use long-form-fiction, academic-paper, chapter-book, social-video, or audiobook."); return { command: "project", exitCode: 2 };
  }
  const background = rest.includes("--background"), keyArg = rest.find(arg => arg.startsWith("--idempotency-key="));
  const idempotencyKey = keyArg?.slice("--idempotency-key=".length);
  if (idempotencyKey !== undefined && (!background || !/^[A-Za-z0-9._:-]{16,128}$/u.test(idempotencyKey))) { io.write("idempotency key requires --background and 16-128 ASCII letters, digits, '.', '_', ':' or '-'"); return { command: "project", exitCode: 2 }; }
  const memoryArgs = rest.filter(arg => arg.startsWith("--memory"));
  const projectArgs = rest.filter(arg => arg.startsWith("--project="));
  let memoryContext: TaskMemorySelection | undefined;
  try {
    const keys = memoryArgs.map(arg => arg.split("=")[0]);
    if (new Set(keys).size !== keys.length || memoryArgs.some(arg => !["--memory=", "--memory-processing=", "--memory-agent=", "--memory-semantic="].some(prefix => arg.startsWith(prefix))) || projectArgs.length > 1) throw new Error("duplicate or unknown memory/project flag");
    if (memoryArgs.length) {
      const value = (prefix: string) => memoryArgs.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
      const agentId = value("--memory-agent=");
      const semantic = value("--memory-semantic=");
      memoryContext = parseTaskMemorySelection({ scope: value("--memory="), processing: value("--memory-processing="), ...(agentId === undefined ? {} : { agentId }), ...(semantic === undefined ? {} : { semantic }) });
    }
  } catch { io.write("Use --memory=user|project|agent|global --memory-processing=configured-provider [--memory-agent=<id>] [--memory-semantic=configured-encoder] [--project=<project-id>], without duplicate flags. Semantic opt-in permits eligible document windows to reach the separately configured encoder."); return { command: "project", exitCode: 2 }; }
  const projectId = projectArgs[0]?.slice("--project=".length);
  const goal = rest.filter((arg) => !arg.startsWith("--posture=") && !arg.startsWith("--domain=") && arg !== "--background" && !arg.startsWith("--idempotency-key=") && !arg.startsWith("--memory") && !arg.startsWith("--project=")).join(" ").trim();
  if (!goal) { io.write('Tell me the goal, e.g.  keep project "build a markdown parser with tests"'); return { command: "project", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "POST", "/project", { goal, ...(projectId === undefined ? {} : { projectId }), ...(memoryContext === undefined ? {} : { memoryContext }), ...(background ? { background: true } : {}), ...(idempotencyKey === undefined ? {} : { idempotencyKey }), ...(postureValue === undefined ? {} : { posture: postureValue }), ...(domainWorkflowKind === undefined ? {} : { domainWorkflowKind }) });
  if (resp.status === 202) { io.write(resp.body); return { command: "project", exitCode: 0 }; }
  if (resp.status === 501) { io.write(gatewayFailure("Requested project executor isn't available", resp)); return { command: "project", exitCode: 2 }; }
  if (resp.status !== 200) { io.write(gatewayFailure("Couldn't start that", resp)); return { command: "project", exitCode: 1 }; }
  const body = JSON.parse(resp.body) as { runId: string; revision: number; status: string; note: string | null; wait: Record<string, unknown> | null; proposal?: boolean };
  renderProjectState(body, io);
  return { command: "project", exitCode: 0 };
}

async function cmdProjectJobs(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  if (rest.length > 1) { io.write("Usage: keep project jobs [<projectId>]"); return { command: "project", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "GET", "/project/jobs");
  if (resp.status !== 200) { io.write(`Couldn't list project jobs (status ${resp.status}).`); return { command: "project", exitCode: 1 }; }
  const body = JSON.parse(resp.body) as { jobs: Array<{ id: string; projectId: string; state: string; label: string }>; status: { running: number; queued: number } };
  const jobs = rest[0] === undefined ? body.jobs : body.jobs.filter((job) => job.projectId === rest[0]);
  if (jobs.length === 0) io.write("No durable project jobs match.");
  else { io.write(`Project jobs (${body.status.running} running, ${body.status.queued} queued):`); for (const job of jobs) io.write(`  ${job.id}  [${job.state}]  ${job.projectId}  ${job.label}`); }
  return { command: "project", exitCode: 0 };
}

async function cmdProjectQuarantine(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  if (rest.length > 1) { io.write("Usage: keep project quarantine [<projectId>]"); return { command: "project", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "GET", "/projects");
  if (resp.status !== 200) { io.write(`Couldn't inspect quarantine (status ${resp.status}).`); return { command: "project", exitCode: 1 }; }
  const body = JSON.parse(resp.body) as { projects: Array<{ id: string; name: string; quarantined: string | null }> };
  const rows = body.projects.filter((project) => project.quarantined !== null && (rest[0] === undefined || project.id === rest[0]));
  if (rows.length === 0) io.write("No matching projects are quarantined.");
  else { io.write("Quarantined projects:"); for (const row of rows) io.write(`  ${row.id}  ${row.name}: ${row.quarantined}`); }
  return { command: "project", exitCode: 0 };
}

async function cmdProjectLifecycle(action: "archive" | "delete", rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const projectId = rest[0]?.trim();
  if (!projectId || rest.length !== 1) { io.write(`Usage: keep project ${action} <projectId>`); return { command: "project", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "POST", `/project/${action}`, { projectId });
  if (resp.status !== 200) {
    const reason = (() => { try { return (JSON.parse(resp.body) as { error?: string }).error; } catch { return undefined; } })();
    io.write(`Couldn't ${action} that project (status ${resp.status})${reason ? `: ${reason}` : "."}`); return { command: "project", exitCode: 1 };
  }
  io.write(action === "archive" ? `Project ${projectId} is archived and read-only.` : `Project ${projectId} was crypto-shredded.`);
  return { command: "project", exitCode: 0 };
}

async function cmdProjectMerge(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const runId = rest[0]?.trim() ?? "";
  const decision = rest[1];
  const proposalArg = rest.find((arg) => arg.startsWith("--proposal="));
  const proposalDigest = proposalArg?.slice("--proposal=".length);
  if (!runId || rest.length !== 3 || (decision !== "approve" && decision !== "veto") || !proposalDigest || !/^[0-9a-f]{64}$/u.test(proposalDigest)) {
    io.write("Usage: keep merge <run-id> <approve|veto> --proposal=<sha256>");
    return { command: "merge", exitCode: 2 };
  }
  const resp = await gatewayCall(deps, "POST", "/project/merge", { runId, decision, proposalDigest });
  if (resp.status !== 200) { io.write(gatewayFailure("Could not decide project merge", resp)); return { command: "merge", exitCode: 1 }; }
  const result = JSON.parse(resp.body) as { status: string; reason: string; mergeId?: string };
  io.write(`Merge ${result.status}: ${result.reason}${result.mergeId ? ` (${result.mergeId})` : ""}`);
  return { command: "merge", exitCode: result.status === "failed" ? 1 : 0 };
}

async function cmdProjectRevert(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const runId = rest[0]?.trim() ?? "";
  if (!runId || rest.length !== 1) { io.write("Usage: keep revert <run-id>"); return { command: "revert", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "POST", "/project/revert", { runId });
  if (resp.status !== 200) { io.write(gatewayFailure("Could not revert project", resp)); return { command: "revert", exitCode: 1 }; }
  const result = JSON.parse(resp.body) as { status: string; reason: string; revertCommit?: string };
  io.write(`Revert ${result.status}: ${result.reason}${result.revertCommit ? ` (${result.revertCommit})` : ""}`);
  return { command: "revert", exitCode: result.status === "failed" ? 1 : 0 };
}

async function cmdProjectResume(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const runId = rest[0]?.trim();
  if (!runId) { io.write("Usage: keep project resume <runId> [resume option]"); return { command: "project", exitCode: 2 }; }
  const option = rest[1] ?? "";
  const evidence = rest.find((arg) => arg.startsWith("--evidence="))?.slice("--evidence=".length);
  let input: Record<string, unknown> = { runId };
  if (option.startsWith("--approve=")) input = { ...input, approval: { decisionId: option.slice(10), approved: true } };
  else if (option.startsWith("--decline=")) input = { ...input, approval: { decisionId: option.slice(10), approved: false } };
  else if (option.startsWith("--add-steps=")) input = { ...input, addSteps: Number(option.slice(12)) };
  else if (option.startsWith("--capability=") && evidence) input = { ...input, capability: { capability: option.slice(13), evidenceId: evidence } };
  else if (option.startsWith("--reconcile=") && evidence) input = { ...input, reconciliation: { effectId: option.slice(12), resolved: true, evidenceId: evidence } };
  else if ((option.startsWith("--capability=") || option.startsWith("--reconcile=")) && !evidence) { io.write("Capability and reconciliation resumes require --evidence=<id>."); return { command: "project", exitCode: 2 }; }
  else if (option !== "") { io.write("Unknown resume option."); return { command: "project", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "POST", "/project/resume", input);
  if (resp.status !== 200) { io.write(gatewayFailure("Couldn't resume that", resp)); return { command: "project", exitCode: 1 }; }
  renderProjectState(JSON.parse(resp.body) as { runId: string; revision: number; status: string; note: string | null; wait: Record<string, unknown> | null; proposal?: boolean }, io);
  return { command: "project", exitCode: 0 };
}

function renderProjectState(body: { runId: string; revision: number; status: string; note: string | null; wait: Record<string, unknown> | null; proposal?: boolean; proposalDigest?: string; memoryCopyNotice?: string }, io: CliIO): void {
  const { status, note } = body;
  if (body.memoryCopyNotice) io.write(body.memoryCopyNotice);
  const human = status === "waiting-approval" ? "waiting — it needs your go-ahead"
    : status === "waiting-policy" ? "waiting — policy must resolve this action"
    : status === "waiting-capability" ? "waiting — a named capability or safe alternative is required"
    : status === "waiting-retry" ? "waiting — a bounded retry is scheduled"
    : status === "waiting-reconciliation" ? "waiting — an external effect must be reconciled"
    : status === "paused-budget" ? "paused — it would exceed the spend cap" : status;
  const signal = body.wait?.["decisionId"] ?? body.wait?.["capability"] ?? body.wait?.["effectId"] ?? body.wait?.["resumeAt"];
  const next = body.proposal && body.proposalDigest ? `keep merge ${body.runId} approve --proposal=${body.proposalDigest}  |  keep merge ${body.runId} veto --proposal=${body.proposalDigest}`
    : status === "waiting-approval" && typeof body.wait?.["decisionId"] === "string" ? `keep project resume ${body.runId} --approve=${String(body.wait["decisionId"])}  |  keep project resume ${body.runId} --decline=${String(body.wait["decisionId"])}`
    : status.startsWith("waiting-") || status.startsWith("paused-") ? `keep project resume ${body.runId}`
    : undefined;
  io.write(`Project status: ${human}.\n  Run: ${body.runId} @ revision ${body.revision}${note ? `\n  ${note}` : ""}${signal === undefined ? "" : `\n  Resume signal: ${String(signal)}`}${next ? `\n  Next: ${next}` : "\n  Terminal: no resume action is required."}`);
}

async function cmdProjects(io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const resp = await gatewayCall(deps, "GET", "/projects");
  if (resp.status !== 200) { io.write(gatewayFailure("Couldn't list projects", resp)); return { command: "projects", exitCode: 1 }; }
  const { projects, active } = JSON.parse(resp.body) as { projects: Array<{
    id: string; name: string; lifecycle: string; quarantined: string | null; runId: string | null; status: string | null; proposal: boolean; decision: string | null;
    goalWork?: { active: boolean; phase: string; totalTasks: number; acceptedTasks: number; deferredTasks: number; heldTasks: number; nextTaskId: string | null };
  }>; active: string | null };
  if (projects.length === 0) { io.write("No projects yet. Start one with:  keep project \"<goal>\""); return { command: "projects", exitCode: 0 }; }
  io.write(`Your projects:`);
  for (const p of projects) {
    io.write(`  ${p.id === active ? "*" : " "} ${p.id}  [${p.lifecycle}${p.status ? `/${p.status}` : ""}${p.quarantined ? ", QUARANTINED" : ""}]  ${p.name}${p.runId ? `\n      Run: ${p.runId}` : ""}${p.quarantined ? ` — ${p.quarantined}` : ""}`);
    if (p.goalWork) {
      const goal = p.goalWork;
      io.write(`      Goal: ${goal.phase}, ${goal.active ? "active" : "paused"}; ${goal.acceptedTasks}/${goal.totalTasks} tested-proposals; ${goal.heldTasks} held; ${goal.deferredTasks} deferred${goal.nextTaskId === null ? "" : `; next task: ${goal.nextTaskId}`}`);
      io.write(`      Next: keep project goal show ${p.id}`);
    }
    else if (p.runId && p.proposal && p.decision === null) io.write(`      Next: keep merge ${p.runId} approve  |  keep merge ${p.runId} veto`);
    else if (p.runId && p.decision === null && p.status && !["completed", "failed"].includes(p.status)) io.write(`      Next: keep project resume ${p.runId}`);
  }
  return { command: "projects", exitCode: 0 };
}

async function cmdOffer(rest: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const verb = (rest[0] ?? "").toLowerCase();
  if (verb !== "accept" && verb !== "decline") { io.write("Usage: keep offer <accept|decline>"); return { command: "offer", exitCode: 2 }; }
  const resp = await gatewayCall(deps, "POST", "/offer", { accepted: verb === "accept" });
  if (resp.status !== 200) { io.write(`Couldn't record that (status ${resp.status}).`); return { command: "offer", exitCode: 1 }; }
  io.write(verb === "accept" ? "Okay — noted, I'll keep that in mind." : "No problem — I won't suggest that.");
  return { command: "offer", exitCode: 0 };
}

// ─── onboard: drive the deterministic FrontDoor conversation ───

async function cmdOnboard(io: CliIO, deps: CliDeps): Promise<CliResult> {
  const fd = deps.app.frontDoor;
  if (!fd) {
    io.write("Onboarding isn't available in this build (no memory configured). You can still use `keep solve`.");
    return { command: "onboard", exitCode: 0 };
  }
  const greeting = fd.greeting();
  io.write(greeting.say);
  let awaiting = greeting.awaiting;
  // The onboarding is a bounded deterministic state machine; loop until it reports done.
  // Guard with a hard cap so a misbehaving brain can never spin forever.
  for (let i = 0; i < 20; i++) {
    const reply = await io.prompt("> ");
    const turn = await fd.converse(reply);
    io.write(turn.say);
    awaiting = turn.awaiting;
    if (turn.done) break;
  }
  const directives = fd.capturedDirectives();
  if (directives.length > 0) {
    io.write(`\nGot it. I've noted ${directives.length} thing(s) you told me. They'll earn trust before they change anything.`);
  }
  return { command: "onboard", exitCode: 0 };
}

// ─── solve: run the pipeline to a human-gated PR, record it for review ───

async function cmdSolve(rest: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const description = rest.join(" ").trim();
  if (!description) {
    io.write("Tell me what to work on, e.g.  keep solve \"fix the bug where totals add tax twice\"");
    return { command: "solve", exitCode: 2 };
  }
  if (!deps.solve) {
    io.write("No model/repository is configured yet, so I can't solve here.\nRun `keep onboard` first, or configure a provider and repository.");
    return { command: "solve", exitCode: 2 };
  }
  const id = `KEEP-${(deps.clock ?? Date.now)().toString(36).toUpperCase()}`;
  const issue: Issue = { id, text: description, repoRef: "cli" };
  io.write(`Working on it… (${id})`);
  const result = await deps.solve(issue);
  if (!result.solveResult.solved || !result.manifest) {
    const why = result.solveResult.gaveUpReason ?? "I couldn't find a change I was confident in.";
    io.write(`I didn't produce a change: ${why}\nNothing was applied. You can refine the description and try again.`);
    return { command: "solve", exitCode: 0 };
  }
  recordPending(deps.app, result.manifest, (deps.clock ?? Date.now)(), result.safety?.decisionBrief, result.safety?.patchForecast);
  io.write(renderSolveSummary(result.manifest));
  io.write(`\nReview it with:  keep review ${result.manifest.id}`);
  return { command: "solve", exitCode: 0 };
}

function renderSolveSummary(m: PrManifest): string {
  const checks = m.checks.map((c) => `  - ${c.name}: ${c.passed ? "passed" : "did not pass"}`).join("\n");
  const band = m.oversight?.band ?? "medium";
  const cleared = m.oversight?.disposition === "auto-approved";
  const dispositionLine = cleared
    ? `Keep's verification cleared this and auto-approved it for batch review — nothing merged. Spot-check anytime.`
    : `This needs your decision before it can proceed${m.oversight?.requiresImmediateAttention ? " (please look soon)" : ""}. Keep never merges on its own.`;
  return [
    `\nProposed a change (not merged):`,
    `  ${m.title}`,
    `  branch: ${m.branch}`,
    checks ? `checks Keep ran & verified:\n${checks}` : "",
    `attention: ${band}`,
    `\n${dispositionLine}`,
  ].filter(Boolean).join("\n");
}

/** The machine vetting's risk-tier: does this change actually need a human decision, or was it auto-cleared?
 *  Safe default when the oversight verdict is absent: require a decision (never silently auto-clear). */

// ─── status: list pending reviews ───

function cmdStatus(rest: readonly string[], io: CliIO, deps: CliDeps): CliResult {
  const dead = deadLettered(deps.app);
  if (dead.length > 0) {
    io.write(`⚠ ${dead.length} ticket(s) could NOT be processed and are parked for you (Keep stopped retrying):`);
    for (const d of dead) io.write(`  ${d.ticketId}  — ${d.reason}`);
    io.write("");
  }
  const all = listPending(deps.app);
  if (all.length === 0) {
    io.write(dead.length > 0 ? "Nothing else is waiting for review." : "Nothing is waiting. Use `keep solve <description>` to propose a change.");
    return { command: "status", exitCode: 0 };
  }
  const showAll = rest.includes("--all");
  const needs = all.filter(needsDecision);
  const auto = all.filter((m) => !needsDecision(m));

  if (needs.length === 0) {
    io.write(`Nothing needs your decision. ${auto.length} change(s) were cleared by Keep's verification and auto-approved for batch review (nothing merged).`);
  } else {
    io.write(`${needs.length} change(s) need your decision:\n`);
    for (const m of needs) {
      const band = m.oversight?.band ?? "medium";
      io.write(`  ${m.id}  [${band}]${m.oversight?.requiresImmediateAttention ? " (soon)" : ""}  ${m.title}`);
    }
    if (auto.length > 0) io.write(`\n(${auto.length} other change(s) were auto-approved by verification — batch spot-check only.)`);
  }

  if (showAll && auto.length > 0) {
    io.write(`\nAuto-approved (verification-cleared, optional spot-check):`);
    for (const m of auto) io.write(`  ${m.id}  [${m.oversight?.band ?? "low"}]  ${m.title}`);
  } else if (auto.length > 0) {
    io.write(`See the auto-approved ones with:  keep status --all`);
  }
  io.write(`Review one with:  keep review <id>`);
  return { command: "status", exitCode: 0 };
}

/** Dead-lettered ingress tickets (retries exhausted) — parked for a human (W2 surfacing). */
function deadLettered(app: KeepApp): Array<{ ticketId: string; reason: string }> {
  const out: Array<{ ticketId: string; reason: string }> = [];
  const seen = new Set<string>();
  for (const e of app.spine.currentEvents()) {
    const p = e.payload as Record<string, unknown>;
    if (p["event"] === "trigger.dead-lettered") {
      const id = String(p["ticketId"] ?? p["issueId"] ?? "");
      if (id && !seen.has(id)) { seen.add(id); out.push({ ticketId: id, reason: String(p["reason"] ?? "repeated failures") }); }
    }
  }
  return out;
}

// ─── review: render the decision packet, record the human's decision ───

async function cmdReview(rest: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const full = rest.includes("--full");
  let id = rest.find((a) => !a.startsWith("--"));
  if (!id) {
    const pending = listPending(deps.app);
    if (pending.length === 0) { io.write("Nothing is waiting for review."); return { command: "review", exitCode: 0 }; }
    const needs = pending.filter(needsDecision);
    id = (needs[0] ?? pending[0]!).id; // default to the first change that needs a decision
  }
  const inputs = getPacketInputs(deps.app, id);
  if (!inputs) {
    io.write(`I couldn't find a change with id ${id}. Try \`keep status\`.`);
    return { command: "review", exitCode: 2 };
  }
  if (isDecided(deps.app, id)) {
    io.write(`Change ${id} has already been reviewed.`);
    return { command: "review", exitCode: 0 };
  }
  const packet = assembleDecisionPacket(inputs);
  const plain = rest.includes("--plain");
  io.write(plain ? renderNonEngineerView(packet) : renderPacket(packet, { full }));
  const answer = (await io.prompt("\nApprove this change? [approve / decline / skip]: ")).trim().toLowerCase();
  if (answer.startsWith("a") || answer === "y" || answer === "yes") {
    applyReviewDecision(deps.app, id, true, (deps.clock ?? Date.now)());
    io.write(`Approved ${id}. (Keep records your decision; merging remains your action.)`);
  } else if (answer.startsWith("d") || answer === "n" || answer === "no") {
    applyReviewDecision(deps.app, id, false, (deps.clock ?? Date.now)());
    io.write(`Declined ${id}. Nothing was applied.`);
  } else {
    io.write(`Skipped ${id}. It's still waiting for review.`);
  }
  return { command: "review", exitCode: 0 };
}

// ─── monitor: live view of every ticket in flight (S4) ───

function cmdMonitor(io: CliIO, deps: CliDeps): CliResult {
  const now = (deps.clock ?? Date.now)();
  io.write(renderMonitor(computeMonitor(deps.app.spine.currentEvents(), now), now));
  return { command: "monitor", exitCode: 0 };
}

// ─── resolution: the honest cost/efficiency curve of the resolution moat (R5) ───

function cmdResolution(io: CliIO, deps: CliDeps): CliResult {
  const econ = computeResolutionEconomics(deps.app.spine.currentEvents());
  io.write(renderResolutionCurve(econ));
  return { command: "resolution", exitCode: 0 };
}

// ─── serve: the web review UI (S2) ───

async function cmdServe(rest: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const portArg = rest.find((a) => a.startsWith("--port="));
  const port = portArg ? Number(portArg.slice("--port=".length)) : undefined;

  // `keep serve --gateway`: start the GATEWAY (the surface every client talks to), with a DURABLE token so a paired
  // phone/CLI stays paired across restarts. `--new-token` rotates it. Composes startGatewayServer; no new server.
  if (rest.includes("--gateway")) {
    const rotate = rest.includes("--new-token");
    const existing = deps.tokenStore?.load();
    // DURABLE-TOKEN: reuse the persisted token unless there is none or the operator asked to rotate.
    const token = (rotate || existing === undefined) ? (deps.gatewayToken ?? randomBytes(24).toString("hex")) : existing;
    if (deps.tokenStore && token !== existing) deps.tokenStore.save(token);
    // SAFE-BIND: 127.0.0.1 by default; binding wider is an explicit opt-in.
    const hostArg = rest.find((a) => a.startsWith("--host="));
    const host = hostArg ? hostArg.slice("--host=".length) : "127.0.0.1";
    const startGw = deps.serveGateway ?? startGatewayServer;
    const handle = await startGw(deps.app, { ...(port !== undefined ? { port } : {}), host, token, ...(deps.app.identity ? { identity: deps.app.identity } : {}) });
    io.write([
      `Keep is running. Point a client at it:`,
      ``,
      `  URL:    ${handle.origin}`,
      `  Token:  ${handle.token}`,
      ``,
      host === "127.0.0.1"
        ? `Bound to your own machine (127.0.0.1). For a phone or another device, expose it over a private overlay (e.g. Tailscale) or re-run with --host= to bind wider (behind TLS).`
        : `Bound to ${host} — make sure this is behind TLS and reachable only by trusted clients.`,
      `The token is saved, so a paired client stays paired across restarts. Rotate it with: keep serve --gateway --new-token`,
      `Press Ctrl+C to stop.`,
    ].join("\n"));
    return { command: "serve", exitCode: 0 };
  }

  const start = deps.serveReviews ?? startReviewServer;
  const handle = await start(deps.app, { ...(port !== undefined ? { port } : {}), ...(deps.app.identity ? { identity: deps.app.identity } : {}) });
  io.write(`Keep's review page is running. Open this link — it includes your private access token:\n\n  ${handle.url}\n\nIt's bound to your own machine (127.0.0.1) and no one without the token can reach it. Press Ctrl+C to stop.`);
  return { command: "serve", exitCode: 0 };
}

// ─── memory: manual store / recall / update / forget / correct (M3) ───

async function cmdMemory(rest: readonly string[], io: CliIO, deps: GatewayCliDeps): Promise<CliResult> {
  const sub = rest[0], durable = sub === "init" || sub === "erase" || sub === "hold" || sub === "consolidate" || rest.includes("--durable");
  const flag = (name: string): string | undefined => { const value = rest.find(arg => arg.startsWith("--" + name + "=")); return value?.slice(name.length + 3); };
  const queryFlags = rest.filter(arg => arg === "--query" || arg.startsWith("--query="));
  if (queryFlags.length && (sub !== "consolidate" || queryFlags.length !== 1 || flag("query") === undefined
    || Buffer.byteLength(flag("query")!) > 1024 || !/[\p{L}\p{N}]/u.test(flag("query")!.normalize("NFKC")))) {
    io.write("--query=<task> is valid once for consolidate, with 1–1024 UTF-8 bytes and at least one lexical term."); return { command: "memory", exitCode: 2 };
  }
  const processingFlags = rest.filter(arg => arg === "--processing" || arg.startsWith("--processing="));
  const privateFlags = rest.filter(arg => arg === "--private-purpose" || arg.startsWith("--private-purpose="));
  if (privateFlags.length > 1 || (privateFlags.length && (!durable || !["store", "correct"].includes(sub ?? "")
    || !/^[a-z][a-z0-9.-]{0,127}$/u.test(flag("private-purpose") ?? "") || (flag("processing") !== undefined && flag("processing") !== "source-only")))) {
    io.write("--private-purpose=<purpose-id> is valid once for durable source-only store/correct; installation policy must separately allow it."); return { command: "memory", exitCode: 2 };
  }
  if (processingFlags.length > 1 || (processingFlags.length > 0 && (!durable || !["store", "correct", "recall"].includes(sub ?? "")
    || !["source-only", "configured-provider"].includes(flag("processing") ?? "")))) {
    io.write("--processing=source-only|configured-provider is valid once, for durable store/correct/recall only."); return { command: "memory", exitCode: 2 };
  }
  const filter = { ...(flag("kind") ? { kind: flag("kind")! } : {}), ...(flag("scope") ? { scope: flag("scope")! } : {}), ...(flag("tier") ? { tier: flag("tier")! } : {}) };
  const target = { scope: flag("scope") ?? "user", ...(flag("project") ? { projectId: flag("project")! } : {}), ...(flag("agent") ? { agentId: flag("agent")! } : {}) };
  if (flag("use-until") !== undefined && (!durable || sub !== "store" || !/^\d+$/u.test(flag("use-until")!) || !Number.isSafeInteger(Number(flag("use-until"))))) {
    io.write("--use-until requires durable store and an absolute safe-integer epoch-millisecond deadline."); return { command: "memory", exitCode: 2 };
  }
  // Remote clients and local CLI use the same permission/resource boundary. A configured
  // organization identity may not silently become OWNER merely because the call is local.
  const routed = deps.gateway !== undefined || deps.app?.identity === undefined ? deps : { ...deps,
    gateway: (req: GatewayRequest) => handleGatewayRequest(deps.app!, req, { token: deps.gatewayExpectedToken ?? "keep-local", identity: deps.app!.identity! }),
  };
  let method = "POST", path = "/memory", body: Record<string, unknown> | undefined, query: Record<string, string> = {};
  if (sub === "init") { path = "/memory/durable/init"; body = { target, retain: rest.includes("--retain") }; }
  else if (sub === "store") {
    if (!rest[1]) { io.write("Usage: keep memory store <text> [--durable] [--scope=user|project|agent|global] [--project=<id>] [--agent=<id>]"); return { command: "memory", exitCode: 2 }; }
    body = { content: rest[1], ...(flag("kind") ? { kind: flag("kind")! } : {}), ...(!durable && flag("scope") ? { scope: flag("scope")! } : {}), ...(!durable && flag("agent") ? { agentId: flag("agent")! } : {}) };
    if (flag("use-until") !== undefined) body["useUntil"] = Number(flag("use-until"));
  } else if (sub === "consolidate") {
    body = { sourceIds: rest.slice(1).filter(arg => !arg.startsWith("--")), ...(flag("query") === undefined ? {} : { query: flag("query")! }) };
  } else if (sub === "recall") {
    if (durable) body = { query: rest[1] ?? "", ...(flag("k") ? { k: Number(flag("k")) } : {}) };
    else { method = "GET"; query = { q: rest[1] ?? "", ...(flag("agent") ? { agentId: flag("agent")! } : {}) }; }
  } else if (sub === "erase" || sub === "hold") {
    body = { id: rest[1] ?? "", ...(sub === "hold" ? { holdId: flag("hold-id") ?? "", active: !rest.includes("--release") } : {}) };
  } else if (sub === "update" || sub === "forget" || sub === "correct") {
    path = "/memory/" + sub;
    body = { id: rest[1] ?? "", ...(sub === "update" ? { importance: Number(flag("importance") ?? "0") } : {}), ...(sub === "correct" ? { content: rest[2] ?? "" } : {}) };
  } else if (sub === "list" || sub === "review") {
    method = "GET"; path = "/memory/" + sub;
    query = sub === "review" ? { id: rest[1] ?? "" } : { ...filter, ...(rest.includes("--include-retired") ? { includeRetired: "true" } : {}) };
  } else if (sub === "purge") { path = "/memory/purge"; body = filter; }
  else { io.write("Usage: keep memory <init|store|recall|update|forget|correct|list|review|purge|erase|hold> ... [--durable]"); return { command: "memory", exitCode: 2 }; }
  if (durable && sub !== "init") {
    path = "/memory/durable";
    if (method === "GET") query = { ...query, ...target, action: sub! };
    else {
      const operationId = flag("operation-id") ?? randomUUID();
      if (["store", "correct", "recall"].includes(sub!)) {
        body = { ...body, processing: flag("processing") ?? "source-only" };
        if (flag("private-purpose") !== undefined) body = { ...body, privatePurpose: flag("private-purpose") };
        io.write("Memory processing=" + String(body["processing"]) + ": source-only skips embedding for this operation; separately authorized model use may send text. Correction is not erasure of earlier copies.");
      }
      io.write("Memory operation id=" + operationId + "; reuse this id to reconcile an uncertain result.");
      body = { target, operationId, command: sub === "purge" ? { action: sub, filter } : { action: sub, ...body } };
    }
  }
  const response = await gatewayCall(routed, method, path, body, query);
  if (response.status !== 200) { io.write(gatewayFailure("Memory operation unavailable", response)); io.write(response.body); return { command: "memory", exitCode: 1 }; }
  const envelope = JSON.parse(response.body) as Record<string, unknown>;
  if (sub === "init") { io.write(response.body); return { command: "memory", exitCode: 0 }; }
  if (durable && envelope["audit"] === "pending") io.write("Memory committed; audit delivery is pending (not a rollback).");
  const value = durable ? envelope["result"] : envelope;
  const row = value as Record<string, unknown> | null;
  if (row?.["ingestion"] !== undefined) io.write("Stored representation: " + JSON.stringify(row["ingestion"]));
  if (sub === "consolidate" && row?.["selection"] === "lexical-query") io.write("Partial task-focused excerpts; originals remain authoritative sources. Unmatched sources kept as prefixes: " + String(row["unmatchedSources"]) + ". Omitted text may change interpretation; inspect originals.");
  if (sub === "store" || sub === "consolidate") { io.write(row?.["id"] ? (sub === "store" ? "Stored. id=" : "Derived view created; originals retained. id=") + String(row["id"]) : "Rejected at ingestion."); return { command: "memory", exitCode: row?.["id"] ? 0 : 1 }; }
  if (sub === "recall") {
    if (durable && row?.["retrieval"] !== undefined) io.write("Retrieval representation (top-K, not complete memory enumeration): " + JSON.stringify(row["retrieval"]));
    const hits = row?.["hits"] as { id: string; kind: string; content: string; importance: number }[];
    io.write(hits.length ? hits.map(hit => "[" + hit.kind + " " + hit.importance.toFixed(2) + "] " + hit.content + "  (" + hit.id + ")").join("\n") : "No memories found.");
  } else if (sub === "list") {
    const rows = (durable ? value : row?.["memories"]) as MemorySummary[];
    io.write(rows.length ? rows.map(item => item.id + "  [" + item.kind + "/" + item.scope + " " + item.tier + " " + item.importance.toFixed(2) + "]").join("\n") : "No memories.");
  } else if (sub === "review") {
    const detail = value as MemoryDetail;
    io.write((detail.content ?? (detail.useStatus === "retention-policy" ? "Content withheld: current private-retention policy does not permit use." : detail.useStatus === "source-not-current" ? "Content withheld: a supporting source is no longer current." : "Content withheld: use deadline expired; erasure remains pending.")) + "\n  kind=" + detail.kind + " scope=" + detail.scope + " tier=" + detail.tier + " origin=" + detail.origin + " importance=" + detail.importance.toFixed(2) + " evidence=" + detail.evidenceCount + "\n  provenance=" + detail.provenanceEventId + (detail.citation ? " lineage=" + detail.citation : ""));
    if (detail.custody !== undefined) io.write("  custody=" + JSON.stringify(detail.custody) + " useStatus=" + detail.useStatus);
  } else if (sub === "correct") {
    io.write(row?.["newId"] ? "Corrected. old=" + String(row["oldId"]) + " superseded by new=" + String(row["newId"]) : "No such live memory / correction failed.");
    return { command: "memory", exitCode: row?.["newId"] ? 0 : 1 };
  } else if (sub === "erase") {
    io.write("Local memory key revoked; metadata erasure, outside copies and media sanitization remain pending. " + JSON.stringify(value));
  } else if (sub === "hold") {
    io.write("Memory hold " + (row?.["active"] === true ? "registered" : "released") + ": " + String(row?.["holdId"]));
  } else if (sub === "purge") {
    io.write(row ? "Purged " + String(row["purged"]) + " (bulk-retired — provenance retained)." : "Refused: an explicit filter is required.");
    return { command: "memory", exitCode: row ? 0 : 2 };
  } else {
    const ok = durable ? value === true : row?.["ok"] === true;
    io.write(ok ? (sub === "forget" ? "Forgotten (retired — provenance retained)." : "Updated.") : "No such live memory.");
    return { command: "memory", exitCode: ok ? 0 : 1 };
  }
  return { command: "memory", exitCode: 0 };
}

// ─── audit: plain-language history from the spine ───

function cmdAudit(rest: readonly string[], io: CliIO, deps: CliDeps): CliResult {
  const id = rest[0];
  if (!id) { io.write("Usage: keep audit <id>"); return { command: "audit", exitCode: 2 }; }
  const lines = auditTrail(deps.app, id);
  if (lines.length === 0) { io.write(`No history found for ${id}.`); return { command: "audit", exitCode: 0 }; }
  io.write(`History for ${id}:\n`);
  for (const line of lines) io.write(`  ${line}`);
  return { command: "audit", exitCode: 0 };
}

/**
 * `keep ingest <source> <file.json>` — the reachable no-webhook path (NAT'd laptop, air-gapped, back-of-house).
 * Reads a JSON array (or single object) of NATIVE tracker payloads and routes each through the SAME deduped
 * ingress the webhook path uses. Use source "generic" for any tracker without a bespoke adapter. No signature is
 * required (the operator's local file access is the authentication).
 */
async function cmdIngest(rest: readonly string[], io: CliIO, deps: CliDeps): Promise<CliResult> {
  const args = rest.filter((a) => !a.startsWith("--"));
  const source = args[0];
  const file = args[1];
  const valid = new Set(["linear", "jira", "github-issues", "gitlab", "generic"]);
  if (!source || !valid.has(source) || !file) {
    io.write("Usage: keep ingest <linear|jira|github-issues|gitlab|generic> <file.json>");
    return { command: "ingest", exitCode: 2 };
  }
  const read = deps.readFile;
  if (!read) {
    io.write("File reading isn't available in this environment.");
    return { command: "ingest", exitCode: 2 };
  }
  let items: Array<Record<string, unknown>>;
  try {
    const parsed = JSON.parse(read(file)) as unknown;
    items = Array.isArray(parsed) ? (parsed as Array<Record<string, unknown>>) : [parsed as Record<string, unknown>];
  } catch (e) {
    io.write(`Couldn't read/parse ${file}: ${(e as Error).message}`);
    return { command: "ingest", exitCode: 2 };
  }
  let accepted = 0, duplicates = 0, rejected = 0, errored = 0;
  for (const native of items) {
    const r = await deps.app.triggerIngress.ingestNative(source as "generic", native);
    if (r.status === "accepted") accepted++;
    else if (r.status === "duplicate") duplicates++;
    else if (r.status === "error") errored++;
    else rejected++;
  }
  io.write(`Ingested ${items.length} item(s) from ${source}: ${accepted} accepted, ${duplicates} duplicate, ${rejected} rejected${errored ? `, ${errored} deferred (will retry)` : ""}.`);
  return { command: "ingest", exitCode: 0 };
}

/**
 * `keep calibration [status|authorize <class>|outcome <class> <clean|reverted|failed>]`.
 * The surface for the oversight learning loop (F2). Loosening (authorize) is an explicit HUMAN, governed,
 * revocable action; recording a real post-approval outcome feeds the loop (tightening is then automatic).
 */
function cmdCalibration(rest: readonly string[], io: CliIO, deps: CliDeps): CliResult {
  const wire = deps.app.calibrationWire;
  const sub = rest.find((a) => !a.startsWith("--")) ?? "status";

  if (sub === "authorize") {
    const cls = rest[rest.indexOf("authorize") + 1];
    if (!cls) { io.write("Usage: keep calibration authorize <class> --step-up"); return { command: "calibration", exitCode: 2 }; }
    // Reducing escalation lowers how much Keep asks you to review — a security-critical action. Gate it behind
    // RBAC + Separation-of-Duties dual control (step-up stands in for the second party in single-operator mode).
    const now = (deps.clock ?? Date.now)();
    const gate = authorizeSecurityCritical(
      { authorization: deps.app.authorization, separationOfDuties: deps.app.separationOfDuties, spine: deps.app.spine },
      { action: "calibration.reduce_escalation", author: OWNER, stepUpVerified: rest.includes("--step-up"), now },
    );
    if (!gate.ok) {
      io.write(`Reducing escalation for '${cls}' is a security-critical change — it lowers how much Keep asks you to review. It needs a step-up confirmation (your hardware key / re-auth):\n  keep calibration authorize ${cls} --step-up\n(reason: ${gate.reason})`);
      return { command: "calibration", exitCode: 2 };
    }
    const policy = wire.authorizeReduction(cls, OWNER.id, now);
    if (!policy) {
      io.write(`No pending reduce-escalation proposal for class '${cls}'. Keep only offers to reduce escalation for a class with a proven-clean, all-reversible outcome history. (keep calibration status)`);
      return { command: "calibration", exitCode: 2 };
    }
    io.write(`Authorized reduced escalation for class '${cls}' (dual-control step-up recorded; governed + revocable). Keep will stop asking you about proven-clean, reversible '${cls}' changes — and will automatically re-tighten if their revert rate rises.`);
    return { command: "calibration", exitCode: 0 };
  }

  if (sub === "outcome") {
    const cls = rest[rest.indexOf("outcome") + 1];
    const outcome = rest[rest.indexOf("outcome") + 2];
    if (!cls || (outcome !== "clean" && outcome !== "reverted" && outcome !== "failed")) {
      io.write("Usage: keep calibration outcome <class> <clean|reverted|failed>");
      return { command: "calibration", exitCode: 2 };
    }
    const a = wire.observeOutcome(cls, outcome);
    io.write(`Recorded a '${outcome}' outcome for class '${cls}'. ${a.recommendation === "reduce-escalation-candidate" ? `This class now has a clean-enough history — you can 'keep calibration authorize ${cls}' to stop being asked about it.` : a.recommendation === "increase-scrutiny" ? `Revert rate rose — any reduced-escalation policy for '${cls}' was automatically revoked (re-tightened).` : "Noted."}`);
    return { command: "calibration", exitCode: 0 };
  }

  // status
  const pending = wire.pendingReductions();
  const active = [...wire.activePolicyGates()];
  if (pending.length === 0 && active.length === 0) {
    io.write("No calibration proposals or active policies yet. As you review changes and their outcomes prove clean, Keep will propose reducing low-value approvals for you — you stay in control of every loosening.");
    return { command: "calibration", exitCode: 0 };
  }
  if (pending.length > 0) {
    io.write(`Proposals awaiting your authorization (proven-clean reversible classes — loosening is your call):`);
    for (const c of pending) io.write(`  ${c}   → keep calibration authorize ${c}`);
  }
  if (active.length > 0) {
    io.write(`${pending.length > 0 ? "\n" : ""}Active reduced-escalation policies (governed, revocable, auto-tightening):`);
    for (const c of active) io.write(`  ${c}`);
  }
  return { command: "calibration", exitCode: 0 };
}

// ─── spine-backed review state (the audit record IS the source of truth) ───


function recordPending(app: KeepApp, manifest: PrManifest, ts: number, brief?: DecisionBrief, forecast?: ForecastVerdict): void {
  // Delegates to the shared intake so the CLI solve path + the closed loop (W3) behave identically (review.pending
  // + correlation id + W2 notification — only the dangerous few interrupt).
  recordReviewPending({ spine: app.spine, notifications: app.notifications }, manifest, ts, { ...(brief ? { brief } : {}), ...(forecast ? { forecast } : {}), correlationId: manifest.id });
}
