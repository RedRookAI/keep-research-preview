import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

export class KeepHold extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const hash = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const JOB = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const PROJECT = /^prj_[a-f0-9]{32}$/u;
export const configSchema = {
  type: "object", additionalProperties: false,
  required: ["endpoint", "clientId", "grantId", "commandBinding", "openclawAgentId", "tokenFile", "stateDirectory", "requestTimeoutMs"],
  properties: {
    endpoint: { type: "string" }, clientId: { type: "string", maxLength: 128 }, grantId: { type: "string", maxLength: 128 },
    commandBinding: { type: "string", pattern: "^[a-f0-9]{64}$" }, openclawAgentId: { type: "string", maxLength: 128 },
    tokenFile: { type: "string" }, stateDirectory: { type: "string" }, requestTimeoutMs: { type: "integer", minimum: 1, maximum: 2147483647 },
  },
};
export function parseConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join() !== [...configSchema.required].sort().join()) throw new KeepHold("configuration");
  const endpoint = new URL(value.endpoint);
  if (!((endpoint.protocol === "http:" && endpoint.hostname === "127.0.0.1") || endpoint.protocol === "https:")
    || endpoint.username || endpoint.password || endpoint.pathname !== "/" || endpoint.search || endpoint.hash
    || ![value.clientId, value.grantId, value.openclawAgentId].every(s => typeof s === "string" && ID.test(s))
    || typeof value.commandBinding !== "string" || !SHA256.test(value.commandBinding)
    || ![value.tokenFile, value.stateDirectory].every(p => typeof p === "string" && isAbsolute(p) && !p.includes("\0"))
    || !Number.isSafeInteger(value.requestTimeoutMs) || value.requestTimeoutMs < 1 || value.requestTimeoutMs > 2147483647) throw new KeepHold("configuration");
  return Object.freeze({ ...value, endpoint: endpoint.origin });
}
export function captureScope(config, context, toolCallId, signal) {
  if (context.senderIsOwner !== true || context.agentId !== config.openclawAgentId || typeof context.assertInvocationCurrent !== "function"
    || ![context.sessionId, context.sessionKey, toolCallId].every(s => typeof s === "string" && s.length > 0 && Buffer.byteLength(s) <= 1024 && !/[\u0000-\u001f\u007f]/u.test(s))) throw new KeepHold("context");
  const assertCurrent = () => { signal?.throwIfAborted(); context.assertInvocationCurrent(); };
  assertCurrent();
  return Object.freeze({ assertCurrent,
    conversation: hash(["keep.openclaw-conversation/v1", config.clientId, context.agentId, context.sessionKey]),
    call: hash(["keep.openclaw-call/v1", context.agentId, context.sessionId, context.sessionKey, toolCallId]),
  });
}
export function goalInput(params) {
  if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).join() !== "goal"
    || typeof params.goal !== "string" || !params.goal.trim() || params.goal.includes("\0") || Buffer.byteLength(params.goal) > 900 * 1024) throw new KeepHold("input");
  return params.goal;
}
export function emptyInput(params) {
  if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length) throw new KeepHold("input");
}
function object(value, allowed, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !(k in value))) throw new KeepHold("response");
  return value;
}
const oneOf = (value, choices) => { if (!choices.includes(value)) throw new KeepHold("response"); return value; };
const bool = value => { if (typeof value !== "boolean") throw new KeepHold("response"); return value; };
const text = (value, max = 4096) => { if (typeof value !== "string" || value.length > max) throw new KeepHold("response"); return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/gu, ""); };
export function acceptedResponse(value) {
  object(value, ["projectId", "jobId", "runId", "status", "replayed"], ["projectId", "jobId", "runId", "status"]);
  if (!PROJECT.test(value.projectId) || !JOB.test(value.jobId) || value.runId !== value.jobId) throw new KeepHold("response");
  oneOf(value.status, ["accepted", "observed"]);
  if (value.replayed !== undefined) bool(value.replayed);
  return { projectId: value.projectId, jobId: value.jobId };
}
export function statusResponse(value, expected) {
  object(value, ["projectId", "jobId", "job", "run", "proposal", "review", "delivery"]);
  if (value.projectId !== expected.projectId || value.jobId !== expected.jobId) throw new KeepHold("response");
  const job = object(value.job, ["state", "reason", "cancellationRequested"], ["state", "cancellationRequested"]);
  oneOf(job.state, ["queued", "running", "stopped", "reconciliation-required", "completed", "failed"]); bool(job.cancellationRequested);
  const result = { projectId: value.projectId, jobId: value.jobId, job: { state: job.state, cancellationRequested: job.cancellationRequested,
    ...(job.reason === undefined ? {} : { reason: text(job.reason) }) }, run: null };
  if (value.run !== null) {
    const run = object(value.run, ["status", "stage", "wait"]);
    oneOf(run.status, ["running", "waiting-retry", "waiting-capability", "waiting-approval", "waiting-policy", "waiting-reconciliation", "paused-budget", "completed", "failed"]);
    oneOf(run.stage, ["understand", "research", "rag", "plan", "vet_plan", "ticket", "implement", "vet_artifact", "learn", "done"]);
    let wait = null;
    if (run.wait !== null) {
      const source = object(run.wait, ["kind", "reason", "decisionId"], ["kind", "reason"]);
      wait = { kind: text(source.kind, 64), reason: text(source.reason), ...(source.decisionId === undefined ? {} : { decisionId: text(source.decisionId, 512) }) };
    }
    result.run = { status: run.status, stage: run.stage, wait };
  }
  const proposal = object(value.proposal, ["available", "digest", "checks"]); bool(proposal.available);
  if (proposal.digest !== null && (typeof proposal.digest !== "string" || !SHA256.test(proposal.digest))) throw new KeepHold("response");
  let checks = null;
  if (proposal.checks !== null) { object(proposal.checks, ["testsPassed", "vettingCleared"]); checks = { testsPassed: proposal.checks.testsPassed === null ? null : bool(proposal.checks.testsPassed), vettingCleared: proposal.checks.vettingCleared === null ? null : bool(proposal.checks.vettingCleared) }; }
  const review = object(value.review, ["vetoed", "latestDecision", "generationDecision"], ["vetoed", "latestDecision"]);
  const delivery = object(value.delivery, ["workspace", "source", "revert"]);
  return { ...result, proposal: { available: proposal.available, digest: proposal.digest, checks },
    review: { vetoed: bool(review.vetoed), latestDecision: review.latestDecision === null ? null : text(review.latestDecision, 256), generationDecision: oneOf(review.generationDecision ?? null, [null, "approved", "declined"]) },
    delivery: { workspace: oneOf(delivery.workspace, ["unknown", "merged", "reverted"]), source: oneOf(delivery.source, ["unknown", "landed", "refused", "reverted"]), revert: oneOf(delivery.revert, ["unknown", "reverted", "refused"]) },
  };
}
export function isTerminal(status) {
  if (["running", "queued", "reconciliation-required"].includes(status.job.state) || status.job.cancellationRequested) return false;
  return status.review.vetoed || status.review.generationDecision === "declined" || ["landed", "reverted"].includes(status.delivery.source)
    || (status.job.state === "completed" && status.run?.status === "failed");
}
