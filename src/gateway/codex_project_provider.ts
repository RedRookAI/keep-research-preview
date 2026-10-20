import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { types } from "node:util";
import type { Spine } from "../spine/spine.js";
import type { StagedEvent } from "../spine/event.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import { CODEX_GENERATION_PROFILE, CodexAccountClient, CodexAccountError, type CodexAccountClientOptions } from "./codex_account_client.js";

export interface CodexProjectDescriptor extends CodexAccountClientOptions {
  readonly executableSha256: string;
  readonly cliVersion: string;
  readonly maxInvocations: number;
  readonly processing: "owner-public-repository";
}
export function captureCodexProjectDescriptor(input: CodexProjectDescriptor): CodexProjectDescriptor {
  const keys = ["executable", "executableSha256", "cliVersion", "model", "maxSubmittedPromptBytes", "maxCapturedOutputBytes", "maxElapsedMs", "maxInvocations", "processing"];
  if (!input || types.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Reflect.ownKeys(input).map(String).sort().join(",") !== keys.sort().join(",") ||
      Object.values(Object.getOwnPropertyDescriptors(input)).some(d => !("value" in d) || !d.enumerable) ||
      !/^[a-f0-9]{64}$/u.test(input.executableSha256) || !/^codex-cli [0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/u.test(input.cliVersion) ||
      !Number.isSafeInteger(input.maxInvocations) || input.maxInvocations < 1 || input.processing !== "owner-public-repository")
    throw new Error("invalid owner Codex project descriptor");
  new CodexAccountClient(input); // Validate the explicit transport limits without spawning.
  return Object.freeze({ ...input });
}
export function codexProjectIdentity(input: CodexProjectDescriptor): string {
  const d = captureCodexProjectDescriptor(input);
  return createHash("sha256").update(JSON.stringify({ profile: CODEX_GENERATION_PROFILE, descriptor: keysForIdentity(d) })).digest("hex");
}
function keysForIdentity(d: CodexProjectDescriptor) { return Object.fromEntries(Object.entries(d).sort(([a], [b]) => a.localeCompare(b))); }

const GENERATION_ACTOR = "codex.project-generation";
function invocationState(events: readonly StagedEvent[]) {
  const rows = events.filter(e => e.type === "identity.action" && e.actor === GENERATION_ACTOR);
  const claims = rows.filter(e => e.payload["event"] === "claimed");
  const closed = new Set(rows.filter(e => e.payload["event"] === "completed" || e.payload["event"] === "not-started").map(e => e.payload["id"]));
  const uncertain = new Set(rows.filter(e => e.payload["event"] === "uncertain").map(e => e.payload["id"]));
  const unresolved = claims.filter(e => !closed.has(e.payload["id"]));
  return { rows, claims, unresolved, uncertain };
}
function claimIds(claims: readonly StagedEvent[]): string[] { return claims.map(e => String(e.payload["id"])).sort(); }

/** Local owner administration uses the same durable lock domain as dispatch. No model call. */
export async function inspectCodexInvocations(spine: Spine) {
  return spine.withCoordinationLock(GENERATION_ACTOR, async () => spine.withStableEventView(events => {
    spine.confirmEventDurability();
    const state = invocationState(events);
    return {
      claimed: state.claims.length,
      unresolved: state.unresolved.map(e => ({ id: String(e.payload["id"]), binding: String(e.payload["binding"]),
        state: state.uncertain.has(e.payload["id"]) ? "uncertain" : "pending" })),
      followupAuthorizations: state.rows.filter(e => e.payload["event"] === "followup-authorized").map(e => e.payload),
    };
  }));
}

export interface CodexFollowupAuthorization {
  readonly uncertainClaimIds: readonly string[];
  readonly expectedClaims: number;
  readonly additionalInvocations: number;
}
/** Call only after local owner authentication. This acknowledges uncertainty; it never closes/refunds it. */
export async function authorizeCodexFollowup(spine: Spine, input: CodexProjectDescriptor, review: CodexFollowupAuthorization): Promise<void> {
  const descriptor = captureCodexProjectDescriptor(input), binding = codexProjectIdentity(descriptor);
  const ids = [...review.uncertainClaimIds].sort(), expectedClaims = review.expectedClaims, additionalInvocations = review.additionalInvocations;
  if (!ids.length || new Set(ids).size !== ids.length || ids.some(id => !/^[0-9a-f-]{36}$/iu.test(id)) ||
      !Number.isSafeInteger(expectedClaims) || expectedClaims < 1 ||
      !Number.isSafeInteger(additionalInvocations) || additionalInvocations < 1 ||
      !Number.isSafeInteger(expectedClaims + additionalInvocations) ||
      expectedClaims + additionalInvocations > descriptor.maxInvocations)
    throw new Error("follow-up requires exact uncertain claim IDs and a finite allowance within the configured total");
  if (createHash("sha256").update(readFileSync(descriptor.executable)).digest("hex") !== descriptor.executableSha256)
    throw new Error("Codex executable identity changed before follow-up authorization");
  await spine.withCoordinationLock(GENERATION_ACTOR, async () => spine.withStableEventView(events => {
    spine.confirmEventDurability();
    const state = invocationState(events);
    if (state.claims.length !== expectedClaims || JSON.stringify(claimIds(state.unresolved)) !== JSON.stringify(ids))
      throw new Error("Codex claims changed; inspect the current ledger before authorizing follow-up work");
    if (state.unresolved.some(e => !state.uncertain.has(e.payload["id"])))
      throw new Error("a pending Codex invocation cannot be reviewed as a recorded uncertain failure");
    const payload = { event: "followup-authorized", binding, uncertainClaimIds: ids,
      expectedClaims, additionalInvocations };
    // Repeating an acknowledgement before any new dispatch does not append/reset a grant.
    const prior = [...state.rows].reverse().find(e => e.payload["event"] === payload.event && e.payload["binding"] === binding)?.payload;
    if (!prior || prior["expectedClaims"] !== expectedClaims || prior["additionalInvocations"] !== additionalInvocations ||
        JSON.stringify(prior["uncertainClaimIds"]) !== JSON.stringify(ids))
      spine.stage({ type: "identity.action", actor: GENERATION_ACTOR, payload });
  }));
}

/** Project-only subscription admission. It never manufactures an API token price. */
export class CodexProjectProvider implements ModelProvider {
  readonly generationMode = "codex-account" as const;
  readonly isLocal = false;
  readonly name: string;
  private readonly descriptor: CodexProjectDescriptor;
  private readonly client: CodexAccountClient;
  private readonly binding: string;
  constructor(input: CodexProjectDescriptor, private readonly spine: Spine) {
    this.descriptor = captureCodexProjectDescriptor(input); this.binding = codexProjectIdentity(this.descriptor);
    this.client = new CodexAccountClient(this.descriptor); this.name = `codex-account:${this.descriptor.model}`;
  }
  async generate(request: GenerateRequest): Promise<GenerateResult> {
    if (request.billingBasis !== "chatgpt-subscription" || request.maxTokens !== undefined ||
        (request.maxAttempts !== undefined && request.maxAttempts !== 1))
      throw new Error("Codex project generation requires the explicit account-managed request contract");
    if (request.signal?.aborted) request.signal.throwIfAborted();
    request.assertAuthority?.();
    if (createHash("sha256").update(readFileSync(this.descriptor.executable)).digest("hex") !== this.descriptor.executableSha256)
      throw new Error("Codex executable identity changed before dispatch");
    const id = randomUUID();
    await this.spine.withCoordinationLock("codex.project-generation", async () => this.spine.withStableEventView(events => {
      this.spine.confirmEventDurability();
      request.assertAuthority?.(); if (request.signal?.aborted) request.signal.throwIfAborted();
      const { rows, claims, unresolved, uncertain } = invocationState(events);
      if (unresolved.length) {
        const ids = JSON.stringify(claimIds(unresolved));
        const review = [...rows].reverse().find(e => e.payload["event"] === "followup-authorized" && e.payload["binding"] === this.binding);
        if (unresolved.some(e => !uncertain.has(e.payload["id"])) || !review || JSON.stringify(review.payload["uncertainClaimIds"]) !== ids)
          throw new Error("Codex prior work is uncertain; inspect codex-usage and obtain an exact owner follow-up authorization");
        const ceiling = Number(review.payload["expectedClaims"]) + Number(review.payload["additionalInvocations"]);
        if (!Number.isSafeInteger(ceiling) || claims.length >= ceiling) throw new Error("Codex owner follow-up invocation allowance exhausted");
      }
      if (claims.length >= this.descriptor.maxInvocations) throw new Error("Codex configured invocation allowance exhausted");
      this.spine.stage({ type: "identity.action", actor: "codex.project-generation", payload: { event: "claimed", id, binding: this.binding,
        billingBasis: "chatgpt-subscription", requestedModel: this.descriptor.model, processing: this.descriptor.processing,
        promptSha256: createHash("sha256").update(request.prompt).digest("hex"), allocatedPlanCostUsd: null } });
    }));
    let entered = false;
    try {
      request.assertAuthority?.(); if (request.signal?.aborted) request.signal.throwIfAborted();
      entered = true;
      const result = await this.client.generate({ billingBasis: "chatgpt-subscription", prompt: request.prompt, ...(request.signal ? { signal: request.signal } : {}) });
      this.spine.stage({ type: "identity.action", actor: "codex.project-generation", payload: { event: "completed", id, binding: this.binding,
        billingBasis: result.billingBasis, inputTokens: result.usage.inputTokens, cachedInputTokens: result.usage.cachedInputTokens,
        outputTokens: result.usage.outputTokens, cliInvocations: 1, modelWireAttempts: null, reportedModel: null, allocatedPlanCostUsd: null,
        ...(result.warnings?.length ? { warnings: result.warnings } : {}) } });
      return { text: result.text, model: this.name, tokensIn: result.usage.inputTokens, tokensOut: result.usage.outputTokens, usageComplete: true };
    } catch (error) {
      if (error instanceof CodexAccountError && error.dispatch === "not-started") entered = false;
      this.spine.stage({ type: "identity.action", actor: "codex.project-generation", payload: { event: entered ? "uncertain" : "not-started", id, binding: this.binding,
        ...(error instanceof CodexAccountError && error.diagnostics ? { diagnostics: error.diagnostics } : {}) } });
      throw error;
    }
  }
  async embed(_texts: readonly string[]): Promise<Embedding[]> { throw new Error("Codex project provider has no embedding capability"); }
}
