import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { types } from "node:util";
import type { Spine } from "../spine/spine.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import { CodexAccountClient, CodexAccountError, type CodexAccountClientOptions } from "./codex_account_client.js";

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
  return createHash("sha256").update(JSON.stringify(keysForIdentity(d))).digest("hex");
}
function keysForIdentity(d: CodexProjectDescriptor) { return Object.fromEntries(Object.entries(d).sort(([a], [b]) => a.localeCompare(b))); }

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
      const rows = events.filter(e => e.type === "identity.action" && e.actor === "codex.project-generation");
      const claims = rows.filter(e => e.payload["event"] === "claimed");
      const closed = new Set(rows.filter(e => e.payload["event"] === "completed" || e.payload["event"] === "not-started").map(e => e.payload["id"]));
      if (claims.some(e => !closed.has(e.payload["id"]))) throw new Error("Codex prior work is uncertain; reconcile before another invocation");
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
        outputTokens: result.usage.outputTokens, cliInvocations: 1, modelWireAttempts: null, reportedModel: null, allocatedPlanCostUsd: null } });
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
