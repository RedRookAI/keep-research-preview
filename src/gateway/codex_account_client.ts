/** Generation-only Codex transport. Admission and subscription accounting belong to its caller.
 * This is deliberately not an API-priced ModelProvider: unsupported token/wire limits refuse.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { types } from "node:util";

export interface CodexAccountUsage {
  readonly inputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
}
export interface CodexAccountResult {
  readonly text: string;
  readonly requestedModel: string;
  readonly reportedModel: null;
  readonly usage: CodexAccountUsage;
  readonly billingBasis: "chatgpt-subscription";
  readonly allocatedPlanCostUsd: null;
  readonly modelWireAttempts: null;
  readonly cliInvocations: 1;
}
export interface CodexAccountRequest {
  readonly billingBasis: "chatgpt-subscription";
  readonly prompt: string;
  readonly signal?: AbortSignal;
  readonly hardOutputTokenLimit?: number;
  readonly hardModelWireAttemptLimit?: number;
  readonly hardModelInputByteLimit?: number;
}
export interface CodexAccountClientOptions {
  /** A trusted installed executable selected by the composition root, not untrusted repository data. */
  readonly executable: string;
  readonly model: string;
  /** Explicit caller limits. There are no invented default quotas or dollar rates. */
  /** Bytes submitted on stdin, including our prefix; not Codex-added or complete model wire input. */
  readonly maxSubmittedPromptBytes: number;
  /** Combined captured process stdout/stderr bytes, not a model output-token guarantee. */
  readonly maxCapturedOutputBytes: number;
  readonly maxElapsedMs: number;
}
export class CodexAccountError extends Error {
  constructor(message: string, readonly dispatch: "not-started" | "entered") {
    super(message); this.name = "CodexAccountError";
  }
}
const counter = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export class CodexAccountClient {
  readonly isLocal = false;
  private readonly options: Readonly<CodexAccountClientOptions>;
  constructor(options: CodexAccountClientOptions) {
    if (!isAbsolute(options.executable) || options.executable.includes("\0") ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(options.model) ||
        ![options.maxSubmittedPromptBytes, options.maxCapturedOutputBytes, options.maxElapsedMs].every(n => Number.isSafeInteger(n) && n > 0) || options.maxElapsedMs > 2_147_483_647)
      throw new CodexAccountError("Invalid Codex executable, model or caller limits", "not-started");
    this.options = Object.freeze({ ...options });
  }
  async generate(request: CodexAccountRequest): Promise<CodexAccountResult> {
    const keys = ["billingBasis", "prompt", "signal", "hardOutputTokenLimit", "hardModelWireAttemptLimit", "hardModelInputByteLimit"];
    if (!request || types.isProxy(request) || Object.getPrototypeOf(request) !== Object.prototype ||
        Reflect.ownKeys(request).some(key => typeof key !== "string" || !keys.includes(key)) ||
        Object.values(Object.getOwnPropertyDescriptors(request)).some(d => !("value" in d) || !d.enumerable))
      throw new CodexAccountError("Codex request requires explicit subscription fields; API-priced request limits cannot be ignored", "not-started");
    if (request.billingBasis !== "chatgpt-subscription")
      throw new CodexAccountError("Codex requires an explicit subscription usage request", "not-started");
    if (request.signal !== undefined && !(request.signal instanceof AbortSignal))
      throw new CodexAccountError("Codex cancellation requires an AbortSignal", "not-started");
    if (request.hardOutputTokenLimit !== undefined || request.hardModelWireAttemptLimit !== undefined || request.hardModelInputByteLimit !== undefined)
      throw new CodexAccountError("Codex does not establish the requested hard model-input/token/wire-attempt guarantee", "not-started");
    if (typeof request.prompt !== "string" || !request.prompt.trim() || request.signal?.aborted)
      throw new CodexAccountError("Codex input exceeds its admitted work or was cancelled", "not-started");
    const prompt = "Return only the requested text in the schema's text field. Generate text only; do not run tools, inspect files, or edit a workspace.\n\n" + request.prompt;
    if (Buffer.byteLength(prompt) > this.options.maxSubmittedPromptBytes)
      throw new CodexAccountError("Codex submitted prompt exceeds its admitted bytes", "not-started");
    const dir = mkdtempSync(join(tmpdir(), "keep-codex-generation-"));
    const schema = join(dir, "output-schema.json");
    writeFileSync(schema, JSON.stringify({ type: "object", additionalProperties: false, required: ["text"],
      properties: { text: { type: "string" } } }), { mode: 0o600 });
    const environment: NodeJS.ProcessEnv = {};
    // Keep existing login location unchanged; never forward API keys or copy auth material.
    for (const key of ["PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TMPDIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
      "https_proxy", "http_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"])
      if (process.env[key] !== undefined) environment[key] = process.env[key];
    const args = ["exec", "--ignore-user-config", "--strict-config", "--ephemeral", "--json", "--skip-git-repo-check", "--sandbox", "read-only",
      "--disable", "shell_tool", "--disable", "unified_exec", "--disable", "shell_snapshot",
      "--disable", "skill_mcp_dependency_install", "-c", 'web_search="disabled"',
      "-c", 'forced_login_method="chatgpt"', "-c", 'model_provider="openai"',
      "-c", "model_providers.openai.request_max_retries=0", "-c", "model_providers.openai.stream_max_retries=0",
      "--model", this.options.model, "--output-schema", schema, "-"];
    let locallyClosed = false;
    try {
      return await new Promise<CodexAccountResult>((resolve, reject) => {
        const child = spawn(this.options.executable, args, { cwd: dir, env: environment, detached: true, stdio: ["pipe", "pipe", "pipe"] });
        let failure: string | undefined, pending = "", bytes = 0, text: string | undefined, rawMessage: string | undefined, usage: CodexAccountUsage | undefined;
        let thread = false, started = false, completed = false;
        const decoder = new StringDecoder("utf8");
        const stop = (reason: string) => {
          failure ??= reason;
          if (child.pid) try { process.kill(-child.pid, "SIGKILL"); } catch { /* own group already exited */ }
        };
        const interrupt = (reason: string) => {
          stop(reason);
          reject(new CodexAccountError(reason, "entered"));
          child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy(); child.unref();
        };
        const abort = () => interrupt("Codex invocation cancelled; remote work may have occurred");
        request.signal?.addEventListener("abort", abort, { once: true });
        if (request.signal?.aborted) abort();
        const timer = setTimeout(() => interrupt("Codex deadline elapsed; remote work may have occurred"), this.options.maxElapsedMs);
        const line = (value: string) => {
          if (!value.trim() || failure) return;
          try {
            const event = JSON.parse(value) as Record<string, unknown>;
            if (event.type === "thread.started" && !thread && !started) { thread = true; return; }
            if (event.type === "turn.started" && thread && !started) { started = true; return; }
            if (!started || completed) throw new Error();
            if (["item.started", "item.updated", "item.completed"].includes(String(event.type))) {
              const item = event.item as { type?: unknown; text?: unknown } | undefined;
              if (item?.type === "reasoning") return;
              if (item?.type !== "agent_message") throw new Error();
              if (event.type === "item.completed") {
                if (typeof item.text !== "string") throw new Error();
                rawMessage = item.text;
              }
              return;
            }
            if (event.type === "turn.completed") {
              const u = event.usage as Record<string, unknown> | undefined;
              if (rawMessage === undefined || !u || !counter(u.input_tokens) || !counter(u.cached_input_tokens) || !counter(u.output_tokens) || u.cached_input_tokens > u.input_tokens) throw new Error();
              const output = JSON.parse(rawMessage) as Record<string, unknown>;
              if (Object.keys(output).join(",") !== "text" || typeof output.text !== "string" || !output.text.trim() || Buffer.byteLength(output.text) > this.options.maxCapturedOutputBytes) throw new Error();
              text = output.text;
              usage = { inputTokens: u.input_tokens, cachedInputTokens: u.cached_input_tokens, outputTokens: u.output_tokens };
              completed = true; return;
            }
            throw new Error();
          } catch { stop("Codex returned invalid, incomplete or unsupported activity; invocation remains uncertain"); }
        };
        child.stdout.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > this.options.maxCapturedOutputBytes) { stop("Codex output exceeds its admitted bytes"); return; }
          pending += decoder.write(chunk);
          for (;;) { const end = pending.indexOf("\n"); if (end < 0) break; line(pending.slice(0, end)); pending = pending.slice(end + 1); }
        });
        child.stderr.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > this.options.maxCapturedOutputBytes) stop("Codex output exceeds its admitted bytes"); });
        child.stdin.on("error", () => stop("Codex input pipe closed; invocation remains uncertain"));
        child.once("error", () => stop("Codex process could not execute"));
        child.once("close", code => {
          locallyClosed = true;
          clearTimeout(timer); request.signal?.removeEventListener("abort", abort);
          // Only an owned local process closed. This does not attest remote cancellation or group emptiness.
          rmSync(dir, { recursive: true, force: true });
          pending += decoder.end(); if (pending) line(pending);
          if (failure || code !== 0 || !completed || text === undefined || !usage)
            reject(new CodexAccountError(failure ?? "Codex did not complete with verified output/usage", "entered"));
          else resolve({ text, usage, requestedModel: this.options.model, reportedModel: null, billingBasis: "chatgpt-subscription",
            allocatedPlanCostUsd: null, modelWireAttempts: null, cliInvocations: 1 });
        });
        child.stdin.end(prompt);
      });
    } finally { if (locallyClosed) rmSync(dir, { recursive: true, force: true }); }
  }
}
