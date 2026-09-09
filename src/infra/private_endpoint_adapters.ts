import { createHmac, timingSafeEqual } from "node:crypto";
import type { A2ATaskState, A2ATransport } from "../ecosystem/a2a.js";
import type { McpTransport } from "../ecosystem/mcp.js";
import type { ToolDefinition } from "../ecosystem/hostile_mcp_gateway.js";
import type { Notification, NotificationChannel } from "../notify/notification_router.js";

export interface PrivateEndpointConfig {
  readonly baseUrl: string;
  readonly token: string;
  readonly fetchImpl?: typeof fetch;
  readonly maxResponseBytes?: number;
  readonly timeoutMs?: number;
}

/** Origin-pinned JSON client. Redirects are refused so credentials cannot cross origins. */
export class PrivateJsonEndpoint {
  private readonly base: URL;
  private readonly fetchImpl: typeof fetch;
  private readonly maxBytes: number;
  private readonly timeoutMs: number;
  constructor(private readonly cfg: PrivateEndpointConfig) {
    this.base = new URL(cfg.baseUrl);
    if (!['http:', 'https:'].includes(this.base.protocol) || this.base.username || this.base.password) throw new Error("private endpoint must be an HTTP(S) URL without embedded credentials");
    this.fetchImpl = cfg.fetchImpl ?? fetch;
    this.maxBytes = cfg.maxResponseBytes ?? 1024 * 1024;
    this.timeoutMs = cfg.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1 || this.maxBytes > 16 * 1024 * 1024) throw new Error("maxResponseBytes is outside the supported bound");
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 120_000) throw new Error("timeoutMs is outside the supported bound");
  }
  async request(path: string, method = "GET", body?: unknown): Promise<unknown> {
    const target = new URL(path, this.base);
    if (target.origin !== this.base.origin) throw new Error("endpoint path escaped the configured origin");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`private endpoint timed out after ${this.timeoutMs}ms`)), this.timeoutMs);
    let response: Response;
    try { response = await this.fetchImpl(target, { method, redirect: "error", signal: controller.signal, headers: { authorization: `Bearer ${this.cfg.token}`, "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }); }
    finally { clearTimeout(timer); }
    if (!response.ok) throw new Error(`private endpoint returned HTTP ${response.status}`);
    const declared = Number(response.headers.get("content-length") ?? 0);
    if (declared > this.maxBytes) throw new Error("private endpoint response exceeded limit");
    const text = await response.text();
    if (Buffer.byteLength(text) > this.maxBytes) throw new Error("private endpoint response exceeded limit");
    return text === "" ? undefined : JSON.parse(text) as unknown;
  }
}

export class PrivateForgeAdapter {
  constructor(private readonly endpoint: PrivateJsonEndpoint) {}
  createPullRequest(repo: string, input: { title: string; head: string; base: string; body?: string }): Promise<unknown> {
    return this.endpoint.request(`/repos/${encodeURIComponent(repo)}/pulls`, "POST", input);
  }
  comment(repo: string, issue: string, body: string): Promise<unknown> {
    return this.endpoint.request(`/repos/${encodeURIComponent(repo)}/issues/${encodeURIComponent(issue)}/comments`, "POST", { body });
  }
}

export class PrivateChatNotificationChannel implements NotificationChannel {
  constructor(private readonly endpoint: PrivateJsonEndpoint, private readonly path = "/notifications") {}
  async send(notification: Notification): Promise<void> { await this.endpoint.request(this.path, "POST", notification); }
}

export class PrivateHttpMcpTransport implements McpTransport {
  readonly serverProtocolVersion = "2026-07-28";
  readonly requiresOAuth = false;
  constructor(private readonly endpoint: PrivateJsonEndpoint) {}
  async listTools(): Promise<string[]> { const r = await this.endpoint.request("/mcp/tools") as { tools?: Array<{ name?: unknown }> }; return (r.tools ?? []).map((x) => String(x.name ?? "")).filter(Boolean); }
  async listToolDefinitions(): Promise<readonly ToolDefinition[]> {
    const r = await this.endpoint.request("/mcp/tools") as { tools?: unknown };
    if (!Array.isArray(r.tools) || r.tools.length > 1_000) throw new Error("MCP tool list is malformed or exceeds the bound");
    return r.tools.map((value) => {
      if (value === null || typeof value !== "object") throw new Error("MCP tool definition is malformed");
      const row = value as Record<string, unknown>;
      if (typeof row["name"] !== "string" || row["name"].length < 1 || row["name"].length > 256 || typeof row["description"] !== "string" || row["description"].length > 16_384) throw new Error("MCP tool definition is malformed");
      return { name: row["name"], description: row["description"], ...(row["inputSchema"] === undefined ? {} : { inputSchema: row["inputSchema"] }) };
    });
  }
  async callTool(name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<unknown> { return this.endpoint.request("/mcp/call", "POST", { name, arguments: args, ...(meta ? { _meta: meta } : {}) }); }
}

export class PrivateHttpA2ATransport implements A2ATransport {
  constructor(private readonly endpoint: PrivateJsonEndpoint) {}
  async sendTask(skill: string, args: Record<string, unknown>): Promise<{ state: A2ATaskState; output?: unknown; error?: string }> {
    const r = await this.endpoint.request("/a2a/tasks", "POST", { skill, args }) as Record<string, unknown>;
    const allowed: readonly A2ATaskState[] = ["submitted", "working", "input-required", "completed", "failed", "canceled"];
    if (!allowed.includes(r["state"] as A2ATaskState)) return { state: "failed", error: "invalid A2A task state from untrusted peer" };
    return { state: r["state"] as A2ATaskState, ...(r["output"] === undefined ? {} : { output: r["output"] }), ...(typeof r["error"] === "string" ? { error: r["error"] } : {}) };
  }
}

/** Constant-time webhook verification over the exact bytes received. */
export function verifyWebhook(raw: string, supplied: string, secret: string): boolean {
  const expected = createHmac("sha256", secret).update(raw).digest("hex");
  const actual = supplied.replace(/^sha256=/, "");
  return actual.length === expected.length && timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

