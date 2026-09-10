/**
 * Stdio MCP transport (infra, Phase 6 #45) — a REAL working transport.
 *
 * Implements the injected `McpTransport` over a child process speaking
 * line-delimited JSON-RPC 2.0 (the MCP stdio transport). It spawns the server
 * (argv-only), negotiates the protocol version via `initialize`, and implements
 * listTools/callTool by correlating JSON-RPC responses by id. Testable here against
 * a subprocess MCP server; the remote HTTP+OAuth transport stays a logged seam.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { MCP_PROTOCOL_VERSION, type McpTransport } from "../ecosystem/mcp.js";
import type { ToolDefinition } from "../ecosystem/hostile_mcp_gateway.js";

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

export class StdioMcpTransport implements McpTransport {
  private child?: ChildProcess;
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private buffer: Buffer = Buffer.alloc(0);
  private startupError: Error | undefined;
  private closedError: Error | undefined;
  private _serverProtocolVersion = MCP_PROTOCOL_VERSION;
  private _requiresOAuth = false; // stdio (local) has no OAuth; remote HTTP would

  constructor(
    private readonly command: string,
    private readonly args: readonly string[] = [],
    private readonly options: { readonly token?: string; readonly env?: NodeJS.ProcessEnv; readonly timeoutMs?: number; readonly maxResponseBytes?: number } = {},
  ) {
    if (!Number.isSafeInteger(options.timeoutMs ?? 10_000) || (options.timeoutMs ?? 10_000) < 1 || (options.timeoutMs ?? 10_000) > 120_000) throw new Error("MCP timeoutMs is outside the supported bound");
    if (!Number.isSafeInteger(options.maxResponseBytes ?? 1024 * 1024) || (options.maxResponseBytes ?? 1024 * 1024) < 1 || (options.maxResponseBytes ?? 1024 * 1024) > 16 * 1024 * 1024) throw new Error("MCP maxResponseBytes is outside the supported bound");
  }

  get serverProtocolVersion(): string {
    return this._serverProtocolVersion;
  }
  get requiresOAuth(): boolean {
    return this._requiresOAuth;
  }

  /** Start the server process and perform the MCP initialize handshake. */
  async start(): Promise<void> {
    this.child = spawn(this.command, [...this.args], { stdio: ["pipe", "pipe", "inherit"], shell: false, ...(this.options.env ? { env: this.options.env } : {}) });
    this.child.stdout?.on("data", (b: Buffer) => this.onData(b));
    // A spawn failure (missing binary, EAGAIN under load) must surface as a clean rejection, never an uncaught error.
    this.child.on("error", (err: Error) => {
      this.startupError = err;
      for (const { reject } of this.pending.values()) reject(new Error(`MCP server failed to start: ${err.message}`));
      this.pending.clear();
    });
    this.child.on("close", (code: number | null) => {
      const why = this.startupError ? this.startupError.message : `MCP server closed${code !== null ? ` (exit ${code})` : ""}`;
      this.closedError = new Error(why);
      for (const { reject } of this.pending.values()) reject(this.closedError);
      this.pending.clear();
    });
    const init = (await this.request("initialize", { protocolVersion: MCP_PROTOCOL_VERSION })) as { protocolVersion?: string };
    if (init?.protocolVersion) this._serverProtocolVersion = init.protocolVersion;
  }

  async stop(): Promise<void> {
    this.child?.kill("SIGKILL");
  }

  async listTools(): Promise<string[]> {
    return (await this.listToolDefinitions()).map((tool) => tool.name);
  }

  async listToolDefinitions(): Promise<readonly ToolDefinition[]> {
    const res = (await this.request("tools/list", this.options.token ? { token: this.options.token } : {})) as { tools?: unknown };
    if (!Array.isArray(res.tools) || res.tools.length > 1_000) throw new Error("MCP tool list is malformed or exceeds the bound");
    return res.tools.map((value) => {
      if (value === null || typeof value !== "object") throw new Error("MCP tool definition is malformed");
      const row = value as Record<string, unknown>;
      if (typeof row["name"] !== "string" || row["name"].length < 1 || row["name"].length > 256 || typeof row["description"] !== "string" || row["description"].length > 16_384) throw new Error("MCP tool definition is malformed");
      return { name: row["name"], description: row["description"], ...(row["inputSchema"] === undefined ? {} : { inputSchema: row["inputSchema"] }) };
    });
  }

  async callTool(name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<unknown> {
    const params: Record<string, unknown> = { name, arguments: args };
    if (this.options.token) params["token"] = this.options.token;
    if (meta) params["_meta"] = meta; // W3C Trace Context threads here
    const res = (await this.request("tools/call", params)) as { content?: unknown };
    return res.content ?? res;
  }

  private onData(buf: Buffer): void {
    // Bound raw pending bytes (including incomplete characters and delimiters)
    // before allocating. This remains a pending-batch bound, not per-line quota.
    if (this.buffer.length + buf.length > (this.options.maxResponseBytes ?? 1024 * 1024)) {
      const error = new Error("MCP response exceeded configured byte bound");
      this.buffer = Buffer.alloc(0); for (const { reject } of this.pending.values()) reject(error); this.pending.clear(); this.child?.kill("SIGKILL"); return;
    }
    this.buffer = Buffer.concat([this.buffer, buf]);
    let nl: number, consumed = 0;
    while ((nl = this.buffer.indexOf(0x0a, consumed)) >= 0) {
      // ASCII LF cannot be a UTF8 continuation byte. Only decode complete lines.
      const line = this.buffer.toString("utf8", consumed, nl).trim();
      consumed = nl + 1;
      if (!line) continue;
      let msg: JsonRpcResponse;
      try {
        msg = JSON.parse(line) as JsonRpcResponse;
      } catch {
        continue; // ignore non-JSON lines (server logging)
      }
      if (msg === null || typeof msg !== "object" || Array.isArray(msg) || typeof msg.id !== "number") continue;
      const waiter = this.pending.get(msg.id);
      if (!waiter) continue;
      this.pending.delete(msg.id);
      if (msg.error) waiter.reject(new Error(`MCP error ${msg.error.code}: ${msg.error.message}`));
      else waiter.resolve(msg.result);
    }
    // Compact once per chunk, so a tiny residual does not retain a large batch.
    if (consumed > 0) this.buffer = Buffer.from(this.buffer.subarray(consumed));
  }

  private request(method: string, params: Record<string, unknown>): Promise<unknown> {
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise<unknown>((resolve, reject) => {
      if (this.closedError) { reject(this.closedError); return; }
      if (!this.child?.stdin) {
        reject(new Error("MCP transport not started"));
        return;
      }
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`MCP request "${method}" timed out`));
        }
      }, this.options.timeoutMs ?? 10_000);
      timer.unref();
      const settle = <T>(fn: (value: T) => void) => (value: T) => { clearTimeout(timer); fn(value); };
      this.pending.set(id, { resolve: settle(resolve), reject: settle(reject), timer });
      this.child.stdin.write(payload);
    });
  }
}
