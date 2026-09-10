/**
 * P6 — MCP SERVER SURFACE (let other agents and IDEs call Keep as a tool).
 *
 * Keep already has `KeepMcpServer` (a generic register/list/call registry) but nothing registers its actual
 * capabilities on it. This exposes Keep's GATEWAY capabilities as MCP tools by registering gateway-backed handlers
 * onto that existing registry — compose, not a new server. Each tool routes through `handleGatewayRequest`, so the
 * MCP surface, the CLI, the web page, and the chat channel all drive the SAME engine.
 *
 * A real stdio/HTTP MCP transport must authenticate its caller and translate this internal result
 * to the negotiated wire protocol. These handlers do not establish transport/OAuth qualification.
 *
 * Four hard properties (each disproof-backed):
 *   - COMPOSED: every tool routes through `handleGatewayRequest`; no engine behavior is re-implemented.
 *   - TOKEN-AUTHED: a tool call carries the token; a mismatch is refused before any gateway call.
 *   - NEVER-AUTO-EXECUTE: `keep_approve` maps to the explicit `/veto/approve` (which only marks an item runnable on
 *     explicit approval); nothing auto-runs.
 *   - SCHEMA-HONEST: `list_tools` advertises EXACTLY the tools that are registered and dispatch — no phantom tools.
 */

import { handleGatewayRequest, type GatewayRequest, type GatewaySecurity } from "../gateway/http_gateway.js";
import type { KeepApp } from "../compose.js";
import { KeepMcpServer } from "../ecosystem/mcp.js";

export interface McpToolSchema {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: { readonly type: "object"; readonly properties: Record<string, { type: string; description?: string }>; readonly required?: readonly string[] };
}

export interface McpToolCall {
  readonly name: string;
  readonly args: Record<string, unknown>;
  /** The caller's token — checked against the server's before any dispatch. */
  readonly token: string;
  /** Keep session credential from the transport, never a tool argument or claimed principal. */
  readonly session?: string;
}

export interface McpToolResult {
  readonly ok: boolean;
  readonly content?: unknown;
  readonly error?: string;
  /** Tool execution failure; a wire adapter must preserve this distinction. */
  readonly isError?: boolean;
}

export type McpSecurity = GatewaySecurity;

function gwReq(method: string, path: string, token: string, session: string | undefined, body?: unknown): GatewayRequest {
  return { method, path, query: {}, headers: { authorization: `Bearer ${token}`, ...(session === undefined ? {} : { "x-keep-session": session }) }, body: body !== undefined ? JSON.stringify(body) : "" };
}

/** The advertised tool schemas — the SINGLE SOURCE registered below, so `list_tools` can never drift from dispatch. */
const TOOL_DEFS: ReadonlyArray<McpToolSchema & { route: (a: Record<string, unknown>) => { method: string; path: string; body?: unknown } }> = [
  { name: "keep_message", description: "Send Keep a message; returns its reply and any suggestion.", inputSchema: { type: "object", properties: { message: { type: "string" } }, required: ["message"] }, route: (a) => ({ method: "POST", path: "/message", body: { message: String(a["message"] ?? "") } }) },
  { name: "keep_project", description: "Start an autonomous project on a goal; returns its status.", inputSchema: { type: "object", properties: { goal: { type: "string" } }, required: ["goal"] }, route: (a) => ({ method: "POST", path: "/project", body: { goal: String(a["goal"] ?? "") } }) },
  { name: "keep_projects", description: "List Keep's projects.", inputSchema: { type: "object", properties: {} }, route: () => ({ method: "GET", path: "/projects" }) },
  { name: "keep_veto_digest", description: "List actions awaiting the human's veto or approval.", inputSchema: { type: "object", properties: {} }, route: () => ({ method: "GET", path: "/veto" }) },
  { name: "keep_approve", description: "Explicitly approve a parked action so it may run.", inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }, route: (a) => ({ method: "POST", path: "/veto/approve", body: { id: String(a["id"] ?? "") } }) },
  { name: "keep_veto", description: "Veto a parked action so it will not run.", inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }, route: (a) => ({ method: "POST", path: "/veto/decline", body: { id: String(a["id"] ?? "") } }) },
];

/** COMPOSE: register the gateway-backed tools onto the EXISTING KeepMcpServer registry. */
export function buildGatewayMcpServer(app: KeepApp, security: string | McpSecurity, session?: string): KeepMcpServer {
  // Capture deployment configuration, not a resolved principal. Session expiry,
  // revocation and injected principal resolution still run at the gateway per call.
  const configured = typeof security === "string" ? { token: security } : { ...security };
  const appIdentity = app.identity;
  const conflictingIdentity = appIdentity !== undefined && (
    (configured.identity !== undefined && configured.identity !== appIdentity) || configured.principalFor !== undefined
  );
  const sec: GatewaySecurity = { ...configured, ...(appIdentity === undefined ? {} : { identity: appIdentity }) };
  const server = new KeepMcpServer();
  for (const def of TOOL_DEFS) {
    server.registerTool({
      name: def.name,
      description: def.description,
      handler: async (args: Record<string, unknown>) => {
        if (typeof sec.token !== "string" || sec.token.trim().length === 0) throw new Error("unauthorized");
        if (conflictingIdentity || app.identity !== appIdentity) throw new Error("gateway identity configuration changed or conflicts");
        let r;
        try {
          const { method, path, body } = def.route(args);
          r = await handleGatewayRequest(app, gwReq(method, path, sec.token, session, body), sec);
        } catch {
          // An exception is not proof that nothing happened. Do not retry here or
          // leak arbitrary exception/provider text, credentials or stack traces.
          throw new Error("gateway request failed; outcome not established");
        }
        if (r.status < 200 || r.status >= 300) throw new Error(`gateway request failed (HTTP ${r.status})`);
        let payload: unknown;
        try { payload = JSON.parse(r.body); }
        catch { throw new Error("gateway returned an invalid response"); }
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) throw new Error("gateway returned an invalid response");
        if ((payload as Record<string, unknown>)["ok"] === false) throw new Error(`gateway operation refused (HTTP ${r.status})`);
        return payload;
      },
    });
  }
  return server;
}

/** SCHEMA-HONEST: exactly the tools that are registered (and therefore dispatch). */
export function listGatewayMcpTools(): readonly McpToolSchema[] {
  return TOOL_DEFS.map((d) => ({ name: d.name, description: d.description, inputSchema: d.inputSchema }));
}

/** The pure, token-authed MCP entrypoint. A transport parses JSON-RPC into this and formats the result back. */
export async function handleMcpToolCall(app: KeepApp, call: McpToolCall, sec: McpSecurity): Promise<McpToolResult> {
  // TOKEN-AUTHED: a tool call with the wrong/absent token never drives a gateway call.
  if (typeof sec.token !== "string" || sec.token.trim().length === 0 || call.token !== sec.token) return { ok: false, isError: true, error: "unauthorized" };
  // Each entrypoint call gets its own session-bound handlers. No cross-caller cache.
  const server = buildGatewayMcpServer(app, sec, call.session);
  const r = await server.callTool(call.name, call.args);
  return r.ok ? { ok: true, content: r.output } : { ok: false, isError: true, error: r.error ?? "tool failed" };
}
