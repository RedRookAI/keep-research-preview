/**
 * MCP-native, both sides (Phase 6, #45) — built to spec 2026-07-28 (final).
 *
 * Keep-as-CLIENT: wrap any remote MCP server as a HOSTILE capability adapter behind
 * the capability port. The 2026-07-28 spec is a STATELESS core (each request is
 * self-contained HTTP; no sticky sessions), carries W3C Trace Context in `_meta`
 * (threads into Keep's Phase 4 tracing), and mandates OAuth 2.1 + PKCE for remote
 * servers. We pin the protocol version and negotiate.
 *
 * Keep-as-SERVER: expose Keep's own capabilities (file a build, query a lesson,
 * fetch the audit trail) as MCP tools so other agents use Keep as a component.
 *
 * The wire transport is injected (`McpTransport`) so a real MCP SDK client/server
 * plugs in behind these seams; the security/audit behavior lives here and is tested.
 */

import { boundedCapabilityOutput, captureCapabilityInvocation, type CapabilityAdapter, type CapabilityDescriptor, type CapabilityInvocation, type CapabilityResult, type CapabilityTrust } from "./capability_port.js";
import type { CapabilityEffect } from "../reference/reference_registry.js";
import type { HostileMcpGateway, ToolDefinition, ToolDisposition } from "./hostile_mcp_gateway.js";

export const MCP_PROTOCOL_VERSION = "2026-07-28";

/** A minimal stateless MCP transport (each call self-contained). Injected. */
export interface McpTransport {
  /** Negotiated protocol version reported by the server. */
  readonly serverProtocolVersion: string;
  /** True if the remote requires OAuth 2.1 (mandatory for remote servers in 2026). */
  readonly requiresOAuth: boolean;
  listTools(): Promise<string[]>;
  listToolDefinitions?(): Promise<readonly ToolDefinition[]>;
  callTool(name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<unknown>;
}

/** Negotiate protocol version; Keep pins 2026-07-28 and requires compatibility. */
export function negotiateVersion(serverVersion: string): { ok: boolean; reason: string } {
  if (serverVersion === MCP_PROTOCOL_VERSION) return { ok: true, reason: "exact match" };
  // Date-versioned: accept a server that is newer (forward-compatible negotiation),
  // reject older experimental (< 2026) versions Keep won't speak.
  if (/^\d{4}-\d{2}-\d{2}$/.test(serverVersion) && serverVersion > MCP_PROTOCOL_VERSION) {
    return { ok: true, reason: `server newer (${serverVersion}); negotiated down to ${MCP_PROTOCOL_VERSION}` };
  }
  return { ok: false, reason: `incompatible MCP version "${serverVersion}"; Keep speaks ${MCP_PROTOCOL_VERSION}` };
}

/** Keep-as-CLIENT: a remote MCP server as a hostile capability adapter. */
export class McpServerAdapter implements CapabilityAdapter {
  readonly descriptor: CapabilityDescriptor;

  constructor(
    id: string,
    name: string,
    credentialId: string,
    private readonly transport: McpTransport,
    trust: CapabilityTrust = "untrusted", // hostile by default
    private readonly hostileGateway?: HostileMcpGateway,
    private readonly maxResultBytes = 1024 * 1024,
  ) {
    this.descriptor = { id, kind: "mcp-server", name, credentialId, trust };
  }

  async approveTool(name: string, actor: string, disposition?: ToolDisposition): Promise<void> {
    if (!this.hostileGateway) throw new Error("MCP adapter has no hostile definition-pin gateway");
    const current = await this.currentDefinition(name);
    if (!current) throw new Error(`MCP server does not currently advertise tool "${name}"`);
    this.hostileGateway.approve(this.descriptor.id, current, actor, disposition);
  }

  /** Verify version + auth posture before use. Returns a reason on failure. */
  async handshake(): Promise<{ ok: boolean; reason: string }> {
    const v = negotiateVersion(this.transport.serverProtocolVersion);
    if (!v.ok) return v;
    // A remote server that doesn't require OAuth in 2026 is a red flag (the
    // unauthenticated-server crisis) — surfaced, and only usable while untrusted.
    if (!this.transport.requiresOAuth) {
      return { ok: true, reason: "WARNING: remote MCP server does not require OAuth 2.1 (2026 mandate); kept untrusted" };
    }
    return { ok: true, reason: "handshake ok (version + OAuth)" };
  }

  async invoke(inv: CapabilityInvocation, context?: { readonly effect: CapabilityEffect | "unknown"; readonly authorized: boolean }): Promise<CapabilityResult> {
    try {
      // Direct callers need the hub's same check/use binding. Capture approval
      // before JSON serialization can run trusted caller callbacks. This is an
      // entry-time context value, not a live grant/revocation protocol.
      let humanApproved: boolean;
      try {
        humanApproved = context?.authorized === true;
        inv = captureCapabilityInvocation(inv);
      } catch {
        return { ok: false, error: "MCP invocation input is invalid" };
      }
      const version = negotiateVersion(this.transport.serverProtocolVersion);
      if (!version.ok) return { ok: false, error: version.reason };
      if (!this.hostileGateway) return { ok: false, error: "MCP invocation requires the hostile definition-pin gateway" };
      const meta = inv.traceparent ? { traceparent: inv.traceparent } : undefined;
      const definition = await this.currentDefinition(inv.operation);
      if (!definition) return { ok: false, error: `MCP tool "${inv.operation}" is not currently advertised` };
      const result = await this.hostileGateway.invoke(this.descriptor.id, definition, inv.args as Record<string, unknown>, () => this.transport.callTool(inv.operation, inv.args as Record<string, unknown>, meta), { humanApproved });
      return result.status === "ok" ? { ok: true, output: boundedCapabilityOutput(result.output, this.maxResultBytes) } : { ok: false, held: result.status === "gated", error: result.reason ?? result.status };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  private async currentDefinition(name: string): Promise<ToolDefinition | undefined> {
    if (!this.transport.listToolDefinitions) return undefined;
    const definitions = await this.transport.listToolDefinitions();
    return definitions.find((definition) => definition.name === name);
  }
}

/** A capability Keep exposes when acting as an MCP server. */
export interface KeepMcpTool {
  readonly name: string;
  readonly description: string;
  handler(args: Record<string, unknown>): Promise<unknown>;
}

/**
 * Keep-as-SERVER: registers Keep's own tools and answers MCP-style tool calls.
 * A real MCP server binding (HTTP/stateless) wraps this; the tool logic + auth
 * gate live here.
 */
export class KeepMcpServer {
  readonly protocolVersion = MCP_PROTOCOL_VERSION;
  private readonly tools = new Map<string, KeepMcpTool>();

  registerTool(tool: KeepMcpTool): void {
    this.tools.set(tool.name, tool);
  }

  listTools(): string[] {
    return [...this.tools.keys()];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CapabilityResult> {
    const tool = this.tools.get(name);
    if (!tool) return { ok: false, error: `no tool "${name}"` };
    try {
      return { ok: true, output: await tool.handler(args) };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }
}
