/**
 * P5 — CHAT-CHANNEL ADAPTER (meet people where they already work).
 *
 * A pure, transport-agnostic core that turns an inbound chat event into the SAME gateway calls the CLI and web page
 * use, and formats the reply as chat text. A Slack/Discord/webhook transport is a THIN adapter that verifies the
 * platform signature, parses its payload into a `ChannelEvent`, calls this core, and posts the reply back — mirroring
 * the gateway's pure-handler/socket split (all routing/formatting proven here without a socket).
 *
 * Four hard properties (each disproof-backed):
 *   - COMPOSED: every event routes through `handleGatewayRequest`; no message/veto logic is re-implemented here.
 *   - SIGNATURE-AUTHED: an inbound event whose signature doesn't verify is REFUSED and drives no gateway call.
 *   - NEVER-AUTO-EXECUTE: a chat "approve" maps to the explicit `/veto/approve` route (which itself only marks an
 *     item runnable on explicit approval) — nothing auto-runs, and the adapter never approves on its own.
 *   - BOTH-TRACKS: the `verify` seam is a shared secret for a single DM channel (n=1) or per-workspace signing (org).
 */

import { handleGatewayRequest, type GatewayRequest } from "../gateway/http_gateway.js";
import type { KeepApp } from "../compose.js";

export type ChannelEvent =
  | { readonly kind: "message"; readonly text: string }
  | { readonly kind: "project"; readonly goal: string }
  | { readonly kind: "projects" }
  | { readonly kind: "approve"; readonly id: string }
  | { readonly kind: "veto"; readonly id: string }
  | { readonly kind: "digest" };

export interface InboundEnvelope {
  readonly event: ChannelEvent;
  /** The transport's signature over `raw` (Slack/Discord HMAC, or a shared secret for n=1). */
  readonly signature: string;
  /** The raw payload bytes the signature is computed over. */
  readonly raw: string;
}

export interface ChannelSecurity {
  /** The gateway token — the adapter is a trusted local client and holds it. */
  readonly token: string;
  /** Verify an inbound event's signature. False → the event is refused (no gateway call). */
  verify(raw: string, signature: string): boolean;
}

export interface ChannelReply {
  readonly text: string;
}

function gwReq(method: string, path: string, token: string, body?: unknown): GatewayRequest {
  return { method, path, query: {}, headers: { authorization: `Bearer ${token}` }, body: body !== undefined ? JSON.stringify(body) : "" };
}

export interface ChannelGatewayRoute { readonly method: string; readonly path: string; readonly body?: unknown; }

export function routeChannelEvent(event: ChannelEvent): ChannelGatewayRoute {
  switch (event.kind) {
    case "message": return { method: "POST", path: "/message", body: { message: event.text } };
    case "project": return { method: "POST", path: "/project", body: { goal: event.goal } };
    case "projects": return { method: "GET", path: "/projects" };
    case "approve": return { method: "POST", path: "/veto/approve", body: { id: event.id } };
    case "veto": return { method: "POST", path: "/veto/decline", body: { id: event.id } };
    case "digest": return { method: "GET", path: "/veto" };
  }
}

export function formatChannelResponse(event: ChannelEvent, status: number, body: string): ChannelReply {
  if (status !== 200) return { text: event.kind === "project" ? "I couldn't start that project right now." : event.kind === "projects" ? "I couldn't list projects right now." : "I couldn't handle that right now." };
  const value = JSON.parse(body) as Record<string, unknown>;
  if (event.kind === "message") { const result = value["result"] as { say: string; offer?: { text: string } }; return { text: result.say + (result.offer ? `\n\n💡 ${result.offer.text}\n(reply "accept" or "decline")` : "") }; }
  if (event.kind === "project") { const note = typeof value["note"] === "string" ? value["note"] : null; return { text: `Project status: ${String(value["status"])}${note ? ` — ${note}` : ""}` }; }
  if (event.kind === "projects") { const projects = value["projects"] as Array<{ name: string; lifecycle: string }>; return projects.length === 0 ? { text: "No projects yet." } : { text: `Your projects:\n${projects.map((p) => `• ${p.name} — ${p.lifecycle}`).join("\n")}` }; }
  if (event.kind === "approve") return { text: value["ok"] ? `✅ Approved ${event.id}.` : `Couldn't approve ${event.id} — it may be already decided.` };
  if (event.kind === "veto") return { text: value["ok"] ? `🚫 Vetoed ${event.id} — it won't run.` : `Couldn't veto ${event.id}.` };
  const digest = value["digest"] as { total: number; summary: string; entries: Array<{ id: string; line: string }> } | null;
  return digest === null || digest.total === 0 ? { text: "Nothing is awaiting your OK." } : { text: `${digest.summary}\n${digest.entries.map((en) => `• ${en.line}   (approve ${en.id}  /  veto ${en.id})`).join("\n")}` };
}

export async function handleChannelEvent(app: KeepApp, inbound: InboundEnvelope, sec: ChannelSecurity): Promise<ChannelReply> {
  // SIGNATURE-AUTHED: an unverified inbound event never drives a gateway call.
  if (!sec.verify(inbound.raw, inbound.signature)) {
    return { text: "⚠️ Ignored — this message couldn't be verified." };
  }

  const call = (method: string, path: string, body?: unknown) =>
    handleGatewayRequest(app, gwReq(method, path, sec.token, body), { token: sec.token });

  const route = routeChannelEvent(inbound.event);
  const response = await call(route.method, route.path, route.body);
  return formatChannelResponse(inbound.event, response.status, response.body);
}
