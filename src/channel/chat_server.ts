#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { WebhookVerifier } from "../ingress/webhook_verifier.js";
import { formatChannelResponse, routeChannelEvent, type ChannelEvent } from "./chat_channel.js";

const MAX_BODY = 1024 * 1024;
const WINDOW_MS = 5 * 60 * 1000;

class DurableReplayWindow {
  readonly #file: string;
  readonly #seen = new Map<string, number>();
  constructor(file: string, now = Date.now()) {
    this.#file = file; mkdirSync(dirname(file), { recursive: true });
    try { for (const line of readFileSync(file, "utf8").split("\n")) { if (!line) continue; const row = JSON.parse(line) as { id: string; at: number }; if (typeof row.id === "string" && Number.isFinite(row.at) && now - row.at <= WINDOW_MS) this.#seen.set(row.id, row.at); } }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    this.#save(now);
  }
  accept(id: string, now = Date.now()): boolean { this.#prune(now); if (this.#seen.has(id)) return false; this.#seen.set(id, now); this.#save(now); return true; }
  #prune(now: number): void { for (const [id, at] of this.#seen) if (now - at > WINDOW_MS) this.#seen.delete(id); }
  #save(now: number): void { this.#prune(now); const temp = `${this.#file}.${process.pid}.tmp`; writeFileSync(temp, [...this.#seen].map(([id, at]) => JSON.stringify({ id, at })).join("\n") + (this.#seen.size ? "\n" : ""), { mode: 0o600 }); renameSync(temp, this.#file); }
}

function channelEvent(value: unknown): ChannelEvent | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (row["kind"] === "message" && typeof row["text"] === "string") return { kind: "message", text: row["text"] };
  if (row["kind"] === "project" && typeof row["goal"] === "string") return { kind: "project", goal: row["goal"] };
  if (row["kind"] === "projects" || row["kind"] === "digest") return { kind: row["kind"] };
  if ((row["kind"] === "approve" || row["kind"] === "veto") && typeof row["id"] === "string") return { kind: row["kind"], id: row["id"] };
  return null;
}

function config(): { origin: URL; gatewayToken: string; secret: string; replayFile: string; host: string; port: number } {
  const origin = new URL(process.env["KEEP_GATEWAY_ORIGIN"] ?? ""); const gatewayToken = process.env["KEEP_GATEWAY_TOKEN"] ?? ""; const secret = process.env["KEEP_CHAT_SECRET"] ?? ""; const replayFile = process.env["KEEP_CHAT_REPLAY_FILE"] ?? ""; const host = process.env["KEEP_CHAT_HOST"] ?? "127.0.0.1"; const port = Number(process.env["KEEP_CHAT_PORT"] ?? "7790");
  const loopbackOrigin = origin.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname) && origin.pathname === "/" && !origin.username && !origin.password && !origin.search && !origin.hash;
  if (!loopbackOrigin || !gatewayToken || !secret || !replayFile) throw new Error("a loopback KEEP_GATEWAY_ORIGIN plus KEEP_GATEWAY_TOKEN, KEEP_CHAT_SECRET, and KEEP_CHAT_REPLAY_FILE are required");
  if (!["127.0.0.1", "localhost", "::1"].includes(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error("development chat adapter must use a loopback host and valid port");
  return { origin, gatewayToken, secret, replayFile, host, port };
}

function respond(res: ServerResponse, status: number, value: unknown): void { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(value)); }
async function body(req: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of req) { const bytes = Buffer.from(chunk); size += bytes.length; if (size > MAX_BODY) throw new Error("body too large"); chunks.push(bytes); } return Buffer.concat(chunks).toString("utf8"); }

export async function main(): Promise<void> {
  const cfg = config(); const replay = new DurableReplayWindow(cfg.replayFile); const verifier = new WebhookVerifier();
  const server = createServer(async (req, res) => {
    try {
      if (req.method !== "POST" || req.url !== "/event") { respond(res, 404, { error: "not found" }); return; }
      const raw = await body(req); const headers: Record<string, string> = {}; for (const [key, value] of Object.entries(req.headers)) if (typeof value === "string") headers[key] = value;
      const verified = verifier.verify({ source: "generic", rawBody: raw, headers, secret: cfg.secret });
      if (!verified.ok) { respond(res, 401, { error: "unauthorized" }); return; }
      if (!replay.accept(verified.deliveryId)) { respond(res, 409, { error: "replayed event" }); return; }
      let parsed: unknown; try { parsed = JSON.parse(raw); } catch { respond(res, 400, { error: "invalid json" }); return; }
      const event = channelEvent(parsed); if (!event) { respond(res, 400, { error: "invalid channel event" }); return; }
      const route = routeChannelEvent(event); const gateway = await fetch(new URL(route.path, cfg.origin), { method: route.method, headers: { authorization: `Bearer ${cfg.gatewayToken}`, "content-type": "application/json" }, ...(route.body === undefined ? {} : { body: JSON.stringify(route.body) }) });
      respond(res, gateway.ok ? 200 : 502, formatChannelResponse(event, gateway.status, await gateway.text()));
    } catch (error) { respond(res, (error as Error).message === "body too large" ? 413 : 500, { error: "chat adapter failure" }); }
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(cfg.port, cfg.host, resolve); });
  const address = server.address(); const port = typeof address === "object" && address ? address.port : cfg.port;
  process.stdout.write(`${JSON.stringify({ ready: true, host: cfg.host, port })}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((error) => { process.stderr.write(`${(error as Error).message}\n`); process.exit(1); });
