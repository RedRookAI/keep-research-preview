#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import { ChatDeliveryStore, ChatDeliveryCapacityError, deliveryDigest } from "./chat_delivery_store.js";
import { WebhookVerifier } from "../ingress/webhook_verifier.js";
import { formatChannelResponse, routeChannelEvent, type ChannelEvent } from "./chat_channel.js";

const MAX_BODY = 1024 * 1024;
const WINDOW_MS = 5 * 60 * 1000;

const REPLAY_SCHEMA = "keep.chat-replay/v2";
const KEY_PREFIX = "keep-chat-envelope/v2:";
function digest(bytes: string | Buffer): string { return createHash("sha256").update(bytes).digest("hex"); }
function legacySnapshot(file: string): string {
  const before = lstatSync(file, { bigint: true });
  if (!before.isFile()) throw new Error("chat replay migration requires a regular legacy file");
  const bytes = readFileSync(file);
  const after = lstatSync(file, { bigint: true });
  const identity = (stat: typeof before) => [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].map(String);
  if (JSON.stringify(identity(before)) !== JSON.stringify(identity(after))) throw new Error("legacy chat replay state changed during observation");
  for (const line of bytes.toString("utf8").split("\n")) {
    if (!line.trim()) continue;
    const row = JSON.parse(line) as { id?: unknown; at?: unknown };
    if (!row || typeof row.id !== "string" || !row.id || typeof row.at !== "number" || !Number.isFinite(row.at)) throw new Error("malformed legacy chat replay state; preserve and reconcile it");
  }
  return JSON.stringify({ sha256: digest(bytes), identity: identity(after) });
}
export function recordReplayMigration(file: string, now = Date.now()): void {
  if (!file || !Number.isFinite(now)) throw new Error("legacy replay file and finite cutoff required");
  const fingerprint = legacySnapshot(file);
  const receipt = `${file}.migration-v2.json`, temp = `${receipt}.${process.pid}.tmp`;
  writeFileSync(temp, JSON.stringify({ schema: REPLAY_SCHEMA, cutoff: now, fingerprint }) + "\n", { mode: 0o600 }); renameSync(temp, receipt);
}
function requireLegacyQuiet(file: string, now: number): void {
  let legacyExists = true;
  try { lstatSync(file); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; legacyExists = false; }
  if (!legacyExists) {
    if (existsSync(`${file}.migration-v2.json`)) throw new Error("legacy replay file disappeared after migration cutoff; reconcile it");
    return;
  }
  const fingerprint = legacySnapshot(file);
  let receipt: { schema?: unknown; cutoff?: unknown; fingerprint?: unknown };
  try { receipt = JSON.parse(readFileSync(`${file}.migration-v2.json`, "utf8")); }
  catch { throw new Error("legacy chat replay state requires --record-replay-cutoff after stopping only this adapter, then a full quiet window"); }
  if (!receipt || receipt.schema !== REPLAY_SCHEMA || typeof receipt.cutoff !== "number" || !Number.isFinite(receipt.cutoff) || receipt.fingerprint !== fingerprint) throw new Error("invalid or changed legacy replay migration cutoff; preserve and reconcile state");
  if (now <= receipt.cutoff + 2 * WINDOW_MS) throw new Error("legacy chat replay migration quiet window has not elapsed (must exceed ten minutes)");
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

function config(): { origin: URL; gatewayToken: string; secret: string; replayFile: string; host: string; port: number; forwardTimeoutMs: number } {
  const origin = new URL(process.env["KEEP_GATEWAY_ORIGIN"] ?? ""); const gatewayToken = process.env["KEEP_GATEWAY_TOKEN"] ?? ""; const secret = process.env["KEEP_CHAT_SECRET"] ?? ""; const replayFile = process.env["KEEP_CHAT_REPLAY_FILE"] ?? ""; const host = process.env["KEEP_CHAT_HOST"] ?? "127.0.0.1"; const port = Number(process.env["KEEP_CHAT_PORT"] ?? "7790");
  const forwardTimeoutMs = Number(process.env["KEEP_CHAT_FORWARD_TIMEOUT_MS"] ?? "10000");
  if (!Number.isSafeInteger(forwardTimeoutMs) || forwardTimeoutMs <= 0) throw new Error("KEEP_CHAT_FORWARD_TIMEOUT_MS must be a positive safe integer");
  const loopbackOrigin = origin.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname) && origin.pathname === "/" && !origin.username && !origin.password && !origin.search && !origin.hash;
  if (!loopbackOrigin || !gatewayToken || !secret || !replayFile) throw new Error("a loopback KEEP_GATEWAY_ORIGIN plus KEEP_GATEWAY_TOKEN, KEEP_CHAT_SECRET, and KEEP_CHAT_REPLAY_FILE are required");
  if (!["127.0.0.1", "localhost", "::1"].includes(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error("development chat adapter must use a loopback host and valid port");
  return { origin, gatewayToken, secret, replayFile, host, port, forwardTimeoutMs };
}

function respond(res: ServerResponse, status: number, value: unknown): void { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(value)); }
async function body(req: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of req) { const bytes = Buffer.from(chunk); size += bytes.length; if (size > MAX_BODY) throw new Error("body too large"); chunks.push(bytes); } return Buffer.concat(chunks).toString("utf8"); }

/** One request-owned monotonic deadline, covering headers AND response consumption.
 * Timer slices avoid Node's large-delay clamp; disposal prevents late callbacks.
 * This bounds network waiting, not downstream work, body bytes or event-loop stalls.
 */
function forwardingDeadline(ms: number): { signal: AbortSignal; dispose(): void } {
  const controller = new AbortController(), deadline = performance.now() + ms;
  let timer: NodeJS.Timeout | undefined, disposed = false;
  const arm = (): void => {
    if (disposed) return;
    const remaining = deadline - performance.now();
    if (remaining <= 0) { controller.abort(new Error("chat forwarding deadline exceeded")); return; }
    timer = setTimeout(arm, Math.min(2_147_483_647, Math.ceil(remaining))); timer.unref();
  };
  arm();
  return { signal: controller.signal, dispose() { disposed = true; if (timer) clearTimeout(timer); } };
}

export async function main(): Promise<void> {
  const cfg = config(); requireLegacyQuiet(cfg.replayFile, Date.now());
  const deliveries = new ChatDeliveryStore(cfg.replayFile, { ...(process.env["KEEP_CHAT_DELIVERY_MAX_RECORDS"] === undefined ? {} : { maxRecords: Number(process.env["KEEP_CHAT_DELIVERY_MAX_RECORDS"]) }), ...(process.env["KEEP_CHAT_DELIVERY_MAX_BYTES"] === undefined ? {} : { maxBytes: Number(process.env["KEEP_CHAT_DELIVERY_MAX_BYTES"]) }) });
  const verifier = new WebhookVerifier();
  const server = createServer(async (req, res) => {
    try {
      if (req.method !== "POST" || req.url !== "/event") { respond(res, 404, { error: "not found" }); return; }
      const raw = await body(req); const headers: Record<string, string> = {}; for (const [key, value] of Object.entries(req.headers)) if (typeof value === "string") headers[key] = value;
      const verified = verifier.verify({ source: "generic", rawBody: raw, headers, secret: cfg.secret });
      if (!verified.ok) { respond(res, 401, { error: "unauthorized" }); return; }
      const timestamp = Number(headers["x-webhook-timestamp"]);
      const replayKey = KEY_PREFIX + digest(JSON.stringify(["generic", timestamp, raw]));
      let parsed: unknown; try { parsed = JSON.parse(raw); } catch { respond(res, 400, { error: "invalid json" }); return; }
      const event = channelEvent(parsed); if (!event) { respond(res, 400, { error: "invalid channel event" }); return; }
      const claim = deliveries.claimForEntry(replayKey, timestamp * 1000 + WINDOW_MS);
      if (!claim.admitted) { respond(res, 409, { error: ["entered", "unknown"].includes(claim.state) ? "delivery outcome uncertain; explicit reconciliation required" : "replayed event", deliveryState: claim.state }); return; }
      // The lock is released and entered state is durable before network entry.
      const deadline = forwardingDeadline(cfg.forwardTimeoutMs);
      try {
        const route = routeChannelEvent(event); const gateway = await fetch(new URL(route.path, cfg.origin), { method: route.method, signal: deadline.signal, headers: { connection: "close", authorization: `Bearer ${cfg.gatewayToken}`, "content-type": "application/json" }, ...(route.body === undefined ? {} : { body: JSON.stringify(route.body) }) });
        const responseBody = await gateway.text(), reply = formatChannelResponse(event, gateway.status, responseBody);
        if (gateway.status === 200) deliveries.finish(replayKey, claim.token, { status: 200, bodySha256: deliveryDigest(responseBody) });
        else deliveries.finish(replayKey, claim.token);
        respond(res, gateway.status === 200 ? 200 : 502, reply);
      } catch {
        // Failed confirmation publication may have left confirmed OR entered state.
        // Never relabel that ambiguity as proof that the gateway had no effect.
        try { deliveries.finish(replayKey, claim.token); } catch { /* retained state requires reconciliation */ }
        respond(res, 502, { error: "delivery outcome uncertain; explicit reconciliation required" });
      } finally { deadline.dispose(); }
    } catch (error) { respond(res, error instanceof ChatDeliveryCapacityError ? 503 : (error as Error).message === "body too large" ? 413 : 500, { error: "chat adapter failure" }); }
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(cfg.port, cfg.host, resolve); });
  const address = server.address(); const port = typeof address === "object" && address ? address.port : cfg.port;
  process.stdout.write(`${JSON.stringify({ ready: true, host: cfg.host, port })}\n`);
}

async function command(): Promise<void> {
  if (process.argv[2] === "--record-replay-cutoff") { recordReplayMigration(process.env["KEEP_CHAT_REPLAY_FILE"] ?? ""); return; }
  if (process.argv[2] === "--reconcile-delivery") {
    const file = process.env["KEEP_CHAT_REPLAY_FILE"] ?? ""; if (!file) throw new Error("KEEP_CHAT_REPLAY_FILE required for reconciliation");
    requireLegacyQuiet(file, Date.now());
    new ChatDeliveryStore(file).reconcile(process.argv[3] ?? "", process.argv[4] as "confirmed" | "no-effect", process.argv[5] ?? "");
    process.stdout.write("delivery reconciled; no redispatch performed\n"); return;
  }
  await main();
}
if (import.meta.url === `file://${process.argv[1]}`) command().catch((error) => { process.stderr.write(`${(error as Error).message}\n`); process.exit(1); });
