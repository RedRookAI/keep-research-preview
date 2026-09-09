/**
 * HttpIngress (Increment W0) — a zero-dep node:http listener in front of TriggerIngress. It reads the EXACT raw
 * body bytes (mandatory: HMAC is computed over the bytes the sender signed, never a re-serialised JSON), derives
 * the tracker source from the path (`/webhook/<source>`), and returns:
 *   - 202 Accepted   after verify + accept
 *   - 200 OK         on a duplicate delivery (idempotent ack — retries are safe)
 *   - 401            on rejection (the reason is AUDITED internally, never leaked to the caller — don't help a
 *                    prober distinguish "bad signature" from "unknown source")
 *   - 404 / 413      unknown route / oversized body (a basic DoS guard)
 *
 * The optional IP allowlist is now BUILT (direct-peer, fail-closed; X-Forwarded-For untrusted). Only TLS termination + DNS
 * remain a deployment concern (VERIFIED-SEAM); signatures are the primary control, the allowlist brittle defense-in-depth. The request handling + verification
 * + dedup is BUILT here and proven with a real localhost request.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import type { TrackerSource } from "../ecosystem/integrations.js";
import type { TriggerIngress } from "./trigger_ingress.js";

const SOURCES: ReadonlySet<string> = new Set(["linear", "jira", "github-issues", "gitlab", "generic"]);

export interface HttpIngressHandle {
  readonly server: Server;
  readonly port: number;
  close(): Promise<void>;
}

export async function startHttpIngress(
  ingress: TriggerIngress,
  opts: { port?: number; host?: string; pathPrefix?: string; maxBodyBytes?: number; allowedIps?: readonly string[] } = {},
): Promise<HttpIngressHandle> {
  const prefix = opts.pathPrefix ?? "/webhook/";
  const maxBody = opts.maxBodyBytes ?? 1_000_000; // 1 MB cap
  const allow = opts.allowedIps ? new Set(opts.allowedIps.map(normalizeIp)) : undefined;
  const server = createServer((req, res) => {
    // Defense-in-depth IP allowlist (signatures remain the PRIMARY control). Checked against the real TCP peer only —
    // X-Forwarded-For is client-controlled and trivially spoofable (2026 CVE class: Wekan/Kanboard/Gitea), so it is NOT
    // trusted here; behind a real trusted proxy, IP allowlisting is the proxy's job (deployment). Fail CLOSED: a
    // configured-but-empty allowlist denies everything rather than trusting every source.
    if (allow !== undefined) {
      const peer = normalizeIp(req.socket.remoteAddress ?? "");
      if (!allow.has(peer)) {
        res.writeHead(403);
        res.end("forbidden"); // reason not leaked
        req.resume(); // drain
        return;
      }
    }
    void handle(req, res, ingress, prefix, maxBody);
  });
  const port = await new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, opts.host ?? "127.0.0.1", () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr ? addr.port : (opts.port ?? 0));
    });
  });
  return { server, port, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/** Normalize an IP: strip the IPv4-mapped IPv6 prefix so ::ffff:127.0.0.1 and 127.0.0.1 compare equal. */
export function normalizeIp(ip: string): string {
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

async function handle(req: IncomingMessage, res: ServerResponse, ingress: TriggerIngress, prefix: string, maxBody: number): Promise<void> {
  try {
    if (req.method !== "POST" || !req.url || !req.url.startsWith(prefix)) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    const src = req.url.slice(prefix.length).split(/[/?]/)[0] ?? "";
    if (!SOURCES.has(src)) {
      res.writeHead(404);
      res.end("unknown source");
      return;
    }
    const rawBody = await readRaw(req, maxBody);
    if (rawBody === null) {
      res.writeHead(413);
      res.end("payload too large");
      return;
    }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(",") : (v ?? "");
    const result = await ingress.receive({ source: src as TrackerSource, rawBody, headers });
    if (result.status === "accepted") {
      res.writeHead(202, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "accepted", issueId: result.issueId }));
    } else if (result.status === "duplicate") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "duplicate" }));
    } else if (result.status === "dead-letter") {
      // Retries exhausted → parked for a human. Ack 200 so the sender STOPS retrying (further retries won't help).
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "dead-letter" }));
    } else if (result.status === "error") {
      // Transient handler failure — the event is NOT marked processed, so a sender retry will re-run it.
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "error" }));
    } else {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "rejected" })); // reason NOT leaked
    }
  } catch {
    res.writeHead(500);
    res.end("error");
  }
}

/** Read the raw body, enforcing a size cap. Returns null if the cap is exceeded. */
function readRaw(req: IncomingMessage, maxBody: number): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBody) {
        tooBig = true;
        req.destroy();
      } else {
        chunks.push(c);
      }
    });
    req.on("end", () => resolve(tooBig ? null : Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(tooBig ? null : Buffer.concat(chunks).toString("utf8")));
  });
}
