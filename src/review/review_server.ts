/**
 * Node HTTP adapter for the review handler. Owns binding, body reads, per-run tokens
 * and the Host allowlist; review_web.ts handles routing, authorization and rendering.
 * Defaults to loopback. Broader exposure needs deployment authentication and TLS.
 */

import { createServer, type IncomingMessage } from "node:http";
import { randomBytes } from "node:crypto";
import type { KeepApp } from "../compose.js";
import { handleReviewRequest, type WebRequest, type WebSecurity, type IdentityLayer } from "./review_web.js";
import { OWNER } from "../identity/rbac.js";

export interface ReviewServerHandle {
  readonly url: string;     // full URL including the token — what the operator opens
  readonly origin: string;  // e.g. http://127.0.0.1:7777
  readonly port: number;
  readonly token: string;
  close(): Promise<void>;
}
export interface ReviewServerOptions {
  readonly port?: number;   // default 7777; pass 0 for an ephemeral port (tests)
  readonly host?: string;   // default 127.0.0.1 — NEVER default to 0.0.0.0
  readonly token?: string;  // injectable for tests; default: 24 random bytes
  readonly maxBodyBytes?: number;
  /** X1: present → the server runs in multi-user mode (IdP login + sessions). Absent → single-owner (N=1). */
  readonly identity?: IdentityLayer;
}

export function startReviewServer(app: KeepApp, opts: ReviewServerOptions = {}): Promise<ReviewServerHandle> {
  const host = opts.host ?? "127.0.0.1";
  const token = opts.token ?? randomBytes(24).toString("hex");
  const maxBody = opts.maxBodyBytes ?? 1_000_000;

  const server = createServer((req, res) => {
    (async () => {
      let body: string;
      try {
        body = await collectBody(req, maxBody);
      } catch {
        res.writeHead(413, { "Content-Type": "text/plain" }); res.end("Request too large."); return;
      }
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const origin = `http://${host}:${port}`;
      const url = new URL(req.url ?? "/", origin);
      const query: Record<string, string> = {};
      for (const [k, v] of url.searchParams) query[k] = v;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k.toLowerCase()] = v;
      const sec: WebSecurity = { token, origin, allowedHosts: [`${host}:${port}`, `localhost:${port}`], principal: OWNER, ...(opts.identity ? { identity: opts.identity } : {}) };
      const wreq: WebRequest = { method: req.method ?? "GET", path: url.pathname, query, headers, body };
      const resp = await handleReviewRequest(app, wreq, sec);
      res.writeHead(resp.status, { ...resp.headers });
      res.end(resp.body);
    })().catch(() => { if (!res.headersSent) { res.writeHead(500, { "Content-Type": "text/plain" }); res.end("Internal error."); } });
  });

  return new Promise((resolve, reject) => {
    // These listeners own startup only; successful startup retains normal runtime error semantics.
    const cleanup = () => {
      server.removeListener("error", onError);
      server.removeListener("listening", onListening);
    };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onListening = () => {
      cleanup();
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const origin = `http://${host}:${port}`;
      resolve({
        url: `${origin}/?token=${token}`, origin, port, token,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    };
    server.once("error", onError);
    server.once("listening", onListening);
    try { server.listen(opts.port ?? 7777, host); }
    catch (error) { cleanup(); reject(error); }
  });
}

function collectBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ""; let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) { reject(new Error("body too large")); req.destroy(); return; }
      data += c.toString("utf8");
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
