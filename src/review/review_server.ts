/**
 * Web review UI — socket seam (Increment S2). A thin Node `http` adapter (built-ins only, zero deps) around the
 * pure handler in review_web.ts. It owns ONLY the things a socket owns: binding, reading the body, generating the
 * per-run token, and computing the Host allowlist from the actually-bound port. All routing/security/rendering is
 * the pure handler's job (and is unit-tested there without a socket).
 *
 * Binds 127.0.0.1 by DEFAULT — never 0.0.0.0 — so a single operator (N=1) is safe out of the box; exposing it
 * further is an explicit, opt-in deployment choice that belongs behind TLS. Real auth (X1) is now BUILT (OidcJwksProvider,
 * real RS256/JWKS); only TLS termination remains a deployment concern. VERIFIED-SEAM: the
 * socket wiring here is exercised by one integration test; the security + rendering guarantees are proven purely.
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

  return new Promise((resolve) => {
    server.listen(opts.port ?? 7777, host, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const origin = `http://${host}:${port}`;
      resolve({
        url: `${origin}/?token=${token}`, origin, port, token,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
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
