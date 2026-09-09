import type { GatewayRequest, GatewayResponse } from "../gateway/http_gateway.js";

/** Pure client transport: no app composition, provider configuration, retry or redirect. */
export function createGatewayClient(origin: string, session?: string): (request: GatewayRequest) => Promise<GatewayResponse> {
  const base = new URL(origin);
  if (base.username || base.password || base.pathname !== "/" || base.search || base.hash
    || (base.protocol !== "https:" && !(base.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(base.hostname)))) throw new Error("gateway URL must be an HTTPS origin or literal-loopback HTTP origin");
  if (session !== undefined && !/^[0-9a-f]{64}$/u.test(session)) throw new Error("gateway session is malformed");
  return async request => {
    if (!/^\/(?:[A-Za-z0-9][A-Za-z0-9/_-]*)?$/u.test(request.path) || Buffer.byteLength(request.body) > 1_000_000) throw new Error("gateway request exceeds the client boundary");
    const url = new URL(request.path, base);
    for (const [key, value] of Object.entries(request.query)) url.searchParams.set(key, value);
    const response = await fetch(url, { method: request.method, headers: { ...request.headers, "content-type": "application/json", ...(session ? { "x-keep-session": session } : {}) },
      ...(request.method === "GET" || request.method === "HEAD" ? {} : { body: request.body }), redirect: "error", signal: AbortSignal.timeout(120_000) });
    const chunks: Uint8Array[] = []; let size = 0;
    if (response.body) {
      const reader = response.body.getReader();
      try {
        for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
          if (size > 1_048_576) { await reader.cancel(); throw new Error("gateway response exceeds 1 MiB"); } chunks.push(part.value); }
      } finally { reader.releaseLock(); }
    }
    return { status: response.status, headers: Object.fromEntries(response.headers), body: Buffer.concat(chunks).toString("utf8") };
  };
}
