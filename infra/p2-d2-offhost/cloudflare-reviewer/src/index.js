const encoder = new TextEncoder();
const hex = (bytes) => [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
const base64 = (bytes) => {
  let binary = "";
  for (const value of new Uint8Array(bytes)) binary += String.fromCharCode(value);
  return btoa(binary);
};

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

export class ReviewerKey {
  constructor(state, env) { this.state = state; this.env = env; }

  async keyPair() {
    let privateKey = await this.state.storage.get("private-key");
    let publicKeyHex = await this.state.storage.get("public-key-hex");
    if (privateKey === undefined || publicKeyHex === undefined) {
      const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
      const publicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
      privateKey = pair.privateKey;
      publicKeyHex = hex(publicKey);
      await this.state.storage.put({ "private-key": privateKey, "public-key-hex": publicKeyHex });
    }
    return { privateKey, publicKeyHex };
  }

  async fetch(request) {
    if (request.headers.get("authorization") !== `Bearer ${this.env.PROVISION_TOKEN}`) return json({ error: "unauthorized" }, 401);
    const url = new URL(request.url);
    const pair = await this.keyPair();
    if (request.method === "GET" && url.pathname === "/public-key") {
      return json({ schema: "keep.p2-d2-offhost-reviewer-key", version: 1, mechanism: "ed25519-service", publicKeyHex: pair.publicKeyHex });
    }
    if (request.method !== "POST" || url.pathname !== "/review") return json({ error: "not-found" }, 404);
    const body = await request.json();
    if (body?.schema !== "keep.p2-d2-review-request" || body?.version !== 1 || typeof body.prompt !== "string" ||
        typeof body.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/.test(body.evidenceDigest) ||
        typeof body.auditPlanDigest !== "string" || !/^[0-9a-f]{64}$/.test(body.auditPlanDigest) ||
        typeof body.role !== "string" || typeof body.counter !== "number" || !Number.isSafeInteger(body.counter))
      return json({ error: "malformed-request" }, 400);
    const provider = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": this.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4-1-20250805", max_tokens: 32000, temperature: 0,
        messages: [{ role: "user", content: body.prompt }] }),
    });
    const responseText = await provider.text();
    if (!provider.ok) return json({ error: "provider-failure", providerStatus: provider.status }, 502);
    const signed = {
      schema: "keep.p2-d2-offhost-review-result", version: 1, principal: "reviewer.cloudflare-anthropic",
      reviewerFamily: "anthropic", custodianFamily: "cloudflare-workers", mechanism: "ed25519-service",
      evidenceDigest: body.evidenceDigest, auditPlanDigest: body.auditPlanDigest, role: body.role,
      counter: body.counter, prompt: body.prompt, providerResponse: responseText,
    };
    const signedBytes = encoder.encode(`keep.p2-d2-review/v1\0${JSON.stringify(signed)}`);
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, signedBytes);
    return json({ ...signed, signatureBase64: base64(signature), publicKeyHex: pair.publicKeyHex });
  }
}

export default {
  async fetch(request, env) {
    const id = env.REVIEWER_KEY.idFromName("keep-p2-d2-reviewer-anthropic-v1");
    return env.REVIEWER_KEY.get(id).fetch(request);
  },
};
