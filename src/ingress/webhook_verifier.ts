/**
 * WebhookVerifier (Increment W0) — the security core of trigger ingress. A webhook endpoint is a HOSTILE
 * external surface: "an unverified webhook is just an HTTP request from the internet — anyone can send one."
 * This verifies authenticity + integrity + freshness BEFORE Keep acts on a payload, fail-closed.
 *
 * SOTA basis (2026-08-06), unanimous across sources (pontil, Hooque, hooklistener, OpsecForge, Linear guide):
 *  1. Verify HMAC-SHA256 over the RAW request bytes — NEVER the re-serialised JSON. "The single most common
 *     verification bug is signing the parsed-and-reserialised body instead of the exact bytes the sender signed."
 *  2. Constant-time comparison (node:crypto timingSafeEqual) — never `===` on the digest (timing side-channel).
 *  3. Timestamp + max-age window for replay/freshness where the provider supplies one (default 300s).
 *  4. Idempotency is a SEPARATE control (dedup on a delivery id, or a stable content hash when absent) — done
 *     by TriggerIngress, not here; the verifier returns the deliveryId to dedup on.
 *  Signatures are the PRIMARY control; IP allowlisting is brittle defense-in-depth (provider IPs rotate).
 *
 * Provider schemes verified current (2026-08-06):
 *  - linear:        `Linear-Signature` = hex HMAC-SHA256 over raw body; `webhookTimestamp` (ms) in body → freshness.
 *  - github-issues: `X-Hub-Signature-256: sha256=<hex>` HMAC-SHA256 over raw body; `X-GitHub-Delivery` = id.
 *  - gitlab:        `X-Gitlab-Token` shared secret (constant-time equality); `X-Gitlab-Event-UUID` = id.
 *  - generic/jira:  `X-Webhook-Signature: sha256=<hex>` HMAC-SHA256 over `${timestamp}.${rawBody}` +
 *                   `X-Webhook-Timestamp` (unix seconds) binds freshness; `X-Webhook-Id` = id. (Jira's native
 *                   signing is app-specific; operators front Jira with this signed scheme, or use polling.)
 *
 * Zero deps (node:crypto is a builtin). What would change it: a provider changes its header/algorithm → update
 * that one scheme; the port + the rest of ingress are unaffected.
 */

import { createHmac, createHash, timingSafeEqual } from "node:crypto";
import type { TrackerSource } from "../ecosystem/integrations.js";

export interface VerifyInput {
  readonly source: TrackerSource;
  /** The EXACT raw request body bytes as received (never re-serialised). */
  readonly rawBody: string;
  readonly headers: Readonly<Record<string, string>>;
  /** The signing secret configured for this source (never hardcoded; supplied by the operator). */
  readonly secret: string;
  readonly now?: number; // ms; injectable for tests
  readonly maxAgeSec?: number; // default 300
}

export type WebhookVerifyResult =
  | { readonly ok: true; readonly deliveryId: string }
  | { readonly ok: false; readonly reason: string };

function lowerHeaders(h: Readonly<Record<string, string>>): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of Object.keys(h)) o[k.toLowerCase()] = h[k]!;
  return o;
}

/** Constant-time compare of two hex digests. Guards length (timingSafeEqual throws on length mismatch). */
function constantTimeHexEqual(aHex: string, bHex: string): boolean {
  if (!/^[0-9a-f]*$/i.test(aHex) || aHex.length === 0) return false;
  const a = Buffer.from(aHex, "hex");
  const b = Buffer.from(bHex, "hex");
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function constantTimeStrEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function hmacHex(secret: string, body: string): string {
  return createHmac("sha256", secret).update(body, "utf8").digest("hex");
}

function contentHash(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex").slice(0, 32);
}

/** Targeted numeric extraction from an ALREADY-AUTHENTICATED raw JSON body (no full parse, no trust needed). */
function extractNumber(rawBody: string, key: string): number | undefined {
  const m = new RegExp(`"${key}"\\s*:\\s*(\\d+)`).exec(rawBody);
  return m ? Number(m[1]) : undefined;
}

export class WebhookVerifier {
  verify(input: VerifyInput): WebhookVerifyResult {
    const h = lowerHeaders(input.headers);
    const maxAgeSec = input.maxAgeSec ?? 300;
    const now = input.now ?? Date.now();
    if (!input.secret) return { ok: false, reason: "no signing secret configured for this source (fail-closed)" };

    switch (input.source) {
      case "linear": {
        const sig = h["linear-signature"];
        if (!sig) return { ok: false, reason: "missing Linear-Signature header" };
        if (!constantTimeHexEqual(sig, hmacHex(input.secret, input.rawBody))) return { ok: false, reason: "signature mismatch" };
        const ts = extractNumber(input.rawBody, "webhookTimestamp"); // ms; body is authenticated now
        if (ts !== undefined && Math.abs(now - ts) > maxAgeSec * 1000) return { ok: false, reason: "stale timestamp (replay window exceeded)" };
        return { ok: true, deliveryId: `linear:${contentHash(input.rawBody)}` };
      }
      case "github-issues": {
        const sig = h["x-hub-signature-256"];
        if (!sig || !sig.startsWith("sha256=")) return { ok: false, reason: "missing X-Hub-Signature-256 header" };
        if (!constantTimeHexEqual(sig.slice("sha256=".length), hmacHex(input.secret, input.rawBody))) return { ok: false, reason: "signature mismatch" };
        const id = h["x-github-delivery"];
        return { ok: true, deliveryId: id ? `github:${id}` : `github:${contentHash(input.rawBody)}` };
      }
      case "gitlab": {
        const token = h["x-gitlab-token"];
        if (!token || !constantTimeStrEqual(token, input.secret)) return { ok: false, reason: "bad or missing X-Gitlab-Token" };
        const id = h["x-gitlab-event-uuid"];
        return { ok: true, deliveryId: id ? `gitlab:${id}` : `gitlab:${contentHash(input.rawBody)}` };
      }
      case "jira":
      case "generic": {
        const sig = h["x-webhook-signature"];
        const tsHeader = h["x-webhook-timestamp"];
        if (!sig || !sig.startsWith("sha256=")) return { ok: false, reason: "missing X-Webhook-Signature header" };
        if (!tsHeader) return { ok: false, reason: "missing X-Webhook-Timestamp header" };
        const ts = Number(tsHeader);
        if (!Number.isFinite(ts)) return { ok: false, reason: "bad timestamp" };
        if (Math.abs(now / 1000 - ts) > maxAgeSec) return { ok: false, reason: "stale timestamp (replay window exceeded)" };
        // Bind freshness + content: sign `${timestamp}.${rawBody}` (SOTA: timestamp.rawBody).
        if (!constantTimeHexEqual(sig.slice("sha256=".length), hmacHex(input.secret, `${ts}.${input.rawBody}`))) return { ok: false, reason: "signature mismatch" };
        const id = h["x-webhook-id"];
        return { ok: true, deliveryId: id ? `${input.source}:${id}` : `${input.source}:${contentHash(input.rawBody)}` };
      }
      default:
        return { ok: false, reason: `unsupported source '${String(input.source)}'` };
    }
  }
}
