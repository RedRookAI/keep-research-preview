import { captureCodeFlowJwks, OidcJwksProvider, strictOidcObject, type Jwks, type VerifiedCodeFlowIdentity } from "./oidc_provider.js";
import type { OidcLoginConfig } from "./oidc_code_flow.js";
import { createHash } from "node:crypto";

export interface OidcKeyRefreshPolicy {
  readonly metadataUrl: string;
  readonly ttlMs: number;
  readonly cooldownMs: number;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly maxKeys: number;
  readonly maxRetiredKeys: number;
}
export function captureOidcKeyRefreshPolicy(value: unknown): OidcKeyRefreshPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid organization key refresh policy");
  const row = value as Record<string, unknown>;
  if (Object.keys(row).sort().join(",") !== "cooldownMs,maxKeys,maxResponseBytes,maxRetiredKeys,metadataUrl,timeoutMs,ttlMs") throw new Error("organization key refresh requires its complete policy");
  let url: URL;
  try { url = new URL(row.metadataUrl as string); } catch { throw new Error("invalid organization metadata endpoint"); }
  if (url.protocol !== "https:" || url.href !== row.metadataUrl || url.username || url.password || url.search || url.hash) throw new Error("invalid organization metadata endpoint");
  for (const field of ["ttlMs", "cooldownMs", "timeoutMs", "maxResponseBytes", "maxKeys", "maxRetiredKeys"]) if (!Number.isSafeInteger(row[field]) || (row[field] as number) < 1) throw new Error("organization refresh limits require positive safe integers");
  if ((row.timeoutMs as number) > 2147483647 || (row.cooldownMs as number) > (row.ttlMs as number) || (row.maxKeys as number) > 64) throw new Error("invalid organization refresh limits");
  return Object.freeze({ ...row }) as unknown as OidcKeyRefreshPolicy;
}
interface Snapshot { readonly jwks: Jwks; readonly loadedAt: number; readonly expiresAt: number; }
type Transaction = { readonly nonce: string; readonly issuedAt: number; readonly expiresAt: number };

/** One process-local, operator-pinned source. A caller's cancellation never cancels another caller's refresh. */
export class OidcIssuerKeySource {
  private snapshot: Snapshot | undefined;
  private refreshing: Promise<void> | undefined;
  private lastAttempt: number | undefined;
  private readonly retired = new Map<string, string>();
  constructor(private readonly issuer: string, private readonly config: OidcLoginConfig, private readonly policy: OidcKeyRefreshPolicy,
    private readonly transport: typeof fetch = fetch, private readonly clock: () => number = Date.now) {}

  async verify(assertion: string, _now: number, transaction: Transaction, signal: AbortSignal): Promise<VerifiedCodeFlowIdentity | null> {
    try {
      if (signal.aborted || assertion.length > 16384) return null;
      const [h, p, s, extra] = assertion.split(".");
      if (!h || !p || !s || extra !== undefined || !/^[A-Za-z0-9_-]+$/u.test(h) || Buffer.from(h, "base64url").toString("base64url") !== h) return null;
      const header = strictOidcObject(Buffer.from(h, "base64url"));
      if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid || header.kid.length > 256 || header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined || header.crit !== undefined || header.b64 !== undefined) return null;
      let now = this.clock();
      if (!Number.isSafeInteger(now)) return null;
      const known = () => this.snapshot !== undefined && now >= this.snapshot.loadedAt && now < this.snapshot.expiresAt && this.snapshot.jwks.keys.some(key => key.kid === header.kid);
      if (!known()) {
        if (this.refreshing) await this.wait(this.refreshing, signal);
        else if (this.lastAttempt === undefined || now >= this.lastAttempt + this.policy.cooldownMs) {
          const refresh = this.refresh(); this.refreshing = refresh;
          void refresh.finally(() => { if (this.refreshing === refresh) this.refreshing = undefined; }).catch(() => undefined);
          await this.wait(refresh, signal);
        }
      }
      now = this.clock();
      if (!Number.isSafeInteger(now) || signal.aborted || !known()) return null;
      return await new OidcJwksProvider({ issuer: this.issuer, audience: this.config.clientId, jwks: this.snapshot!.jwks, leewaySec: this.config.leewaySec }).verifyCodeFlow(assertion, now, transaction);
    } catch { return null; }
  }

  private async wait(work: Promise<void>, signal: AbortSignal): Promise<void> {
    let abort: (() => void) | undefined;
    const cancelled = new Promise<never>((_, reject) => { abort = () => reject(new Error("organization refresh cancelled")); signal.addEventListener("abort", abort, { once: true }); if (signal.aborted) abort(); });
    try { await Promise.race([work, cancelled]); } finally { if (abort) signal.removeEventListener("abort", abort); }
  }

  private async refresh(): Promise<void> {
    const started = this.clock();
    if (!Number.isSafeInteger(started)) throw new Error("organization refresh unavailable");
    this.lastAttempt = started;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error("organization refresh unavailable")); }, this.policy.timeoutMs); });
    const work = async () => {
      const metadata = await this.document(this.policy.metadataUrl, controller.signal);
      if (metadata.issuer !== this.issuer || metadata.authorization_endpoint !== this.config.authorizationEndpoint || metadata.token_endpoint !== this.config.tokenEndpoint || metadata.jwks_uri !== this.config.jwksUri
        || !Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.includes("code") || !Array.isArray(metadata.id_token_signing_alg_values_supported) || !metadata.id_token_signing_alg_values_supported.includes("RS256")
        || !Array.isArray(metadata.code_challenge_methods_supported) || !metadata.code_challenge_methods_supported.includes("S256")
        || (metadata.token_endpoint_auth_methods_supported !== undefined && (!Array.isArray(metadata.token_endpoint_auth_methods_supported) || !metadata.token_endpoint_auth_methods_supported.includes("client_secret_basic")))) throw new Error("organization metadata refused");
      return captureCodeFlowJwks(await this.document(this.config.jwksUri, controller.signal), this.policy.maxKeys);
    };
    try {
      const jwks = await Promise.race([work(), timeout]), now = this.clock();
      if (controller.signal.aborted || !Number.isSafeInteger(now) || now < started || now - started >= this.policy.timeoutMs) throw new Error("organization refresh unavailable");
      const material = (key: Jwks["keys"][number]) => createHash("sha256").update(`${key.n}.${key.e}`).digest("hex");
      const retired = new Map(this.retired);
      const retiredMaterial = new Set(retired.values());
      for (const key of jwks.keys) {
        if (retired.has(key.kid!) || retiredMaterial.has(material(key))) throw new Error("retired organization key refused");
        const prior = this.snapshot?.jwks.keys.find(old => old.kid === key.kid);
        if (prior && material(prior) !== material(key)) throw new Error("organization key id changed material");
      }
      for (const prior of this.snapshot?.jwks.keys ?? []) if (!jwks.keys.some(key => key.kid === prior.kid)) retired.set(prior.kid!, material(prior));
      if (retired.size > this.policy.maxRetiredKeys) throw new Error("organization retired-key capacity requires operator reconciliation");
      this.retired.clear(); for (const [kid, bytes] of retired) this.retired.set(kid, bytes);
      this.snapshot = Object.freeze({ jwks, loadedAt: now, expiresAt: now + this.policy.ttlMs });
    } finally { if (timer !== undefined) clearTimeout(timer); controller.abort(); }
  }

  private async document(url: string, signal: AbortSignal): Promise<Record<string, unknown>> {
    const response = await this.transport(url, { method: "GET", redirect: "error", signal, headers: { accept: "application/json" } });
    if (signal.aborted || response.status !== 200 || response.redirected || (response.url && response.url !== url) || !response.body || response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") throw new Error("organization refresh unavailable");
    const reader = response.body.getReader(), chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) { if (signal.aborted) throw new Error("organization refresh cancelled"); const { value, done } = await reader.read(); if (done) break; size += value.length; if (size > this.policy.maxResponseBytes) throw new Error("organization key document too large"); chunks.push(value); }
    } finally { if (size > this.policy.maxResponseBytes || signal.aborted) void reader.cancel().catch(() => undefined); reader.releaseLock(); }
    return strictOidcObject(Buffer.concat(chunks));
  }
}
