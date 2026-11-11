/** Single-issuer browser acquisition. Static admitted keys today; refresh/revocation use the ports below. */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import { strictOidcObject, type VerifiedCodeFlowIdentity } from "./oidc_provider.js";
import type { VerifiedIdentity } from "./identity_provider.js";
import type { Principal } from "./rbac.js";
import { SessionStore, type Session } from "./session_store.js";
import { captureOidcKeyRefreshPolicy, type OidcKeyRefreshPolicy } from "./oidc_key_source.js";

export interface OidcLoginConfig {
  readonly keys?: OidcKeyRefreshPolicy;
  readonly clientId: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly publicOrigin: string;
  readonly redirectUri: string;
  readonly clientSecretFile: string;
  readonly transactionTtlMs: number;
  readonly maxTransactions: number;
  readonly requestTimeoutMs: number;
  readonly maxResponseBytes: number;
  readonly leewaySec: number;
  readonly sessionIdleMs: number;
  readonly sessionAbsoluteMs: number;
  readonly maxSessions: number;
}
export function captureOidcLoginConfig(value: unknown, audience: string): OidcLoginConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid organization login configuration");
  const row = value as Record<string, unknown>;
  const fields = ["clientId", "authorizationEndpoint", "tokenEndpoint", "jwksUri", "publicOrigin", "redirectUri", "clientSecretFile", "transactionTtlMs", "maxTransactions", "requestTimeoutMs", "maxResponseBytes", "leewaySec", "sessionIdleMs", "sessionAbsoluteMs", "maxSessions"];
  if (fields.some(field => !Object.hasOwn(row, field)) || Object.keys(row).some(field => field !== "keys" && !fields.includes(field))) throw new Error("Organization login requires exactly its declared endpoint, credential-reference and operational fields");
  for (const name of ["clientId", "clientSecretFile"]) if (typeof row[name] !== "string" || !(row[name] as string) || (row[name] as string).length > 8192 || /[\u0000-\u001f\u007f]/u.test(row[name] as string)) throw new Error("Invalid organization login reference");
  if (row.clientId !== audience || !isAbsolute(row.clientSecretFile as string)) throw new Error("Organization login clientId must equal audience and its credential reference must be absolute");
  const urls: Record<string, URL> = {};
  for (const name of ["authorizationEndpoint", "tokenEndpoint", "jwksUri", "publicOrigin", "redirectUri"]) {
    if (typeof row[name] !== "string" || (row[name] as string).length > 8192) throw new Error("Invalid organization login endpoint");
    let url: URL;
    try { url = new URL(row[name] as string); } catch { throw new Error("Invalid organization login endpoint"); }
    if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search || (name === "publicOrigin" ? url.origin : url.href) !== row[name]) throw new Error("Organization login requires exact credential-free HTTPS endpoints");
    urls[name] = url;
  }
  if (urls.publicOrigin!.pathname !== "/" || urls.redirectUri!.origin !== urls.publicOrigin!.origin || urls.redirectUri!.pathname !== "/auth/oidc/callback") throw new Error("Organization callback must be /auth/oidc/callback at the configured public origin");
  for (const name of ["transactionTtlMs", "maxTransactions", "requestTimeoutMs", "maxResponseBytes", "sessionIdleMs", "sessionAbsoluteMs", "maxSessions"])
    if (!Number.isSafeInteger(row[name]) || (row[name] as number) < 1) throw new Error("Organization login operational limits require positive safe integers");
  if (!Number.isSafeInteger(row.leewaySec) || (row.leewaySec as number) < 0 || (row.transactionTtlMs as number) > 2147483647 || (row.requestTimeoutMs as number) > 2147483647
    || (row.sessionIdleMs as number) > (row.sessionAbsoluteMs as number)) throw new Error("Invalid organization login time policy");
  return Object.freeze({ ...row, ...(row.keys === undefined ? {} : { keys: captureOidcKeyRefreshPolicy(row.keys) }) }) as unknown as OidcLoginConfig;
}

interface LoginTransaction { readonly nonce: string; readonly verifier: string; readonly bindingHash: string; readonly issuedAt: number; readonly expiresAt: number; }
export interface OrganizationLoginPorts {
  /** KC008 can acquire current admitted keys through this verifier; context is per request. */
  readonly verify: (assertion: string, now: number, transaction: Pick<LoginTransaction, "nonce" | "issuedAt" | "expiresAt">, signal: AbortSignal) => Promise<VerifiedCodeFlowIdentity | null>;
  /** KC009 must keep roster and delegation authority synchronized; current runtime is a static roster. */
  readonly principal: (identity: VerifiedIdentity) => Principal | null;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
}
export class OrganizationLoginError extends Error {
  constructor() { super("Organization sign-in could not be completed. Start a new sign-in; the previous transaction will not be retried."); }
}
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const equal = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** No credential caching: descriptor read, ownership, single-link/mode/size checks before exchange. */
function clientSecret(path: string): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > 8192 || (process.platform !== "win32" && (stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0))) throw new OrganizationLoginError();
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (stat.size !== after.size || stat.mtimeMs !== after.mtimeMs || bytes.length > 8192) throw new OrganizationLoginError();
    const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/\r?\n$/u, "");
    if (!value || /[\u0000-\u001f\u007f]/u.test(value)) throw new OrganizationLoginError();
    return value;
  } catch { throw new OrganizationLoginError(); }
  finally { if (fd !== undefined) closeSync(fd); }
}

export class OidcCodeFlow {
  private readonly transactions = new Map<string, LoginTransaction>();
  constructor(readonly config: OidcLoginConfig, readonly issuer: string, private readonly tenantId: string, private readonly sessions: SessionStore, private readonly ports: OrganizationLoginPorts) {}

  start(): { readonly authorizationUrl: string; readonly browserBinding: string } {
    const now = (this.ports.now ?? Date.now)();
    if (!Number.isSafeInteger(now)) throw new OrganizationLoginError();
    for (const [state, row] of this.transactions) if (now >= row.expiresAt) this.transactions.delete(state);
    if (this.transactions.size >= this.config.maxTransactions) throw new OrganizationLoginError();
    const state = randomBytes(32).toString("base64url"), nonce = randomBytes(32).toString("base64url"), verifier = randomBytes(32).toString("base64url"), browserBinding = randomBytes(32).toString("base64url");
    this.transactions.set(hash(state), { nonce, verifier, bindingHash: hash(browserBinding), issuedAt: now, expiresAt: now + this.config.transactionTtlMs });
    const url = new URL(this.config.authorizationEndpoint);
    for (const [name, value] of Object.entries({ response_type: "code", scope: "openid", client_id: this.config.clientId, redirect_uri: this.config.redirectUri, state, nonce, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" })) url.searchParams.set(name, value);
    return { authorizationUrl: url.href, browserBinding };
  }

  cancel(state: string, browserBinding: string): void {
    this.claim(state, browserBinding);
  }

  private claim(state: string, browserBinding: string): LoginTransaction {
    const now = (this.ports.now ?? Date.now)();
    if (![state, browserBinding].every(value => typeof value === "string" && value.length > 0 && value.length <= 8192) || !Number.isSafeInteger(now)) throw new OrganizationLoginError();
    const key = hash(state), transaction = this.transactions.get(key);
    if (!transaction || !equal(transaction.bindingHash, hash(browserBinding)) || now < transaction.issuedAt || now >= transaction.expiresAt) throw new OrganizationLoginError();
    this.transactions.delete(key);
    return transaction;
  }

  async complete(state: string, browserBinding: string, code: string): Promise<Session> {
    const now = (this.ports.now ?? Date.now)();
    if (typeof code !== "string" || !code || code.length > 8192) throw new OrganizationLoginError();
    const transaction = this.claim(state, browserBinding); // no await precedes one-shot claim
    const slot = this.sessions.reserve(now);
    const controller = new AbortController();
    const deadline = Math.min(transaction.expiresAt, now + this.config.requestTimeoutMs);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new OrganizationLoginError()); }, Math.max(1, deadline - now)); });
    try {
      const idToken = await Promise.race([this.exchange(code, transaction.verifier, controller.signal), timeout]);
      const verifiedAt = (this.ports.now ?? Date.now)();
      if (!Number.isSafeInteger(verifiedAt) || verifiedAt < transaction.issuedAt || verifiedAt >= deadline) throw new OrganizationLoginError();
      const identity = await Promise.race([this.ports.verify(idToken, verifiedAt, transaction, controller.signal), timeout]);
      const completedAt = (this.ports.now ?? Date.now)();
      if (!identity || !Number.isFinite(identity.validUntil) || !Number.isSafeInteger(completedAt) || completedAt < verifiedAt || completedAt >= deadline || completedAt >= identity.validUntil) throw new OrganizationLoginError();
      const principal = identity === null ? null : this.ports.principal(identity);
      if (!principal || principal.kind !== "human" || principal.tenant !== this.tenantId) throw new OrganizationLoginError();
      return slot.create(principal, completedAt, { issuer: this.issuer, subject: identity!.subject, tenantId: this.tenantId });
    } catch { throw new OrganizationLoginError(); }
    finally { if (timer !== undefined) clearTimeout(timer); controller.abort(); slot.release(); }
  }

  private async exchange(code: string, verifier: string, acquisitionSignal: AbortSignal): Promise<string> {
    const secret = clientSecret(this.config.clientSecretFile);
    const encoded = (value: string) => new URLSearchParams({ v: value }).toString().slice(2);
    const response = await (this.ports.fetch ?? fetch)(this.config.tokenEndpoint, { method: "POST", redirect: "error", signal: acquisitionSignal,
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${encoded(this.config.clientId)}:${encoded(secret)}`).toString("base64")}` },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: this.config.redirectUri, code_verifier: verifier }).toString() });
    if (response.status !== 200 || response.redirected || (response.url && response.url !== this.config.tokenEndpoint) || response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !== "application/json" || !response.body) throw new OrganizationLoginError();
    const reader = response.body.getReader(), chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) { const { value, done } = await reader.read(); if (done) break; total += value.length; if (total > this.config.maxResponseBytes) throw new OrganizationLoginError(); chunks.push(value); }
    } finally { if (total > this.config.maxResponseBytes) void reader.cancel().catch(() => undefined); reader.releaseLock(); }
    const body = strictOidcObject(Buffer.concat(chunks));
    if (body.error !== undefined || typeof body.id_token !== "string" || body.id_token.length > 16384) throw new OrganizationLoginError();
    return body.id_token;
  }
}
