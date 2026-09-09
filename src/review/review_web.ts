/**
 * Web review UI — pure request handler (Increment S2). All routing, security, and HTML rendering live here as a
 * PURE function of (app, request, security-config) → response, with no Node `http` dependency, so every security
 * property is unit-testable without opening a socket. The thin socket adapter is review_server.ts.
 *
 * It reuses the exact same core as the CLI: `listPendingReviews` / `needsDecision` to decide what to surface,
 * `buildNonEngineerView` for the plain-language content (single source of truth — the HTML and the CLI text can't
 * drift), and `applyReviewDecision` for the ONE decision path (spine + calibration together). It never merges.
 *
 * Security (SOTA 2026-08-06 — a local decision server is a real attack surface, not a "trusted" one):
 *  - Host-header validation → blocks DNS rebinding, the exact vector behind CVE-2025-66414 (MCP TS SDK, Dec 2025):
 *    a malicious web page can point a name at 127.0.0.1 and POST to your local server unless the Host is checked.
 *  - A per-run token (the Jupyter model — "don't trust localhost because it's local; add authorization anyway").
 *  - SameSite=Strict, HttpOnly cookie once authenticated + an Origin check + a CSRF token on every POST (defense
 *    in depth against localhost CSRF). The server binds 127.0.0.1 only (set in review_server.ts).
 * What would change it: exposing beyond localhost (a team deployment) would add TLS + real auth (X1 SSO) in front;
 * the Host/CSRF/token checks stay as the innermost layer.
 */

import { timingSafeEqual } from "node:crypto";
import type { KeepApp } from "../compose.js";
import { assembleDecisionPacket } from "../cli/decision_packet.js";
import { listPendingReviews, needsDecision, getPacketInputs, applyReviewDecision, isDecided } from "./review_core.js";
import { buildNonEngineerView, type NonEngineerView } from "./non_engineer_view.js";
import { can, type Principal } from "../identity/rbac.js";
import { computeMonitor, type MonitorSnapshot, type TicketState } from "../monitor/solve_monitor.js";
import type { IdentityProviderPort, PrincipalRegistry } from "../identity/identity_provider.js";
import type { SessionStore } from "../identity/session_store.js";

export interface WebRequest {
  readonly method: string;
  readonly path: string;
  readonly query: Readonly<Record<string, string>>;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}
export interface WebResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}
export interface WebSecurity {
  /** The per-run secret required to use the UI (printed at startup). */
  readonly token: string;
  /** The exact same-origin the server serves on, e.g. "http://127.0.0.1:7777". */
  readonly origin: string;
  /** Host header values that are allowed (the DNS-rebinding allowlist), e.g. ["127.0.0.1:7777","localhost:7777"]. */
  readonly allowedHosts: readonly string[];
  /** X0: the acting principal in single-owner mode (N=1 → OWNER). In multi-user mode it is resolved per session. */
  readonly principal: Principal;
  /** X1: present → multi-user mode (IdP login + opaque server-side sessions). Absent → single-owner (N=1). */
  readonly identity?: IdentityLayer;
  /** Injectable clock (tests); defaults to Date.now(). */
  readonly now?: number;
}

export interface IdentityLayer {
  readonly provider: IdentityProviderPort;
  readonly registry: PrincipalRegistry;
  readonly sessions: SessionStore;
}

// ─── constant-time compares + tiny parsers (zero deps) ───

function safeEqual(a: string | undefined, b: string): boolean {
  if (typeof a !== "string") return false;
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function parseForm(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of body.split("&")) {
    if (!pair) continue;
    const i = pair.indexOf("=");
    const k = i >= 0 ? pair.slice(0, i) : pair;
    const v = i >= 0 ? pair.slice(i + 1) : "";
    out[decodeURIComponent(k.replace(/\+/g, " "))] = decodeURIComponent(v.replace(/\+/g, " "));
  }
  return out;
}
function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ─── responses ───

const secHeaders = { "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'" };
function htmlRes(status: number, body: string, extra: Record<string, string> = {}): WebResponse {
  return { status, headers: { "Content-Type": "text/html; charset=utf-8", ...secHeaders, ...extra }, body };
}
function textRes(status: number, body: string): WebResponse {
  return { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...secHeaders }, body };
}
function redirect(to: string, extra: Record<string, string> = {}): WebResponse {
  return { status: 303, headers: { Location: to, ...secHeaders, ...extra }, body: "" };
}

/** The pure handler. Order matters: Host guard → token → routing (POST also does Origin + CSRF). */
/** The pure handler. Two modes: single-owner (per-run token → owner, N=1) or multi-user (sessions + IdP login). */
export async function handleReviewRequest(app: KeepApp, req: WebRequest, sec: WebSecurity): Promise<WebResponse> {
  // 1) DNS-rebinding guard — reject any Host we did not bind (CVE-2025-66414 defense).
  if (!sec.allowedHosts.includes(req.headers["host"] ?? "")) return textRes(403, "Forbidden: unexpected Host header.");
  return sec.identity ? handleMultiUser(app, req, sec, sec.now ?? Date.now()) : handleSingleOwner(app, req, sec);
}

/** N=1 / single-owner: the per-run token authenticates the owner. Unchanged behavior. */
function handleSingleOwner(app: KeepApp, req: WebRequest, sec: WebSecurity): WebResponse {
  const cookies = parseCookies(req.headers["cookie"]);
  const cookieOk = safeEqual(cookies["keep_token"], sec.token);
  const queryOk = safeEqual(req.query["token"], sec.token);
  if (!cookieOk && !queryOk) {
    return textRes(401, "Unauthorized. Start Keep with `keep serve` and open the printed URL (it contains your token).");
  }
  if (!cookieOk && queryOk && req.method === "GET") {
    const cookie = `keep_token=${encodeURIComponent(sec.token)}; Path=/; HttpOnly; SameSite=Strict`;
    return redirect(req.path === "/" ? "/" : req.path, { "Set-Cookie": cookie });
  }
  return route(app, req, sec, sec.principal, sec.token, false);
}

/** Multi-user: login via the IdP → an opaque server-side session bound to the person's principal. */
async function handleMultiUser(app: KeepApp, req: WebRequest, sec: WebSecurity, now: number): Promise<WebResponse> {
  const id = sec.identity!;
  const secureFlag = sec.origin.startsWith("https://") ? "; Secure" : "";

  if (req.path === "/login" && req.method === "GET") return htmlRes(200, renderLoginPage());
  if (req.path === "/login" && req.method === "POST") {
    if (!originOk(req, sec)) return textRes(403, "Forbidden: cross-origin request refused.");
    const assertion = parseForm(req.body)["assertion"] ?? "";
    const identity = await id.provider.verify(assertion, now);
    if (!identity) return htmlRes(401, renderLoginPage("That sign-in could not be verified. Please try again."));
    const principal = id.registry.resolve(identity);
    if (!principal) {
      app.spine.stage({ type: "identity.action", actor: "rbac", payload: { event: "authz.denied", who: identity.subject, action: "login", reason: "no role assigned to this identity", ts: now } });
      return htmlRes(403, renderLoginPage("Your account is not authorized for this Keep. Ask the owner to grant you a role."));
    }
    const session = id.sessions.create(principal, now); // fresh id on login → anti-fixation
    const cookie = `keep_session=${session.id}; Path=/; HttpOnly; SameSite=Strict${secureFlag}`;
    return redirect("/", { "Set-Cookie": cookie });
  }

  const cookies = parseCookies(req.headers["cookie"]);
  if (req.path === "/logout" && req.method === "POST") {
    const sid = cookies["keep_session"];
    if (sid) id.sessions.revoke(sid); // destroy server-side, not just the cookie
    return redirect("/login", { "Set-Cookie": `keep_session=; Path=/; HttpOnly; SameSite=Strict${secureFlag}; Max-Age=0` });
  }

  const session = id.sessions.get(cookies["keep_session"], now);
  if (!session) {
    if (req.path === "/style.css") return { status: 200, headers: { "Content-Type": "text/css; charset=utf-8", ...secHeaders }, body: STYLE };
    return req.method === "GET" ? redirect("/login") : textRes(401, "Unauthorized: please sign in.");
  }
  return route(app, req, sec, session.principal, session.csrfToken, true);
}

function originOk(req: WebRequest, sec: WebSecurity): boolean {
  const origin = req.headers["origin"];
  const referer = req.headers["referer"];
  return (origin !== undefined && origin === sec.origin) || (origin === undefined && referer !== undefined && referer.startsWith(sec.origin + "/"));
}

/** Shared routing for both modes, given the resolved acting principal + the CSRF token to enforce. */
function route(app: KeepApp, req: WebRequest, sec: WebSecurity, principal: Principal, csrf: string, loggedIn: boolean): WebResponse {
  if (req.method === "GET" && req.path === "/") return htmlRes(200, renderListPage(app, principal, loggedIn));
  if (req.method === "GET" && req.path === "/style.css") {
    return { status: 200, headers: { "Content-Type": "text/css; charset=utf-8", ...secHeaders }, body: STYLE };
  }
  if (req.method === "GET" && req.path === "/monitor") {
    if (!can(app.authorization, principal, "review.view")) return textRes(403, "Forbidden: you do not have view access.");
    return htmlRes(200, renderMonitorPage(app, loggedIn));
  }
  const detail = /^\/review\/([^/]+)$/.exec(req.path);
  if (req.method === "GET" && detail) return renderDetailPage(app, decodeURIComponent(detail[1]!), csrf, can(app.authorization, principal, "review.approve"), loggedIn);

  const decide = /^\/review\/([^/]+)\/decide$/.exec(req.path);
  if (decide && req.method === "POST") {
    if (!originOk(req, sec)) return textRes(403, "Forbidden: cross-origin request refused.");
    const form = parseForm(req.body);
    if (!safeEqual(form["csrf"], csrf)) return textRes(403, "Forbidden: missing or invalid CSRF token.");
    const id = decodeURIComponent(decide[1]!);
    const action = form["action"];
    if (action !== "approve" && action !== "decline") return textRes(400, "Bad request: action must be approve or decline.");
    const outcome = applyReviewDecision(app, id, action === "approve", Date.now(), principal); // shared path + RBAC
    if (outcome.reason === "forbidden") return textRes(403, "Forbidden: your role does not permit deciding on changes.");
    return redirect("/");
  }
  if (decide && req.method === "GET") return textRes(405, "Method not allowed.");

  return textRes(404, "Not found.");
}

// ─── HTML rendering (from the shared structured view) ───

function page(title: string, inner: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><link rel="stylesheet" href="/style.css"></head><body><main>${inner}</main></body></html>`;
}

/** A small "signed in as … · Log out" header, shown only in multi-user mode. */
function sessionHeader(principal: Principal, loggedIn: boolean): string {
  if (!loggedIn) return "";
  const who = esc(principal.displayName ?? principal.id);
  return `<div class="whoami">Signed in as <strong>${who}</strong> <span class="muted">(${esc(principal.role)})</span> ${logoutForm()}</div>`;
}
function logoutForm(): string {
  return `<form method="POST" action="/logout" class="logout"><button type="submit">Log out</button></form>`;
}

/** The sign-in page (multi-user mode). The real IdP redirect/callback plugs in behind the provider port; this
 *  page accepts a verified assertion for the built-in provider and is where an "Sign in with…" button would live. */
function renderLoginPage(error?: string): string {
  const err = error ? `<p class="err">${esc(error)}</p>` : "";
  const inner = `<h1>Sign in to Keep</h1>${err}
<form method="POST" action="/login" class="login">
  <label for="assertion">Sign-in assertion</label>
  <input id="assertion" name="assertion" type="text" autocomplete="off" placeholder="paste your signed sign-in assertion">
  <button type="submit">Sign in</button>
</form>
<p class="muted">Your organization's identity provider issues this assertion. Access is limited to people the owner has given a role.</p>`;
  return page("Sign in — Keep", inner);
}

function renderMonitorPage(app: KeepApp, loggedIn: boolean): string {
  const snap: MonitorSnapshot = computeMonitor(app.spine.currentEvents(), Date.now());
  const mins = (ms: number) => `${Math.round(ms / 60000)}m`;
  const phaseLabel: Record<string, string> = { "solving": "solving", "awaiting-review": "needs decision", "deferred-to-human": "deferred to a human", "decided": "decided", "completed": "done", "dead-lettered": "dead-lettered", "rejected": "rejected" };
  let inner = sessionHeader({ id: "", kind: "human", role: "viewer" } as Principal, loggedIn);
  inner += `<p class="back"><a href="/">← Changes to review</a></p><h1>Work in flight</h1>`;
  if (snap.tickets.length === 0) return page("Keep — monitor", inner + `<p class="empty">Nothing in flight.</p>`);
  inner += `<p class="muted">In flight ${snap.inFlight} · needs attention ${snap.needsAttention.length} · stuck ${snap.counts.stuck}${snap.totalCostUsd > 0 ? ` · $${snap.totalCostUsd.toFixed(2)}` : ""}</p>`;
  const row = (t: TicketState): string => {
    const cls = t.needsAttention ? "attn" : "";
    const flags = [t.stuck ? `stuck ${mins(t.idleMs)}` : "", t.escalations > 0 ? `${t.escalations}×esc` : "", t.costUsd > 0 ? `$${t.costUsd.toFixed(2)}` : ""].filter(Boolean).join(" · ");
    return `<li class="mon ${cls}"><span class="badge ${t.needsAttention ? "decide" : "auto"}">${esc(phaseLabel[t.phase] ?? t.phase)}</span> ${esc(t.issueId)}${flags ? ` <span class="muted">${esc(flags)}</span>` : ""}</li>`;
  };
  const attn = snap.tickets.filter((t) => t.needsAttention);
  const rest = snap.tickets.filter((t) => !t.needsAttention);
  if (attn.length > 0) inner += `<h2>Needs attention</h2><ul class="reviews">${attn.map(row).join("")}</ul>`;
  if (rest.length > 0) inner += `<h2>Everything else</h2><ul class="reviews">${rest.map(row).join("")}</ul>`;
  return page("Keep — monitor", inner);
}

function renderListPage(app: KeepApp, principal: Principal, loggedIn: boolean): string {
  const all = listPendingReviews(app);
  const needs = all.filter(needsDecision);
  const auto = all.filter((m) => !needsDecision(m));
  let inner = sessionHeader(principal, loggedIn) + `<h1>Keep — changes to review</h1><p class="back"><a href="/monitor">See all work in flight →</a></p>`;
  if (all.length === 0) {
    inner += `<p class="empty">Nothing is waiting for you right now.</p>`;
    return page("Keep — review", inner);
  }
  if (needs.length > 0) {
    inner += `<h2>Needs your decision</h2><ul class="reviews">`;
    for (const m of needs) inner += `<li><a href="/review/${encodeURIComponent(m.id)}"><span class="badge decide">Decision</span> ${esc(m.title ?? m.id)}</a></li>`;
    inner += `</ul>`;
  }
  if (auto.length > 0) {
    inner += `<h2>Auto-approved <span class="muted">(optional to review — these passed Keep's checks)</span></h2><ul class="reviews">`;
    for (const m of auto) inner += `<li><a href="/review/${encodeURIComponent(m.id)}"><span class="badge auto">Auto</span> ${esc(m.title ?? m.id)}</a></li>`;
    inner += `</ul>`;
  }
  return page("Keep — review", inner);
}

function renderDetailPage(app: KeepApp, id: string, csrf: string, mayDecide: boolean, loggedIn: boolean): WebResponse {
  const inputs = getPacketInputs(app, id);
  if (!inputs) return htmlRes(404, page("Not found", `<h1>Not found</h1><p>No review with that id is pending. <a href="/">Back</a></p>`));
  const view = buildNonEngineerView(assembleDecisionPacket(inputs));
  const decided = isDecided(app, id);
  return htmlRes(200, page("Keep — review", renderView(id, view, decided, csrf, mayDecide, loggedIn)));
}

function renderView(id: string, v: NonEngineerView, decided: boolean, csrf: string, mayDecide: boolean, loggedIn: boolean): string {
  const L: string[] = [];
  if (loggedIn) L.push(logoutForm());
  L.push(`<p class="back"><a href="/">← All changes</a></p>`);
  // Disposition FIRST, never hidden.
  const cls = v.disposition === "blocked" ? "stopped" : v.disposition === "auto-approved" ? "auto" : "decide";
  L.push(`<div class="headline ${cls}">${esc(v.headline)}</div>`);
  L.push(`<h2>What it does</h2><p>${esc(v.whatItDoes)}</p>`);
  if (v.checked.length > 0) {
    L.push(`<h2>What Keep already checked for you</h2><ul class="checked">`);
    for (const f of v.checked) L.push(`<li><strong>${esc(f.label)}:</strong> ${esc(f.value)}</li>`);
    L.push(`</ul>`);
  }
  L.push(`<h2>Can it be undone?</h2><p>${esc(v.reversalText)}</p>`);
  if (v.affects) L.push(`<p class="affects">What it affects: ${esc(v.affects)}</p>`);
  if (v.onlyYou) {
    L.push(`<h2>What only you can decide</h2><ul class="onlyyou">`);
    for (const item of v.onlyYou) L.push(`<li>${esc(item)}</li>`);
    L.push(`</ul>`);
  }
  if (v.confidenceText) L.push(`<p class="confidence">${esc(v.confidenceText)}</p>`);
  if (v.framing) L.push(`<p class="framing">${esc(v.framing)}</p>`);

  // The decision control — only for items that need one, and only if not already decided.
  if (v.needsDecision && v.disposition !== "blocked" && !mayDecide) {
    L.push(`<p class="note">You have view-only access. Someone with approval rights needs to decide on this change.</p>`);
  } else if (v.needsDecision && v.disposition !== "blocked") {
    if (decided) {
      L.push(`<p class="done">You've already recorded a decision on this change.</p>`);
    } else {
      L.push(`<form method="POST" action="/review/${encodeURIComponent(id)}/decide" class="decide">
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <button type="submit" name="action" value="approve" class="approve">Approve</button>
  <button type="submit" name="action" value="decline" class="decline">Decline</button>
</form>
<p class="note">Approving records your decision. Merging remains a separate, manual step — Keep never merges on its own.</p>`);
    }
  }
  return L.join("\n");
}

const STYLE = `
:root{--fg:#1a1a1a;--muted:#666;--line:#e2e2e2;--decide:#b45309;--auto:#15803d;--stop:#b91c1c;--bg:#fafafa}
*{box-sizing:border-box}body{font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0}
main{max-width:720px;margin:0 auto;padding:32px 20px}
h1{font-size:1.5rem;margin:0 0 1rem}h2{font-size:1.05rem;margin:1.5rem 0 .4rem}
a{color:#1d4ed8}.back a,.empty{color:var(--muted)}
ul.reviews{list-style:none;padding:0}ul.reviews li{border:1px solid var(--line);border-radius:8px;margin:.5rem 0;background:#fff}
ul.reviews a{display:block;padding:.8rem 1rem;text-decoration:none;color:var(--fg)}
.badge{display:inline-block;font-size:.72rem;font-weight:700;padding:.1rem .45rem;border-radius:99px;margin-right:.5rem;vertical-align:middle}
.badge.decide{background:#fef3c7;color:var(--decide)}.badge.auto{background:#dcfce7;color:var(--auto)}
.muted{color:var(--muted);font-weight:400;font-size:.9rem}
.headline{padding:.9rem 1rem;border-radius:8px;font-weight:600;margin:.5rem 0 1rem;border:1px solid var(--line);background:#fff}
.headline.decide{border-left:5px solid var(--decide)}.headline.auto{border-left:5px solid var(--auto)}.headline.stopped{border-left:5px solid var(--stop)}
ul.checked,ul.onlyyou{padding-left:1.2rem}.confidence,.affects{color:var(--muted);font-size:.95rem}
.framing{margin-top:1rem;padding:.8rem 1rem;background:#fff;border:1px solid var(--line);border-radius:8px}
form.decide{display:flex;gap:.75rem;margin:1.25rem 0 .5rem}
button{font:inherit;font-weight:600;padding:.6rem 1.4rem;border-radius:8px;border:1px solid var(--line);cursor:pointer}
button.approve{background:#1d4ed8;color:#fff;border-color:#1d4ed8}button.decline{background:#fff;color:var(--fg)}
.note,.done{color:var(--muted);font-size:.9rem}
.whoami{display:flex;align-items:center;gap:.6rem;font-size:.9rem;color:var(--muted);margin-bottom:1rem}
.logout button{padding:.3rem .8rem;font-size:.85rem;font-weight:600}
form.login{display:flex;flex-direction:column;gap:.5rem;max-width:420px;margin:1rem 0}
form.login input{font:inherit;padding:.6rem;border:1px solid var(--line);border-radius:8px}
.err{color:var(--stop);font-weight:600}
`;
