/** Native project console. Server-rendered views call the existing gateway contracts;
 * authentication, Host/Origin and CSRF checks belong to review_web. No browser bearer or JS. */
import type { WebRequest, WebResponse } from "./review_web.js";
import type { GatewayResponse } from "../gateway/http_gateway.js";

export type ConsoleApi = (method: "GET" | "POST", path: string, query?: Record<string, string>, body?: Record<string, unknown>) => Promise<GatewayResponse>;
export interface ConsolePermissions { readonly approve: boolean; readonly decline: boolean; }
type Row = Record<string, unknown>;
const row = (value: unknown): Row => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.map(row) : [];
const str = (value: unknown, fallback = "Not recorded"): string => typeof value === "string" ? value : fallback;
const esc = (value: unknown): string => String(value ?? "").replace(/[&<>"']/gu, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const pretty = (value: unknown): string => esc(JSON.stringify(value ?? null, null, 2));
const link = (id: unknown): string => `/console/project?projectId=${encodeURIComponent(String(id))}`;
const badge = (value: unknown): string => `<span class="badge">${esc(value ?? "Not started")}</span>`;
const hidden = (name: string, value: unknown): string => `<input type="hidden" name="${name}" value="${esc(value)}">`;
function diffView(diff: string): string {
  const files = diff.split("\n").filter(line => line.startsWith("+++ b/")).map(line => line.slice(6));
  return `${files.length ? `<ul class="files">${files.map(file => `<li>${esc(file)}</li>`).join("")}</ul>` : ""}<pre class="diff">${diff.split("\n").map(line => `<span class="${line.startsWith("+") ? "added" : line.startsWith("-") ? "removed" : line.startsWith("@@") ? "hunk" : "context"}">${esc(line)}\n</span>`).join("")}</pre>`;
}
const security = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" };
function page(title: string, content: string, status = 200): WebResponse {
  return { status, headers: { ...security, "Content-Type": "text/html; charset=utf-8" }, body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Keep</title><link rel="stylesheet" href="/console/style.css"></head><body><header><a class="brand" href="/console">KEEP<span>Workspace control</span></a><nav><a href="/console">Projects</a></nav></header><main>${content}</main><footer>Keep · Local project console · State and evidence from your running instance</footer></body></html>` };
}
function failure(response: GatewayResponse): WebResponse {
  let message = "The operation could not be confirmed. Inspect current state before retrying.";
  try { message = str(row(JSON.parse(response.body))["error"], message); } catch { /* no raw response markup */ }
  return page("Request held", `<p class="eyebrow">Request held · ${response.status}</p><h1>Keep could not complete that action.</h1><p class="notice">${esc(message)}</p><a href="/console">Return to projects</a>`, response.status);
}
async function read(api: ConsoleApi, path: string, query?: Record<string, string>): Promise<Row | GatewayResponse> {
  const response = await api("GET", path, query);
  if (response.status !== 200) return response;
  return row(JSON.parse(response.body));
}
function isResponse(value: Row | GatewayResponse): value is GatewayResponse { return typeof value["status"] === "number" && typeof value["body"] === "string"; }

export async function handleProjectConsole(req: WebRequest, csrf: string, api: ConsoleApi, permissions: ConsolePermissions): Promise<WebResponse> {
  if (req.path === "/console/style.css" && req.method === "GET") return { status: 200, headers: { ...security, "Content-Type": "text/css; charset=utf-8" }, body: CONSOLE_STYLE };
  if (req.method === "POST" && ["/console/resume", "/console/merge"].includes(req.path)) {
    const form = new URLSearchParams(req.body), runId = form.get("runId") ?? "", projectId = form.get("projectId") ?? "";
    // Bind both the visible project and its current run before forwarding an exact decision.
    const state = await read(api, "/project", { runId });
    if (isResponse(state)) return failure(state);
    if (state["projectId"] !== projectId) return page("Stale decision", "<h1>This decision no longer matches the project.</h1><a href=\"/console\">Reload projects</a>", 409);
    const action = form.get("action");
    let body: Row;
    if (req.path === "/console/resume") {
      const wait = row(row(state["project"])["wait"]);
      if (wait["kind"] !== "approval" || wait["decisionId"] !== form.get("decisionId") || !["approve", "decline"].includes(action ?? ""))
        return page("Stale decision", "<h1>This approval is no longer pending.</h1><a href=\"/console\">Reload projects</a>", 409);
      body = { runId, approval: { decisionId: wait["decisionId"], approved: action === "approve" } };
    } else {
      if (!["approve", "veto"].includes(action ?? "")) return page("Invalid decision", "<h1>Choose approve or veto.</h1>", 400);
      body = { runId, decision: action, proposalDigest: form.get("proposalDigest") };
    }
    const response = await api("POST", req.path === "/console/resume" ? "/project/resume" : "/project/merge", {}, body);
    if (response.status !== 200) return failure(response);
    // Display the actual result. A saved decision, workspace merge and source landing differ.
    const result = row(JSON.parse(response.body));
    return page("Decision result", `<p class="eyebrow">Decision recorded</p><h1>${esc(str(result["status"], "Result recorded"))}</h1><p>${esc(str(result["reason"], str(result["note"], "Inspect the updated project before taking another action.")))}</p><section><h2>Observed result</h2><pre>${pretty(result)}</pre></section><a class="button" href="${esc(link(projectId))}">Open updated project</a>`);
  }
  if (req.method !== "GET") return page("Method not allowed", "<h1>Method not allowed</h1>", 405);
  if (req.path !== "/console" && req.path !== "/console/project") return page("Not found", "<h1>Page not found</h1>", 404);
  const list = await read(api, "/projects");
  if (isResponse(list)) return failure(list);
  const projects = rows(list["projects"]);
  if (req.path === "/console") {
    const attention = projects.filter(p => str(p["status"], "").startsWith("waiting-")).length;
    const cards = projects.map(p => `<a class="project" href="${esc(link(p["id"]))}"><div><p class="eyebrow">${esc(p["lifecycle"])} project</p><h2>${esc(p["name"])}</h2><p class="muted mono">${esc(p["id"])}</p></div><div>${badge(p["status"])}<p class="muted">${p["proposal"] === true ? "Proposal available" : "No proposal recorded"}</p><span>Inspect project →</span></div></a>`).join("");
    return page("Projects", `<p class="eyebrow">Your workspace</p><div class="heading"><div><h1>Work you can inspect.</h1><p class="lede">Follow each project from its goal to its evidence and decision.</p></div><a class="button secondary" href="/console">Refresh state</a></div><div class="metrics"><section><strong>${projects.length}</strong><span>Retained projects</span></section><section><strong>${attention}</strong><span>Waiting for a next step</span></section><section><strong>${projects.filter(p => p["proposal"] === true).length}</strong><span>Recorded proposals</span></section></div><h2 class="section-title">Projects</h2>${cards || '<section class="empty"><h2>Your first project starts here.</h2><p>Submit a repository goal with <code>keep solve</code> or a connected client. Its progress, proposal and decision will appear here.</p></section>'}`);
  }
  const projectId = req.query["projectId"], selected = projects.find(p => p["id"] === projectId);
  if (!selected) return page("Not found", "<h1>Project not found.</h1><a href=\"/console\">Return to projects</a>", 404);
  const jobs = await read(api, "/project/jobs", { projectId: String(projectId) });
  if (isResponse(jobs)) return failure(jobs);
  const runId = selected["runId"];
  const detail = typeof runId === "string" ? await read(api, "/project", { runId }) : {};
  if (isResponse(detail)) return failure(detail);
  const state = row(detail["project"]), wait = row(state["wait"]), proposal = row(detail["proposal"]), checks = row(proposal["checks"]);
  const repository = row(detail["repository"] ?? selected["repository"]), source = row(repository["source"]);
  const sourceMerge = row(source["merge"]), workspace = row(repository["workspace"]);
  let action = `<p>${esc(str(wait["reason"], "No approval is currently pending. Refresh to inspect current state."))}</p>`;
  if (wait["kind"] === "approval" && (permissions.approve || permissions.decline)) action += `<form method="post" action="/console/resume">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("runId", runId)}${hidden("decisionId", wait["decisionId"])}${permissions.approve ? '<button name="action" value="approve">Approve this step</button>' : ""} ${permissions.decline ? '<button class="secondary" name="action" value="decline">Decline</button>' : ""}</form>`;
  const digest = row(proposal["rollback"])["patchSha256"];
  if (typeof digest === "string" && /^[a-f0-9]{64}$/u.test(digest) && (permissions.approve || permissions.decline)) action += `<p>Review the exact diff and checks below before deciding on this proposal.</p><form method="post" action="/console/merge">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("runId", runId)}${hidden("proposalDigest", digest)}${permissions.approve ? '<button name="action" value="approve">Approve exact proposal</button>' : ""} ${permissions.decline ? '<button class="secondary" name="action" value="veto">Veto proposal</button>' : ""}<p class="muted mono">SHA256 ${esc(digest)}</p></form>`;
  const jobRows = rows(jobs["jobs"]);
  const activities: Row[] = [];
  for (const job of jobRows) {
    const observed = await read(api, "/project/jobs", { projectId: String(projectId), jobId: String(job["id"]) });
    if (isResponse(observed)) return failure(observed);
    activities.push(...rows(observed["activities"]));
  }
  const history = rows(row(detail["session"])["history"]);
  return page(str(selected["name"]), `<a class="back" href="/console">← All projects</a><p class="eyebrow">${esc(selected["lifecycle"])} project</p><div class="heading"><div><h1>${esc(selected["name"])}</h1><p class="muted mono">${esc(projectId)}</p></div><a class="button secondary" href="${esc(link(projectId))}">Refresh state</a></div><div class="metrics"><section><span>Current stage</span><strong class="small">${esc(state["stage"] ?? "Not started")}</strong>${badge(state["status"] ?? selected["status"])}</section><section><span>Workspace</span><strong class="small">${esc(workspace["status"] ?? "unknown")}</strong></section><section><span>Source repository</span><strong class="small">${esc(sourceMerge["status"] ?? "unknown")}</strong><span>Last recorded landing outcome</span></section></div><section class="next"><p class="eyebrow">Next action</p><h2>${wait["kind"] === "approval" ? "This step needs your decision." : "Inspect the current result."}</h2>${action}</section><div class="columns"><section><h2>Changed files &amp; diff</h2>${typeof proposal["diff"] === "string" ? diffView(proposal["diff"]) : '<p class="muted">No executed proposal diff is recorded yet.</p>'}</section><section><h2>Repository checks</h2>${typeof checks["testsPassed"] === "boolean" ? `<p>${badge(checks["testsPassed"] ? "Tests passed" : "Tests failed")}</p><p>Vetting: ${checks["vettingCleared"] === true ? "cleared" : "not cleared"}</p><pre>${pretty(checks)}</pre>` : '<p class="muted">No repository check result is recorded yet.</p>'}</section></div><section><h2>Jobs &amp; activity</h2>${jobRows.length ? `<ul class="timeline">${jobRows.map(job => `<li><strong>${esc(job["label"])}</strong> ${badge(job["state"])}<p class="muted">${esc(job["reason"] ?? "No hold or failure reason recorded.")}</p><small class="mono">${esc(job["id"])}</small></li>`).join("")}</ul>` : '<p class="muted">No jobs recorded.</p>'}${activities.length ? `<h3>Observed activity</h3><ul class="timeline">${activities.map(activity => `<li>${esc(activity["label"])} ${badge(activity["state"])}</li>`).join("")}</ul>` : ""}</section><section><h2>Decisions &amp; delivery</h2><p>Latest recorded decision: <strong>${esc(repository["latestDecision"] ?? "None")}</strong></p><ul class="timeline">${(Array.isArray(state["consumedSignals"]) ? state["consumedSignals"] : []).map(signal => `<li class="mono">${esc(signal)}</li>`).join("")}</ul><details><summary>Delivery evidence</summary><pre>${pretty(repository)}</pre></details></section><details><summary>Project conversation &amp; history</summary><pre>${pretty(history)}</pre></details>`);
}

export const CONSOLE_STYLE = `
:root{color-scheme:light;--ink:#172c36;--muted:#5b6f78;--line:#dbe3e5;--paper:#f6f8f7;--accent:#14594e}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--accent);text-underline-offset:4px}header{display:flex;align-items:center;justify-content:space-between;padding:22px max(5vw,24px);background:white;border-bottom:1px solid var(--line)}.brand{font-weight:800;font-size:25px;letter-spacing:.16em;text-decoration:none;color:var(--ink)}.brand span{font-size:12px;letter-spacing:0;font-weight:500;margin-left:22px;color:var(--muted)}nav a{text-decoration:none;font-weight:600}main{max-width:1260px;margin:auto;padding:48px max(4vw,24px)}h1{font-size:clamp(27px,3.5vw,43px);line-height:1.16;letter-spacing:-.04em;margin:8px 0 14px;overflow-wrap:anywhere}h2{font-size:20px;line-height:1.4;margin:0 0 14px}h3{font-size:15px}.eyebrow{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin:0 0 8px}.lede{color:var(--muted);font-size:17px;max-width:670px}.heading{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:30px 0}.metrics section{display:flex;flex-direction:column;gap:5px}.metrics strong{font-size:34px;line-height:1.2}.metrics .small{font-size:21px;overflow-wrap:anywhere}.metrics span{color:var(--muted);font-size:13px}section,details{background:white;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:20px}.metrics section{margin:0}.section-title{margin:36px 0 14px}.project{display:flex;justify-content:space-between;gap:24px;text-decoration:none;color:var(--ink);background:white;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:12px}.project:hover{border-color:var(--accent)}.project>div:last-child{text-align:right;min-width:150px}.project h2{margin-bottom:5px;overflow-wrap:anywhere}.badge{display:inline-block;font-size:12px;font-weight:600;border:1px solid #c8ddd7;background:#eef7f2;color:#245d4c;padding:4px 10px;border-radius:30px}.muted{color:var(--muted)}.mono,pre,code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.mono{overflow-wrap:anywhere}pre{background:#f5f7f7;border:1px solid #e5ebeb;border-radius:7px;padding:16px;overflow:auto;max-height:480px;white-space:pre-wrap;overflow-wrap:anywhere}.diff{white-space:pre;max-height:650px}.added{color:#175b37;background:#e6f4e9}.removed{color:#873532;background:#ffebe9}.hunk{color:#365a97}.files{font:12px/1.8 ui-monospace,monospace;overflow-wrap:anywhere}.timeline{list-style:none;padding:0}.timeline li{padding:12px 0;border-bottom:1px solid var(--line)}.timeline li p{margin:6px 0}.columns{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:20px}.columns section{min-width:0}.next{border-left:4px solid var(--accent)}button,.button{display:inline-block;background:var(--accent);color:white;border:1px solid var(--accent);border-radius:7px;padding:10px 17px;font:600 13px/1.5 system-ui;text-decoration:none;cursor:pointer}.secondary{background:white;color:var(--ink);border-color:var(--line)}input{display:block;width:100%;padding:12px;border:1px solid #a9bbbf;border-radius:7px;margin:8px 0 18px;font:inherit}.back{display:inline-block;margin-bottom:24px}.notice{padding:20px;border-left:3px solid #a46b29;background:#fff4e7}.signin{max-width:560px;margin:10vh auto}.signin .brand{display:block;margin-bottom:32px}.signin p{color:var(--muted)}label{font-size:13px;font-weight:600}.empty{text-align:center;padding:55px 24px}footer{text-align:center;color:var(--muted);font-size:12px;padding:25px;border-top:1px solid var(--line)}summary{cursor:pointer;font-weight:600}a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #b18232;outline-offset:4px}@media(max-width:760px){.brand span{display:none}main{padding-top:30px}.heading,.project{display:block}.heading .button{margin-top:12px}.metrics{gap:8px}.metrics section{padding:16px 12px}.metrics strong{font-size:27px}.columns{grid-template-columns:1fr;gap:0}.project>div:last-child{text-align:left;margin-top:18px}button{margin-bottom:8px}}`;
