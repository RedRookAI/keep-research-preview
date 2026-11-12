/** Native project console. Server-rendered views call the existing gateway contracts;
 * authentication, Host/Origin and CSRF checks belong to review_web. No browser bearer or JS. */
import type { WebRequest, WebResponse } from "./review_web.js";
import type { GatewayResponse } from "../gateway/http_gateway.js";
import { randomUUID } from "node:crypto";
import { SAMPLE_SUBMISSION_KEY, SAMPLE_CHECK_NAMES } from "./reviewer_sample.js";

export type ConsoleApi = (method: "GET" | "POST", path: string, query?: Record<string, string>, body?: Record<string, unknown>) => Promise<GatewayResponse>;
export interface ConsolePermissions { readonly approve: boolean; readonly decline: boolean; readonly cancel?: boolean; readonly submit?: boolean; }
type Row = Record<string, unknown>;
const row = (value: unknown): Row => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.map(row) : [];
const str = (value: unknown, fallback = "Not recorded"): string => typeof value === "string" ? value : fallback;
const esc = (value: unknown): string => String(value ?? "").replace(/[&<>"']/gu, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const pretty = (value: unknown): string => esc(JSON.stringify(value ?? null, null, 2));
const link = (id: unknown): string => `/console/project?projectId=${encodeURIComponent(String(id))}`;
const badge = (value: unknown): string => `<span class="badge">${esc(value ?? "Not started")}</span>`;
const hidden = (name: string, value: unknown): string => `<input type="hidden" name="${name}" value="${esc(value)}">`;
function jobView(job: Row, projectId: unknown, csrf: string, mayCancel: boolean): string {
  const active = job["state"] === "queued" || job["state"] === "running";
  const cancellation = job["cancellationRequested"] === true
    ? '<p class="notice">Cancellation was requested. Inspect the current state and activity; this does not prove remote work stopped.</p>'
    : active && mayCancel
      ? `<form method="post" action="/console/cancel">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("jobId", job["id"])}<button class="secondary">Request cancellation</button><p class="muted">Applies to this job only. Cancellation does not undo effects or prove remote work stopped.</p></form>`
      : "";
  return `<li><strong>${esc(job["label"])}</strong> ${badge(job["state"])}<p class="muted">${esc(job["reason"] ?? "No hold or failure reason recorded.")}</p><small class="mono">${esc(job["id"])}</small>${cancellation}</li>`;
}
function diffView(diff: string): string {
  const files = diff.split("\n").filter(line => line.startsWith("+++ b/")).map(line => line.slice(6));
  return `${files.length ? `<ul class="files">${files.map(file => `<li>${esc(file)}</li>`).join("")}</ul>` : ""}<pre class="diff">${diff.split("\n").map(line => `<span class="${line.startsWith("+") ? "added" : line.startsWith("-") ? "removed" : line.startsWith("@@") ? "hunk" : "context"}">${esc(line)}\n</span>`).join("")}</pre>`;
}
const security = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin", "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" };
function page(title: string, content: string, status = 200, refresh = false): WebResponse {
  return { status, headers: { ...security, "Content-Type": "text/html; charset=utf-8" }, body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Keep</title>${refresh ? '<meta http-equiv="refresh" content="2">' : ""}<link rel="stylesheet" href="/console/style.css"></head><body><header><a class="brand" href="/console">KEEP<span>Workspace control</span></a><nav><a href="/console">Projects</a></nav></header><main>${content}</main><footer>Keep · Local project console · State and evidence from your running instance</footer></body></html>` };
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
const submissionKeyValid = (key: string): boolean => /^[A-Za-z0-9._:-]{16,128}$/u.test(key);
function submissionForm(csrf: string, key: string, goal = "", fixed = false): string {
  return `<form method="post" action="/console/submit">${hidden("csrf", csrf)}${hidden("idempotencyKey", key)}<label for="goal">Repository goal</label><textarea id="goal" name="goal" rows="6" maxlength="16000" required${fixed ? " readonly" : ""}>${esc(goal)}</textarea><p>${fixed ? "Submit this sample to inspect its actual code change, checks and proposal." : "Uses this owner's configured repository, checker, provider and execution limits. Describe one bounded change and its acceptance checks."}</p><button>Submit goal</button></form><details><summary>Recover this submission</summary><p>${fixed ? "This instance retains one sample. Submit this fixed goal again from any sample form to recover its original job. Inspect retained projects for its current result. A stopped or uncertain sample stays retained for the operator to reconcile." : "Keep this page and goal text until the job appears. If a response is lost, return to this form and submit the unchanged goal with this same key. Keep will recover the original job. Inspect retained projects before starting another submission."}</p>${fixed ? "" : `<p class="mono">Submission key: ${esc(key)}</p>`}<a href="/console">Inspect retained projects</a></details>`;
}
function workerNotice(list: Row): string {
  const runtime = row(list["runtime"]);
  if (runtime["available"] === false) return '<p class="notice">Durable worker unavailable. Ask the owner to start the configured instance before submitting work.</p>';
  if (runtime["softwareConfigured"] === false) return '<p class="notice">Repository solver is unconfigured. The owner must save repository, provider and checker setup, then restart the instance.</p>';
  return runtime["paused"] === true ? '<p class="notice">Worker dispatch is paused. Jobs remain queued until the owner resumes the worker. Refresh to inspect its state.</p>' : "";
}

export interface ConsoleSample { readonly goal: string; readonly notice: string; readonly workspaceOnly?: boolean; }
function demoSteps(current: number): string {
  return `<ol class="demo-route" aria-label="Demo stages">${["Start", "Prepare the fix", "Review", "Decision"].map((step, i) => `<li${i + 1 === current ? ' aria-current="step"' : ""}>${step}</li>`).join("")}</ol>`;
}
const demoScope = '<p class="scope">This sample remembers processed delivery IDs in memory. It demonstrates duplicate handling within one running state. Production exactly-once delivery is outside this demonstration.</p>';
function sampleLanding(sample: ConsoleSample, list: Row, csrf: string, permissions: ConsolePermissions, suppliedKey?: string): string {
  const retained = rows(list["projects"])[0];
  const key = suppliedKey && submissionKeyValid(suppliedKey) ? suppliedKey : SAMPLE_SUBMISSION_KEY;
  const form = permissions.submit ? `<form method="post" action="/console/submit">${hidden("csrf", csrf)}${hidden("goal", sample.goal)}${hidden("idempotencyKey", key)}<button>${retained ? "Recover demo" : "Start demo"}</button></form>` : '<p class="notice">Demo submission is held by the current owner permissions.</p>';
  return `${demoSteps(1)}<p class="eyebrow">A guided repository task</p><h1>Count each delivery once.</h1><p class="intro">Apps sometimes send the same event again. This sample counts a repeated delivery twice. Keep will prepare a small fix and run the checks. You decide whether to approve or veto the proposal.</p>${workerNotice(list)}${retained ? `<div class="demo-actions"><a class="button" href="${esc(link(retained["id"]))}">Continue demo</a></div><p>Your task is retained. Return to its current result and decision.</p><details><summary>Recover the existing submission</summary><p>This recovers the same demo. It starts no additional response pair.</p>${form}</details>` : `<div class="demo-actions">${form}</div><p>Start opens the task. You'll approve preparation next.</p>`}<section><h2>The behavior we want</h2><div class="demo-example"><article><span>Delivery A arrives</span><strong>Count: 1</strong></article><article><span>Delivery A arrives again</span><strong>Count stays: 1</strong></article><article><span>A different delivery B arrives</span><strong>Count: 2</strong></article></div><p>These are the task's expected results. The next steps will run the code and show the actual checks.</p></section>${demoScope}<details><summary>Task and technical scope</summary><p>${esc(sample.goal)}</p><p>Keep uses the prepared synthetic repository, authored responses and fixed executable checks. The job and exact proposal are retained for review.</p></details>`;
}
function sampleResultCopy(result: Row, sample: ConsoleSample): { title: string; message: string } {
  if (result["decision"] === "veto" && result["status"] === "refused") return { title: "Proposal vetoed.", message: "Keep recorded your veto of this exact proposal. The generated workspace and check results remain available as evidence; the veto does not apply the change to the source repository." };
  if (result["status"] === "merged") {
    const sourceStatus = row(result["sourceDelivery"])["status"];
    if (sourceStatus === "landed") return { title: "Change applied to the demo source.", message: "Keep recorded the exact proposal's landing in this synthetic source repository. Download the diff, checks and decision below." };
    if (sample.workspaceOnly) return { title: "Change approved in the demo workspace.", message: "The reviewed workspace is retained. This local sample leaves the source repository unchanged. Download the diff, checks and decision below." };
    return { title: "Workspace approved; inspect source delivery.", message: "The workspace merge was recorded. Source delivery is not confirmed here; inspect the recorded outcome before another attempt." };
  }
  return { title: "The decision needs attention.", message: str(result["reason"], "Inspect the recorded result before taking another action.") };
}
function sampleEvidenceLink(runId: unknown, digest: unknown): string {
  return typeof runId === "string" && typeof digest === "string" && /^[a-f0-9]{64}$/u.test(digest)
    ? `<a class="button" href="/console/export?runId=${encodeURIComponent(runId)}&amp;proposalDigest=${digest}">Download evidence</a>` : "";
}
function sampleDecision(result: Row, projectId: string, runId: string, digest: string, sample: ConsoleSample): string {
  const copy = sampleResultCopy(result, sample);
  return `${demoSteps(4)}<p class="eyebrow">Your proposal decision</p><h1>${esc(copy.title)}</h1><p class="intro">${esc(copy.message)}</p><section><h2>Take the evidence with you.</h2><p>The export contains the exact diff, pinned source, executed check results and recorded decision. It lets you inspect this same proposal later.</p><div class="demo-actions">${sampleEvidenceLink(runId, digest)}<a class="button secondary" href="${esc(link(projectId))}">Review retained demo</a></div></section>${demoScope}<details><summary>Technical decision result</summary><pre>${pretty(result)}</pre></details>`;
}
function sampleProject(detail: Row, list: Row, jobs: Row, projectId: string, csrf: string, permissions: ConsolePermissions, sample: ConsoleSample): WebResponse {
  const state = row(detail["project"]), wait = row(state["wait"]), proposal = row(detail["proposal"]), checks = row(proposal["checks"]);
  const jobRows = rows(jobs["jobs"]), runtime = row(list["runtime"]), repository = row(detail["repository"]);
  const runId = str(state["runId"], str(rows(list["projects"]).find(p => p["id"] === projectId)?.["runId"], "")), digest = row(proposal["rollback"])["patchSha256"];
  const outcome = rows(detail["decisionHistory"]).filter(decision => str(decision["event"], "").startsWith("local_merge.")).at(-1);
  const unresolved = jobRows.some(job => job["state"] === "reconciliation-required");
  const failedResume = jobRows.filter(job => job["label"] === "autonomy project resume").at(-1);
  const resumeNeedsInspection = ["failed", "stopped"].includes(str(failedResume?.["state"], ""));
  const resuming = jobRows.some(job => job["label"] === "autonomy project resume" && ["queued", "running"].includes(str(job["state"])));
  const active = !unresolved && runtime["paused"] !== true && (resuming || !wait["kind"] && !str(state["status"], "").startsWith("waiting-")) && jobRows.some(job => ["queued", "running"].includes(str(job["state"])));
  const ready = typeof proposal["diff"] === "string" && !active;
  const phase = outcome ? 4 : ready ? 3 : 2;
  let title: string, message: string, controls = "";
  if (outcome) {
    const copy = sampleResultCopy({ ...outcome, status: str(outcome["event"], "").split(".").at(-1), sourceDelivery: row(row(repository["source"])["merge"]) }, sample);
    title = copy.title; message = copy.message;
    controls = `<p>The evidence contains the exact diff, pinned source, check results and your recorded decision.</p><div class="demo-actions">${sampleEvidenceLink(runId, digest)}</div>`;
  } else if (unresolved || runtime["paused"] === true) {
    title = unresolved ? "This demo needs reconciliation." : "The demo worker is paused.";
    message = unresolved ? str(jobRows.find(job => job["state"] === "reconciliation-required")?.["reason"], "Ask the operator to reconcile the retained work before another attempt.") : "Your job is retained. The operator must resume the worker before it can continue.";
  } else if (resumeNeedsInspection) {
    title = "The demo needs attention.";
    message = str(failedResume?.["reason"], "Preparation did not complete. Ask the operator to inspect the retained job before another attempt.");
    controls = '<p>Preparation is held. Ask the operator to inspect this job; opening a new form will recover the same demo.</p>';
  } else if (wait["kind"] === "approval" && !resuming) {
    title = "Ready to prepare the fix.";
    message = "Keep is waiting for your approval before it edits the sample workspace and runs the checks.";
    controls = `<form class="demo-actions" method="post" action="/console/resume">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("runId", runId)}${hidden("decisionId", wait["decisionId"])}${permissions.approve ? '<button name="action" value="approve">Prepare the fix</button>' : ""}${permissions.decline ? '<button class="secondary" name="action" value="decline">Decline preparation</button>' : ""}</form><p>The prepared change will come back to you for a separate proposal decision.</p>`;
  } else if (ready && !unresolved && !wait["kind"]) {
    title = checks["testsPassed"] === true && checks["vettingCleared"] === true ? "Review the checked change." : "The checks need attention.";
    message = "The proposal records each delivery ID before updating the count. Review the actual results and code change below.";
    const effect = sample.workspaceOnly ? "Approval retains this exact proposal in the demo workspace. The source repository stays unchanged." : "Approval asks Keep to apply this exact proposal to the synthetic source repository. The next view reports the actual result.";
    controls = `<p>${effect} Veto records your decision to stop this proposal.</p><form class="demo-actions" method="post" action="/console/merge">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("runId", runId)}${hidden("proposalDigest", digest)}${permissions.approve ? '<button name="action" value="approve">Approve this proposal</button>' : ""}${permissions.decline ? '<button class="secondary" name="action" value="veto">Veto this proposal</button>' : ""}</form>`;
  } else if (active) {
    title = state["stage"] === "vet_artifact" ? "Checking the change." : "Preparing and checking the fix.";
    message = "Keep is working in the sample workspace. This view refreshes the recorded state while work is active. You can leave and return to this same task.";
  } else {
    title = unresolved ? "This demo needs reconciliation." : runtime["paused"] === true ? "The demo worker is paused." : "The demo needs attention.";
    message = str(wait["reason"] ?? state["note"], str(jobRows.find(job => job["reason"])?.["reason"], "Ask the operator to inspect the retained job before another attempt."));
    if (runtime["paused"] === true) message = "Your job is retained. The operator must resume the worker before it can continue.";
  }
  const passed = Array.isArray(checks["passedTests"]) ? checks["passedTests"].filter((value): value is string => typeof value === "string") : [];
  const failed = Array.isArray(checks["failures"]) ? checks["failures"].filter((value): value is string => typeof value === "string") : [];
  const names = [...SAMPLE_CHECK_NAMES, "goal: requested outcome"];
  const resultList = `<ul class="demo-checks">${names.map(name => `<li><span>${esc(name === "goal: requested outcome" ? "Independent goal check" : name)}</span><strong class="${passed.includes(name) ? "demo-success" : failed.includes(name) ? "demo-error" : "muted"}">${passed.includes(name) ? "Passed" : failed.includes(name) ? "Failed" : "Not recorded"}</strong></li>`).join("")}</ul>`;
  const stageCopy: Readonly<Record<string, string>> = { understand: "Opening the prepared task.", research: "Checking the task context.", rag: "Reading the repository context.", plan: "Preparing the change plan.", vet_plan: "Checking the plan.", ticket: "Recording the bounded task.", implement: "Preparing the code change and running repository checks.", vet_artifact: "Running the independent check.", learn: "Saving the result.", done: "Task processing finished." };
  const useful = ready || outcome ? `<section><h2>Actual check results</h2>${resultList}<p class="muted">${checks["testsPassed"] === true ? "Repository tests passed." : checks["testsPassed"] === false ? "Repository tests failed." : "Repository test result is unavailable."} ${checks["vettingCleared"] === true ? "Artifact vetting cleared." : "Artifact vetting is not cleared."}</p><details><summary>Inspect the code change</summary>${diffView(str(proposal["diff"], "No diff recorded."))}</details></section>` : "";
  return page("Webhook delivery demo", `${demoSteps(phase)}<a class="back" href="/console">← Demo overview</a><p class="eyebrow">Count each delivery once</p><h1>${esc(title)}</h1><p class="intro">${esc(message)}</p>${useful}<section class="next"><h2>${outcome ? "Your retained decision" : active ? "Current work" : wait["kind"] === "approval" ? "You control preparation" : ready ? "You control the proposal" : "Current work"}</h2>${controls || `<p>${active ? esc(stageCopy[str(state["stage"], "")] ?? "Waiting for the worker to start this job.") : "The job state is retained."}</p><a class="button secondary" href="${esc(link(projectId))}">Refresh status</a>`}</section>${demoScope}<details><summary>Job, decision and technical evidence</summary><pre>${pretty({ projectId, runId, proposalDigest: digest, stage: state["stage"], status: state["status"], jobs: jobRows, checks, repository, decisions: detail["decisionHistory"] })}</pre></details>`, 200, active);
}

export async function handleProjectConsole(req: WebRequest, csrf: string, api: ConsoleApi, permissions: ConsolePermissions, sample?: ConsoleSample): Promise<WebResponse> {
  const response = await routeProjectConsole(req, csrf, api, permissions, sample);
  return sample && response.headers["Content-Type"]?.startsWith("text/html")
    ? { ...response, body: response.body.replace("<main>", `<main class="guided-demo"><p class="sample-disclosure" role="note">${esc(sample.notice)}</p>`).replace('Workspace control</span>', 'Guided demo</span>').replace('<a href="/console">Projects</a>', '<a href="/console">Demo</a>') } : response;
}
async function routeProjectConsole(req: WebRequest, csrf: string, api: ConsoleApi, permissions: ConsolePermissions, sample?: ConsoleSample): Promise<WebResponse> {
  if (req.path === "/console/style.css" && req.method === "GET") return { status: 200, headers: { ...security, "Content-Type": "text/css; charset=utf-8" }, body: CONSOLE_STYLE };
  if (req.path === "/console/export" && req.method === "GET") {
    const response = await api("GET", "/project/export", { runId: req.query["runId"] ?? "", proposalDigest: req.query["proposalDigest"] ?? "" });
    if (response.status !== 200) return failure(response);
    return { status: 200, headers: { ...security, "Content-Type": "application/json; charset=utf-8", "Content-Disposition": 'attachment; filename="keep-proposal.json"' }, body: response.body };
  }
  if (req.path === "/console/submit" && req.method === "POST") {
    if (!permissions.submit) return page("Forbidden", "<h1>You cannot submit project goals.</h1>", 403);
    const form = new URLSearchParams(req.body), key = form.get("idempotencyKey") ?? "", goal = form.get("goal") ?? "";
    if (sample && (goal !== sample.goal || [...form.keys()].some((name, index, all) => !["csrf", "goal", "idempotencyKey"].includes(name) || all.indexOf(name) !== index)))
      return page("Sample request held", '<h1>This sample admits only its fixed repository goal.</h1><a href="/console/new">Open the sample goal</a>', 400);
    if (!submissionKeyValid(key)) return page("Invalid submission", '<h1>Submission key is missing or invalid.</h1><a href="/console">Inspect retained projects before starting another submission</a>', 400);
    if (!goal.trim() || goal.length > 16000) return page("Invalid goal", `<h1>Enter a goal of at most 16,000 characters.</h1>${submissionForm(csrf, key, goal.slice(0, 16000), sample !== undefined)}`, 400);
    let response: GatewayResponse;
    try { response = await api("POST", "/project", {}, { goal, background: true, idempotencyKey: key }); }
    catch { return page("Submission uncertain", `<h1>Submission outcome is uncertain.</h1><p class="notice">Inspect retained projects first. Recover using the unchanged goal and this original key; a new key could start duplicate work.</p>${submissionForm(csrf, key, goal, sample !== undefined)}`, 503); }
    if (response.status !== 202) {
      const held = failure(response);
      return { ...held, body: held.body.replace('</main>', `${submissionForm(csrf, key, goal, sample !== undefined)}</main>`) };
    }
    const result = row(JSON.parse(response.body));
    return { status: 303, headers: { ...security, Location: link(result["projectId"]) }, body: "" };
  }
  if (sample && req.method === "GET" && ["/console", "/console/new"].includes(req.path)) {
    const list = await read(api, "/projects");
    if (isResponse(list)) return failure(list);
    return page("Count each delivery once", sampleLanding(sample, list, csrf, permissions, req.query["submissionKey"]));
  }
  if (req.path === "/console/new" && req.method === "GET") {
    if (!permissions.submit) return page("Forbidden", "<h1>You cannot submit project goals.</h1>", 403);
    const key = req.query["submissionKey"];
    // Retain identity in this form's URL across refresh/back; a GET never submits.
    if (key === undefined) return { status: 303, headers: { ...security, Location: `/console/new?submissionKey=${randomUUID()}` }, body: "" };
    if (!submissionKeyValid(key)) return page("Invalid submission", '<h1>Invalid submission key.</h1><a href="/console">Inspect retained projects</a>', 400);
    const list = await read(api, "/projects");
    if (isResponse(list)) return failure(list);
    return page("Submit a goal", `<a class="back" href="/console">← All projects</a><h1>Start a repository goal.</h1>${workerNotice(list)}${submissionForm(csrf, key, sample?.goal ?? "", sample !== undefined)}`);
  }
  if (req.path === "/console/cancel" && req.method === "POST") {
    if (!permissions.cancel) return page("Forbidden", "<h1>You cannot cancel project jobs.</h1>", 403);
    const form = new URLSearchParams(req.body), projectId = form.get("projectId") ?? "", jobId = form.get("jobId") ?? "";
    if (!projectId || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(jobId))
      return page("Invalid job", "<h1>Select a recorded project job.</h1>", 400);
    // Read the exact visible project/job pair; a forged form must not cancel a
    // different visible project's job. The gateway rechecks change.solve on POST.
    const observed = await read(api, "/project/jobs", { projectId, jobId });
    if (isResponse(observed)) return failure(observed);
    const before = row(observed["job"]);
    if (before["id"] !== jobId || before["projectId"] !== projectId)
      return page("Job mismatch", "<h1>This job does not match the selected project.</h1>", 409);
    if (before["state"] !== "queued" && before["state"] !== "running")
      return page("Job changed", `<h1>This job is no longer queued or running.</h1><a href="${esc(link(projectId))}">Inspect updated project</a>`, 409);
    const response = await api("POST", "/project/cancel", {}, { jobId });
    if (response.status !== 202) return failure(response);
    const job = row(row(JSON.parse(response.body))["job"]);
    return page("Cancellation result", `<p class="eyebrow">Job control</p><h1>${job["cancellationRequested"] === true ? "Cancellation request recorded." : "Current job state."}</h1><p>Observed state: ${badge(job["state"])}</p><p>A request does not prove that local activity or a remote provider stopped. Inspect this job before any retry.</p><details><summary>Recorded job evidence</summary><pre>${pretty(job)}</pre></details><a class="button" href="${esc(link(projectId))}">Inspect updated project</a>`);
  }
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
      body = { runId, approval: { decisionId: wait["decisionId"], approved: action === "approve" }, ...(sample ? { background: true } : {}) };
    } else {
      if (!["approve", "veto"].includes(action ?? "")) return page("Invalid decision", "<h1>Choose approve or veto.</h1>", 400);
      body = { runId, decision: action, proposalDigest: form.get("proposalDigest") };
    }
    const response = await api("POST", req.path === "/console/resume" ? "/project/resume" : "/project/merge", {}, body);
    if (response.status !== 200 && !(sample && req.path === "/console/resume" && response.status === 202)) return failure(response);
    // Display the actual result. A saved decision, workspace merge and source landing differ.
    const result = row(JSON.parse(response.body));
    if (sample && req.path === "/console/resume") return { status: 303, headers: { ...security, Location: link(projectId) }, body: "" };
    if (sample) return page("Demo decision", sampleDecision(result, projectId, runId, form.get("proposalDigest") ?? "", sample));
    return page("Decision result", `<p class="eyebrow">Decision recorded</p><h1>${esc(str(result["status"], "Result recorded"))}</h1><p>${esc(str(result["reason"], str(result["note"], "Inspect the updated project before taking another action.")))}</p><section><h2>Observed result</h2><pre>${pretty(result)}</pre></section><a class="button" href="${esc(link(projectId))}">Open updated project</a>`);
  }
  if (req.method !== "GET") return page("Method not allowed", "<h1>Method not allowed</h1>", 405);
  if (req.path !== "/console" && req.path !== "/console/project") return page("Not found", "<h1>Page not found</h1>", 404);
  const list = await read(api, "/projects");
  if (isResponse(list)) return failure(list);
  const projects = rows(list["projects"]);
  if (req.path === "/console") {
    const start = permissions.submit ? '<p><a class="button" href="/console/new">Submit a repository goal</a></p>' : "";
    const attention = projects.filter(p => str(p["status"], "").startsWith("waiting-")).length;
    const cards = projects.map(p => `<a class="project" href="${esc(link(p["id"]))}"><div><p class="eyebrow">${esc(p["lifecycle"])} project</p><h2>${esc(p["name"])}</h2><p class="muted mono">${esc(p["id"])}</p></div><div>${badge(p["status"])}<p class="muted">${p["proposal"] === true ? "Proposal available" : "No proposal recorded"}</p><span>Inspect project →</span></div></a>`).join("");
    return page("Projects", `<p class="eyebrow">Your workspace</p><div class="heading"><div><h1>Work you can inspect.</h1><p class="lede">Follow each project from its goal to its evidence and decision.</p></div><a class="button secondary" href="/console">Refresh state</a></div><div class="metrics"><section><strong>${projects.length}</strong><span>Retained projects</span></section><section><strong>${attention}</strong><span>Waiting for a next step</span></section><section><strong>${projects.filter(p => p["proposal"] === true).length}</strong><span>Recorded proposals</span></section></div>${workerNotice(list)}${start}<h2 class="section-title">Projects</h2>${cards || '<section class="empty"><h2>Your first project starts here.</h2><p>Submit a configured repository goal. Its retained job, checks, proposal and decision will appear here.</p></section>'}`);
  }
  const projectId = req.query["projectId"], selected = projects.find(p => p["id"] === projectId);
  if (!selected) return page("Not found", "<h1>Project not found.</h1><a href=\"/console\">Return to projects</a>", 404);
  const jobs = await read(api, "/project/jobs", { projectId: String(projectId), includeTerminal: "true" });
  if (isResponse(jobs)) return failure(jobs);
  const runId = selected["runId"];
  let detail = typeof runId === "string" ? await read(api, "/project", { runId }) : {};
  if (isResponse(detail) && detail.status === 404 && rows(jobs["jobs"]).some(job => ["queued", "running"].includes(str(job["state"])))) detail = {};
  if (isResponse(detail)) return failure(detail);
  if (sample) return sampleProject(detail, list, jobs, String(projectId), csrf, permissions, sample);
  const state = row(detail["project"]), wait = row(state["wait"]), proposal = row(detail["proposal"]), checks = row(proposal["checks"]);
  const repository = row(detail["repository"] ?? selected["repository"]), source = row(repository["source"]);
  const sourceMerge = row(source["merge"]), workspace = row(repository["workspace"]);
  let action = `<p>${esc(str(wait["reason"] ?? state["note"], "Refresh to inspect current state. For a failed or held job, inspect its recorded reason below and ask the owner to correct setup or dependencies. Reconcile uncertain effects before retrying; retain the original submission key."))}</p>`;
  if (wait["kind"] === "approval" && (permissions.approve || permissions.decline)) action += `<form method="post" action="/console/resume">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("runId", runId)}${hidden("decisionId", wait["decisionId"])}${permissions.approve ? '<button name="action" value="approve">Approve this step</button>' : ""} ${permissions.decline ? '<button class="secondary" name="action" value="decline">Decline</button>' : ""}</form>`;
  const digest = row(proposal["rollback"])["patchSha256"];
  if (typeof digest === "string" && /^[a-f0-9]{64}$/u.test(digest)) action += `<p><a class="button secondary" href="/console/export?runId=${encodeURIComponent(str(runId, ""))}&amp;proposalDigest=${digest}">Download proposal evidence</a></p>`;
  if (typeof digest === "string" && /^[a-f0-9]{64}$/u.test(digest) && (permissions.approve || permissions.decline)) action += `<p>Review the exact diff and checks below before deciding on this proposal.</p><form method="post" action="/console/merge">${hidden("csrf", csrf)}${hidden("projectId", projectId)}${hidden("runId", runId)}${hidden("proposalDigest", digest)}${permissions.approve ? '<button name="action" value="approve">Approve exact proposal</button>' : ""} ${permissions.decline ? '<button class="secondary" name="action" value="veto">Veto proposal</button>' : ""}<p class="muted mono">SHA256 ${esc(digest)}</p></form>`;
  const jobRows = rows(jobs["jobs"]);
  const activities: Row[] = [];
  for (const job of jobRows) {
    const observed = await read(api, "/project/jobs", { projectId: String(projectId), jobId: String(job["id"]) });
    if (isResponse(observed)) return failure(observed);
    activities.push(...rows(observed["activities"]));
  }
  const history = rows(row(detail["session"])["history"]);
  const requester = row(detail["requester"]), decisions = rows(detail["decisionHistory"]);
  const attribution = `<p class="muted">Requested by ${esc(requester["kind"] ?? "unavailable identity")}${requester["id"] ? ` · ${esc(requester["id"])}` : ""}</p>`;
  const decisionHistory = decisions.length ? `<ul class="timeline">${decisions.map(decision => `<li><strong>${esc(decision["event"])}</strong><p>${esc(decision["humanPrincipalId"] ?? "")}${decision["agentPrincipalId"] ? ` · on behalf of ${esc(decision["agentPrincipalId"])}` : ""}${typeof decision["approved"] === "boolean" ? ` · ${decision["approved"] ? "approved" : "declined"}` : ""}</p>${decision["reason"] ? `<p class="muted">${esc(decision["reason"])}</p>` : ""}</li>`).join("")}</ul>` : "";
  return page(str(selected["name"]), `<a class="back" href="/console">← All projects</a><p class="eyebrow">${esc(selected["lifecycle"])} project</p><div class="heading"><div><h1>${esc(selected["name"])}</h1><p class="muted mono">${esc(projectId)}</p>${attribution}</div><a class="button secondary" href="${esc(link(projectId))}">Refresh state</a></div><div class="metrics"><section><span>Current stage</span><strong class="small">${esc(state["stage"] ?? "Not started")}</strong>${badge(state["status"] ?? selected["status"])}</section><section><span>Workspace</span><strong class="small">${esc(workspace["status"] ?? "unknown")}</strong></section><section><span>Source repository</span><strong class="small">${esc(sourceMerge["status"] ?? "unknown")}</strong><span>Last recorded landing outcome</span></section></div>${workerNotice(list)}<section class="next"><p class="eyebrow">Next action</p><h2>${wait["kind"] === "approval" ? "This step needs your decision." : "Inspect the current result."}</h2>${action}</section><div class="columns"><section><h2>Changed files &amp; diff</h2>${typeof proposal["diff"] === "string" ? diffView(proposal["diff"]) : '<p class="muted">No executed proposal diff is recorded yet.</p>'}</section><section><h2>Repository checks</h2>${typeof checks["testsPassed"] === "boolean" ? `<p>${badge(checks["testsPassed"] ? "Tests passed" : "Tests failed")}</p><p>Vetting: ${checks["vettingCleared"] === true ? "cleared" : "not cleared"}</p><pre>${pretty(checks)}</pre>` : '<p class="muted">No repository check result is recorded yet.</p>'}</section></div><section><h2>Jobs &amp; activity</h2>${jobRows.length ? `<ul class="timeline">${jobRows.map(job => jobView(job, projectId, csrf, permissions.cancel === true)).join("")}</ul>` : '<p class="muted">No jobs recorded.</p>'}${activities.length ? `<h3>Observed activity</h3><ul class="timeline">${activities.map(activity => `<li>${esc(activity["label"])} ${badge(activity["state"])}</li>`).join("")}</ul>` : ""}</section><section><h2>Decisions &amp; delivery</h2>${decisionHistory}<p>Latest recorded decision: <strong>${esc(repository["latestDecision"] ?? "None")}</strong></p><ul class="timeline">${(Array.isArray(state["consumedSignals"]) ? state["consumedSignals"] : []).map(signal => `<li class="mono">${esc(signal)}</li>`).join("")}</ul><details><summary>Delivery evidence</summary><pre>${pretty(repository)}</pre></details></section><details><summary>Project conversation &amp; history</summary><pre>${pretty(history)}</pre></details>`);
}

export const CONSOLE_STYLE = `
.sample-disclosure{font-size:12px;color:#52666d;padding:12px 16px;border:1px solid var(--line);border-radius:8px;background:#edf3f1;margin:0 0 32px}.guided-demo{max-width:1050px}.guided-demo h1{max-width:800px;font-size:clamp(29px,4vw,46px)}.guided-demo .intro{font-size:18px;color:var(--muted);max-width:720px}.demo-route{display:flex;gap:18px;list-style:none;padding:0;margin:25px 0;color:var(--muted);font-size:13px}.demo-route li[aria-current=step]{color:var(--accent);font-weight:700}.demo-route li+li:before{content:"→";margin-right:18px;color:#889b9c}.demo-example{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:28px 0}.demo-example article{padding:18px;border:1px solid var(--line);border-radius:8px}.demo-example strong{display:block;font-size:19px}.demo-checks{list-style:none;padding:0}.demo-checks li{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 0;border-bottom:1px solid var(--line)}.demo-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:20px 0}.guided-demo details{padding:16px 20px}.guided-demo .scope{font-size:13px;color:var(--muted);max-width:750px}.guided-demo .next p{max-width:760px}.demo-error{color:#873532}.demo-success{color:#175b37}@media(max-width:620px){.demo-example{grid-template-columns:1fr;gap:8px}.demo-route{gap:8px;flex-wrap:wrap}.demo-route li+li:before{margin-right:8px}.demo-checks li{align-items:flex-start}.guided-demo .demo-actions .button,.guided-demo .demo-actions button{width:100%;text-align:center}}
:root{color-scheme:light;--ink:#172c36;--muted:#5b6f78;--line:#dbe3e5;--paper:#f6f8f7;--accent:#14594e}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--accent);text-underline-offset:4px}header{display:flex;align-items:center;justify-content:space-between;padding:22px max(5vw,24px);background:white;border-bottom:1px solid var(--line)}.brand{font-weight:800;font-size:25px;letter-spacing:.16em;text-decoration:none;color:var(--ink)}.brand span{font-size:12px;letter-spacing:0;font-weight:500;margin-left:22px;color:var(--muted)}nav a{text-decoration:none;font-weight:600}main{max-width:1260px;margin:auto;padding:48px max(4vw,24px)}h1{font-size:clamp(27px,3.5vw,43px);line-height:1.16;letter-spacing:-.04em;margin:8px 0 14px;overflow-wrap:anywhere}h2{font-size:20px;line-height:1.4;margin:0 0 14px}h3{font-size:15px}.eyebrow{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin:0 0 8px}.lede{color:var(--muted);font-size:17px;max-width:670px}.heading{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:30px 0}.metrics section{display:flex;flex-direction:column;gap:5px}.metrics strong{font-size:34px;line-height:1.2}.metrics .small{font-size:21px;overflow-wrap:anywhere}.metrics span{color:var(--muted);font-size:13px}section,details{background:white;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:20px}.metrics section{margin:0}.section-title{margin:36px 0 14px}.project{display:flex;justify-content:space-between;gap:24px;text-decoration:none;color:var(--ink);background:white;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:12px}.project:hover{border-color:var(--accent)}.project>div:last-child{text-align:right;min-width:150px}.project h2{margin-bottom:5px;overflow-wrap:anywhere}.badge{display:inline-block;font-size:12px;font-weight:600;border:1px solid #c8ddd7;background:#eef7f2;color:#245d4c;padding:4px 10px;border-radius:30px}.muted{color:var(--muted)}.mono,pre,code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.mono{overflow-wrap:anywhere}pre{background:#f5f7f7;border:1px solid #e5ebeb;border-radius:7px;padding:16px;overflow:auto;max-height:480px;white-space:pre-wrap;overflow-wrap:anywhere}.diff{white-space:pre;max-height:650px}.added{color:#175b37;background:#e6f4e9}.removed{color:#873532;background:#ffebe9}.hunk{color:#365a97}.files{font:12px/1.8 ui-monospace,monospace;overflow-wrap:anywhere}.timeline{list-style:none;padding:0}.timeline li{padding:12px 0;border-bottom:1px solid var(--line)}.timeline li p{margin:6px 0}.columns{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:20px}.columns section{min-width:0}.next{border-left:4px solid var(--accent)}button,.button{display:inline-block;background:var(--accent);color:white;border:1px solid var(--accent);border-radius:7px;padding:10px 17px;font:600 13px/1.5 system-ui;text-decoration:none;cursor:pointer}.secondary{background:white;color:var(--ink);border-color:var(--line)}input,textarea{display:block;width:100%;padding:12px;border:1px solid #a9bbbf;border-radius:7px;margin:8px 0 18px;font:inherit}.back{display:inline-block;margin-bottom:24px}.notice{padding:20px;border-left:3px solid #a46b29;background:#fff4e7}.signin{max-width:560px;margin:10vh auto}.signin .brand{display:block;margin-bottom:32px}.signin p{color:var(--muted)}label{font-size:13px;font-weight:600}.empty{text-align:center;padding:55px 24px}footer{text-align:center;color:var(--muted);font-size:12px;padding:25px;border-top:1px solid var(--line)}summary{cursor:pointer;font-weight:600}a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,summary:focus-visible{outline:3px solid #b18232;outline-offset:4px}@media(max-width:760px){.brand span{display:none}main{padding-top:30px}.heading,.project{display:block}.heading .button{margin-top:12px}.metrics{gap:8px}.metrics section{padding:16px 12px}.metrics strong{font-size:27px}.columns{grid-template-columns:1fr;gap:0}.project>div:last-child{text-align:left;margin-top:18px}button{margin-bottom:8px}}`;
