import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { runInNewContext } from "node:vm";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, startGatewayServer } from "../src/gateway/http_gateway.js";

// Execute the actual served script. This DOM adapter supplies only the elements
// it uses; fetch, authentication, submission and durable jobs use the real server.
class Element {
  value = ""; textContent = ""; innerHTML = ""; disabled = false;
  style = { display: "" }; onclick: (() => unknown) | undefined;
  querySelectorAll() { return []; }
}
async function openPage(origin: string, token: string, savedUrl = origin + "/", loseSubmissionReply = false) {
  const response = await fetch(origin + "/", { headers: { authorization: `Bearer ${token}` } });
  assert.equal(response.status, 200);
  const html = await response.text(), script = /<script>([\s\S]*?)<\/script>/u.exec(html)![1]!;
  const elements = new Map<string, Element>();
  const element = (id: string) => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id)!; };
  for (const id of html.matchAll(/id="([^"]+)"/gu)) element(id[1]!);
  const location = { href: savedUrl }, calls: { method: string; path: string; body?: string }[] = [];
  const pending = new Set<Promise<unknown>>();
  const browserFetch = (path: string, options: RequestInit) => {
    calls.push({ method: String(options.method), path, ...(options.body ? { body: String(options.body) } : {}) });
    const p = (async () => {
      const r = await fetch(origin + path, options);
      if (loseSubmissionReply && options.method === "POST" && path === "/project") {
        loseSubmissionReply = false; await r.text(); throw new Error("Connection lost after acceptance");
      }
      return r;
    })();
    pending.add(p); void p.then(() => pending.delete(p), () => pending.delete(p)); return p;
  };
  const history = { replaceState: (_state: unknown, _title: string, path: string) => { location.href = new URL(path, location.href).href; } };
  const scope = { TOKEN: token, document: { getElementById: element }, fetch: browserFetch, location, history, URL, crypto: { randomUUID }, console };
  runInNewContext(script, scope, { timeout: 1000 });
  const settle = async () => {
    const deadline = Date.now() + 5000;
    do { assert.ok(Date.now() < deadline, "served script requests settled"); await new Promise(resolve => setTimeout(resolve, 2)); } while (pending.size);
    // Settle chained json() and rendering callbacks, without launching another check.
    await new Promise(resolve => setTimeout(resolve, 2));
  };
  await settle();
  return { element, location, calls, settle, revokeCredential() { scope.TOKEN = "expired-credential"; }, async click(id: string) { const e = element(id); if (!e.disabled) await e.onclick?.(); await settle(); } };
}
function fixture(root: string) {
  return composeKeep({ dataDir: root, projectRuntimePaused: true, solve: async () => { throw new Error("paused fixture must not generate"); } });
}

test("served chat script recovers a lost submission across restart without duplicate work or private browser persistence", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-chat-project-")), token = "chat-fixture-credential";
  let app = fixture(root), server = await startGatewayServer(app, { port: 0, token });
  t.after(async () => { await server.close(); rmSync(root, { recursive: true, force: true }); });
  const page = await openPage(server.origin, token, server.origin + "/?token=" + token, true);
  const goal = "Repair the private customer workflow";
  page.element("msg").value = goal; await page.click("start");
  assert.match(page.element("projectStatus").textContent, /Connection lost after acceptance/u);
  const key = new URL(page.location.href).searchParams.get("submissionKey"); assert.ok(key);
  assert.ok(!page.location.href.includes(goal) && !page.location.href.includes(token));
  assert.equal(page.element("newProject").disabled, true, "uncertain work cannot silently acquire a fresh request key");
  assert.equal(app.projectManager!.list().length, 1);
  const pid = app.projectManager!.list()[0]!.id;
  const jobs = app.projectRuntime!.retainedJobs(new Set([pid])); assert.equal(jobs.length, 1);
  const jid = jobs[0]!.id;
  await server.close(); app = fixture(root); server = await startGatewayServer(app, { port: 0, token });
  const saved = new URL(page.location.href); saved.host = new URL(server.origin).host;
  const restored = await openPage(server.origin, token, saved.href);
  assert.equal(restored.calls.filter(c => c.method === "POST").length, 0, "refresh only inspects retained work");
  restored.element("msg").value = "A changed goal must conflict"; await restored.click("start");
  assert.match(restored.element("projectStatus").textContent, /different|conflict|bound/iu);
  assert.equal(new URL(restored.location.href).searchParams.get("submissionKey"), key);
  assert.equal(app.projectManager!.list().length, 1);
  restored.element("msg").value = goal; await restored.click("start");
  assert.equal(new URL(restored.location.href).searchParams.get("jobId"), jid);
  assert.equal(new URL(restored.location.href).searchParams.get("projectId"), pid);
  assert.match(restored.element("projectStatus").textContent, new RegExp(jid));
  assert.equal(app.projectRuntime!.retainedJobs(new Set([pid])).length, 1);
  for (const call of restored.calls.filter(c => c.method === "POST")) {
    const body = JSON.parse(call.body!); assert.equal(body.background, true); assert.equal(body.idempotencyKey, key);
  }
  const connected = await openPage(server.origin, token, restored.location.href);
  assert.match(connected.element("projectStatus").textContent, new RegExp(jid));
  assert.equal(connected.calls.filter(c => c.method === "POST").length, 0);
  connected.revokeCredential(); await connected.click("refreshProject");
  assert.match(connected.element("projectStatus").textContent, /Authentication or permission is unavailable/u);
  assert.equal(connected.calls.filter(c => c.method === "POST").length, 0);
  assert.equal(new URL(connected.location.href).searchParams.get("jobId"), jid);
});

test("chat recovery is read-only and current authorization refuses guessed or stale identities", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-chat-refusal-")), token = "chat-refusal-credential";
  const app = fixture(root), server = await startGatewayServer(app, { port: 0, token });
  t.after(async () => { await server.close(); rmSync(root, { recursive: true, force: true }); });
  const page = await openPage(server.origin, token, server.origin + "/?projectId=foreign-project&jobId=" + randomUUID());
  assert.match(page.element("projectStatus").textContent, /not found/iu);
  assert.equal(page.calls.filter(c => c.method === "POST").length, 0);
  assert.equal(app.projectManager!.list().length, 0);
  const denied = await handleGatewayRequest(app, { method: "GET", path: "/project/jobs", query: { jobId: randomUUID() }, headers: { authorization: "Bearer revoked-credential" }, body: "" }, { token });
  assert.equal(denied.status, 401);
});
