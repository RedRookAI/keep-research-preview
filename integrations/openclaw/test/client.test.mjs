import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureScope, goalInput, parseConfig } from "../contracts.mjs";
import { heldResult, useKeep } from "../client.mjs";

async function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), "keep-openclaw-client-")), token = "a".repeat(64), jobs = new Map(), requests = [];
  const tokenFile = join(root, "client-token"), stateDirectory = join(root, "state");
  writeFileSync(tokenFile, token + "\n", { mode: 0o600 }); mkdirSync(stateDirectory, { mode: 0o700 });
  let lost = false, afterSubmit;
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1"); let body = "";
    for await (const part of request) body += part;
    requests.push({ method: request.method, path: url.pathname, body });
    assert.equal(request.headers.authorization, "Bearer " + token);
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/project") {
      const value = JSON.parse(body); assert.deepEqual(Object.keys(value).sort(), ["goal", "idempotencyKey"]);
      let status = [...jobs.values()].find(job => job.key === value.idempotencyKey);
      if (!status) {
        const index = jobs.size + 1, jobId = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
        status = { key: value.idempotencyKey, projectId: "prj_" + index.toString(16).padStart(32, "0"), jobId,
          job: { state: "completed", cancellationRequested: false },
          run: { status: "waiting-approval", stage: "understand", wait: { kind: "approval", decisionId: "exact-decision", reason: "Owner approval required " + token } },
          proposal: { available: false, digest: null, checks: null }, review: { vetoed: false, latestDecision: null, generationDecision: null }, delivery: { workspace: "unknown", source: "unknown", revert: "unknown" },
        }; jobs.set(jobId, status);
      }
      afterSubmit?.();
      if (options.loseFirst && !lost) { lost = true; request.socket.destroy(); return; }
      response.writeHead(202); response.end(JSON.stringify({ projectId: status.projectId, jobId: status.jobId, runId: status.jobId, status: "accepted", replayed: false })); return;
    }
    if (request.method === "GET" && url.pathname === "/project/jobs") {
      const { key, ...status } = jobs.get(url.searchParams.get("jobId")); response.end(JSON.stringify(status)); return;
    }
    response.writeHead(403); response.end(JSON.stringify({ error: "forbidden" }));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const config = parseConfig({ endpoint: `http://127.0.0.1:${server.address().port}`, clientId: "owned-client", grantId: "owned-grant", commandBinding: "b".repeat(64), openclawAgentId: "portfolio", tokenFile, stateDirectory, requestTimeoutMs: 1000 });
  const context = { senderIsOwner: true, agentId: "portfolio", sessionId: "session-one", sessionKey: "stable-conversation", assertInvocationCurrent() {} };
  const scope = (call, override = {}, signal) => captureScope(config, { ...context, ...override }, call, signal);
  return { config, context, scope, token, jobs, requests, onSubmit: fn => { afterSubmit = fn; },
    close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); rmSync(root, { recursive: true, force: true }); },
  };
}

test("lost acknowledgement, fresh context and new call IDs recover the original request until a real terminal outcome", async () => {
  const f = await fixture({ loseFirst: true });
  try {
    await assert.rejects(useKeep(f.config, f.scope("submit-one"), "submit", "Fix the requested repository behavior."));
    assert.equal(f.jobs.size, 1);
    const recovered = await useKeep(f.config, f.scope("status-new", { sessionId: "reset-session" }), "status");
    assert.equal(recovered.status.run.status, "waiting-approval"); assert.equal(f.jobs.size, 1);
    assert.ok(!JSON.stringify(recovered).includes(f.token), "reflected client credential is never returned");
    const blocked = await useKeep(f.config, f.scope("new-submit"), "submit", "A different goal");
    assert.equal(blocked.previousWork, true); assert.equal(f.jobs.size, 1);
    const old = [...f.jobs.values()][0]; old.run = { status: "completed", stage: "done", wait: null };
    old.proposal = { available: true, digest: "c".repeat(64), checks: { testsPassed: true, vettingCleared: true } };
    await useKeep(f.config, f.scope("still-not-landed"), "status");
    assert.equal((await useKeep(f.config, f.scope("another-goal"), "submit", "A different goal")).previousWork, true);
    assert.equal(f.jobs.size, 1, "completed callback and passing proposal do not mean a landed task");
    old.review.vetoed = true; await useKeep(f.config, f.scope("observe-veto"), "status");
    await useKeep(f.config, f.scope("next-explicit-goal"), "submit", "A different goal");
    assert.equal(f.jobs.size, 2);
    assert.equal(f.requests.filter(request => request.method === "POST").slice(0, 2).map(request => JSON.parse(request.body).idempotencyKey).every(key => key === old.key), true);
  } finally { await f.close(); }
});

test("concurrent calls share one outstanding submission; a changed grant cannot replace it", async () => {
  const f = await fixture();
  try {
    const results = await Promise.all([useKeep(f.config, f.scope("first"), "submit", "First goal"), useKeep(f.config, f.scope("second"), "submit", "Second goal")]);
    assert.equal(f.jobs.size, 1); assert.equal(results[1].previousWork, true);
    const before = f.requests.length;
    await assert.rejects(useKeep({ ...f.config, grantId: "rotated-grant" }, f.scope("rotated"), "submit", "A replacement"), error => error.code === "binding");
    assert.equal(f.requests.length, before);
    assert.throws(() => captureScope(f.config, { ...f.context, senderIsOwner: false }, "untrusted"));
    assert.throws(() => goalInput({ goal: "work", endpoint: "http://untrusted.invalid" }));
  } finally { await f.close(); }
});

test("an invocation ending after HTTP acceptance returns no private observation and retains recoverable work", async () => {
  const f = await fixture(); let active = true;
  try {
    f.onSubmit(() => { active = false; });
    let error;
    try { await useKeep(f.config, f.scope("expires", { assertInvocationCurrent() { if (!active) throw Error("private runtime detail"); } }), "submit", "Original work"); }
    catch (value) { error = value; }
    const held = heldResult(error); assert.equal(held.state, "held"); assert.ok(!JSON.stringify(held).includes("private runtime detail"));
    assert.equal(f.jobs.size, 1);
    f.onSubmit(undefined); const recovered = await useKeep(f.config, f.scope("recover"), "status");
    assert.equal(recovered.status.jobId, [...f.jobs.keys()][0]); assert.equal(f.jobs.size, 1);
  } finally { await f.close(); }
});
