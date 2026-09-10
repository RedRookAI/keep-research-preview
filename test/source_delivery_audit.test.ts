import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, renameSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import { projectRepositoryOutcomes } from "../src/solve/governed_local_merge.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import type { StagedEvent } from "../src/spine/event.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const token = "synthetic-delivery-owner", headers = { authorization: `Bearer ${token}` };
const childEnv = { ...process.env }; delete childEnv["NODE_TEST_CONTEXT"];
function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], {
    cwd, encoding: "utf8", timeout: 5000, env: { ...childEnv, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "Synthetic fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
      GIT_COMMITTER_NAME: "Synthetic fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid" },
  }).trim();
}
type Outcome = { status: string; reason?: string; mergeId?: string; revertCommit?: string; sourceDelivery?: { status: string; recorded: boolean } };
type Summary = { observation: string; workspace: Outcome; source: { merge: Outcome; revert: Outcome }; latestDecision: string | null };

for (const variant of ["control", "advanced", "dirty", "revert-advanced", "recording-failure", "git-error"] as const) {
  test(`KEEP-03B-E01 ${variant}: source and workspace outcomes survive reconstruction`, async () => {
    const root = mkdtempSync(join(tmpdir(), "keep-delivery-audit-"));
    const source = join(root, "source"), workspaceBase = join(root, "workspaces"); mkdirSync(source); mkdirSync(workspaceBase);
    const before = "export function add(a,b) { return a - b; }\n";
    writeFileSync(join(source, "calc.mjs"), before);
    writeFileSync(join(source, "unrelated.txt"), "preserve\n");
    writeFileSync(join(source, "repo.test.mjs"), "import test from 'node:test';import assert from 'node:assert/strict';import {add} from './calc.mjs';test('sum',()=>{for(const [a,b,c] of [[2,3,5],[-4,2,-2],[0,0,0],[1.5,2.25,3.75]])assert.equal(add(a,b),c)});\n");
    git(source, "init", "-q", "-b", "main"); git(source, "add", "-A"); git(source, "commit", "-qm", "synthetic base");
    const base = git(source, "rev-parse", "HEAD");
    let calls = 0;
    const model: ModelProvider = { name: "delivery-audit-scripted", isLocal: true,
      async embed() { throw new Error("unexpected embedding"); },
      async generate(req) {
        calls++;
        assert.ok(req.hints?.["taskRole"] === "goal_test" || req.hints?.["taskRole"] === "repository_edit");
        const value = req.hints?.["taskRole"] === "goal_test"
          ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {add}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(add(2,3),5);" }
          : { action: "plan", rationale: "repair addition", edits: [{ file: "calc.mjs", search: "return a - b", replace: "return a + b", intent: "sum" }] };
        return { text: JSON.stringify(value), model: "scripted", tokensIn: 1, tokensOut: 1 };
      },
    };
    const config = { dataDir: join(root, "state"), sourceLanding: true,
      repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project", commit: base, baseBranch: "main" },
      testCommand: { command: process.execPath, args: ["--test", "repo.test.mjs"], timeoutMs: 5000 } };
    let injected = 0;
    class OutcomeFailureStore extends FileSpineStore {
      override appendStaged(event: StagedEvent): void {
        if (variant !== "recording-failure" || injected || event.payload["event"] !== "source_delivery.outcome") return super.appendStaged(event);
        injected++;
        // Real append-to-directory error on this synthetic state, not a canned
        // throwing callback. Preserve and restore the existing journal exactly.
        const target = join(config.dataDir, "staging.jsonl"), saved = target + ".preserved";
        renameSync(target, saved); mkdirSync(target);
        try { super.appendStaged(event); }
        finally { rmdirSync(target); renameSync(saved, target); }
      }
    }
    const app = composeKeep({ ...config, developmentProvider: model, store: new OutcomeFailureStore(config.dataDir, { fsync: true }) });
    const request = async (path: string, body: object, method: "POST" | "GET" = "POST", query = {}) => {
      const r = await handleGatewayRequest(app, { method, path, headers, query, body: JSON.stringify(body) }, { token });
      assert.equal(r.status, 200, r.body); return JSON.parse(r.body);
    };
    const proposal = await request("/project", { goal: "Fix add in calc.mjs to return the arithmetic sum. Preserve other files." }) as { runId: string; proposalDigest: string; proposal: boolean };
    assert.equal(proposal.proposal, true); assert.equal(calls, 2);
    const runId = proposal.runId, work = join(workspaceBase, "project");
    const advance = () => { writeFileSync(join(source, "later.txt"), "operator work\n"); git(source, "add", "later.txt"); git(source, "commit", "-qm", "later operator commit"); };
    if (variant === "advanced") advance();
    if (variant === "dirty") writeFileSync(join(source, "unrelated.txt"), "uncommitted operator work\n");
    if (variant === "git-error") writeFileSync(join(source, ".git", "index.lock"), "synthetic held index lock\n");
    const headBefore = git(source, "rev-parse", "HEAD"), statusBefore = git(source, "status", "--porcelain");
    const merged = await request("/project/merge", { runId, decision: "approve", proposalDigest: proposal.proposalDigest }) as Outcome;
    assert.equal(git(work, "rev-parse", "HEAD"), merged.mergeId, "workspace merge actually exists");
    let final = merged, operation: "merge" | "revert" = "merge";
    if (variant === "advanced" || variant === "dirty" || variant === "git-error") {
      assert.equal(merged.status, "failed");
      assert.match(merged.reason ?? "", variant === "git-error" ? /source landing failed closed/ : /source.*moved/);
      assert.equal(git(source, "rev-parse", "HEAD"), headBefore); assert.equal(git(source, "status", "--porcelain"), statusBefore);
      assert.equal(readFileSync(join(source, "calc.mjs"), "utf8"), before);
    } else {
      assert.equal(merged.status, "merged", merged.reason); assert.equal(git(source, "rev-parse", "HEAD"), merged.mergeId);
      if (variant === "recording-failure") {
        assert.equal(injected, 1); assert.deepEqual(merged.sourceDelivery?.status, "landed");
        assert.equal(merged.sourceDelivery?.recorded, false, "actual success is distinct from failed reporting persistence");
        assert.equal(app.spine.replay().some(e => e.payload["kind"] === "source_landing.terminal"), true);
        assert.equal(app.spine.replay().some(e => e.payload["event"] === "source_delivery.outcome"), false);
        const incomplete = projectRepositoryOutcomes(app.spine, runId);
        assert.equal(incomplete.source.merge.status, "landed", "the independently sealed source terminal remains visible");
        assert.equal(incomplete.latestDecision, "source_delivery.merge.pending", "the unconfirmed attempt report remains explicit");
      }
      const checked = execFileSync(process.execPath, ["--test", "repo.test.mjs"], { cwd: source, env: childEnv, encoding: "utf8", timeout: 5000 });
      assert.match(checked, /# pass 1\b/);
      if (variant === "revert-advanced") advance();
      const beforeRevert = git(source, "rev-parse", "HEAD");
      if (variant === "control") {
        const history = git(source, "rev-list", "--count", "HEAD");
        const [repeated, inverse] = await Promise.all([
          request("/project/merge", { runId, decision: "approve", proposalDigest: proposal.proposalDigest }),
          request("/project/revert", { runId }),
        ]) as [Outcome, Outcome];
        assert.equal(repeated.status, "merged", "concurrent repeat is serialized with revert");
        assert.equal(repeated.mergeId, merged.mergeId);
        final = inverse;
        assert.equal(Number(git(source, "rev-list", "--count", "HEAD")), Number(history) + 1, "only one inverse commit was created");
      } else final = await request("/project/revert", { runId }) as Outcome;
      operation = "revert";
      assert.equal(git(work, "rev-parse", "HEAD"), final.revertCommit, "workspace inverse exists even when source delivery fails");
      if (variant === "revert-advanced") {
        assert.equal(final.status, "failed"); assert.equal(git(source, "rev-parse", "HEAD"), beforeRevert);
        assert.match(readFileSync(join(source, "calc.mjs"), "utf8"), /a \+ b/);
      } else {
        assert.equal(final.status, "reverted", final.reason); assert.equal(git(source, "rev-parse", "HEAD"), final.revertCommit);
        assert.equal(git(source, "rev-parse", "HEAD^{tree}"), git(source, "rev-parse", `${base}^{tree}`));
      }
    }
    await app.spine.seal();
    const recorded = app.spine.replay().filter(e => e.payload["event"] === "source_delivery.outcome" && e.payload["runId"] === runId && e.payload["operation"] === operation);
    assert.ok(recorded.length > 0, "the final source result is durable, not only an API response");
    assert.equal(recorded.at(-1)?.payload["reason"], final.reason?.slice(0, 500));
    const detail = await request("/project", {}, "GET", { runId }) as { repository: Summary };
    const listed = await request("/projects", {}, "GET") as { projects: { runId: string; repository: Summary }[] };
    const summary = detail.repository;
    assert.equal(summary.observation, "last-recorded");
    assert.equal(summary.workspace.status, operation === "merge" ? "merged" : "reverted");
    assert.equal(summary.source[operation].status, variant === "control" || variant === "recording-failure" ? "reverted" : variant === "git-error" ? "unknown" : "refused");
    assert.deepEqual(listed.projects.find(p => p.runId === runId)?.repository, summary);
    const restored = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", `
      import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
      import {handleGatewayRequest} from ${JSON.stringify(new URL("../src/gateway/http_gateway.js", import.meta.url).href)};
      const app=composeKeep(JSON.parse(process.argv[1])); const runId=process.argv[2], token=process.argv[3];
      const results=[]; for(const path of ['/project','/projects']){ const r=await handleGatewayRequest(app,{method:'GET',path,query:{runId},headers:{authorization:'Bearer '+token},body:''},{token});if(r.status!==200)throw Error(r.body);results.push(JSON.parse(r.body)); }
      console.log(JSON.stringify(results));
    `, JSON.stringify(config), runId, token], { env: childEnv, encoding: "utf8", timeout: 10000 })) as [{ repository: Summary }, { projects: { runId: string; repository: Summary }[] }];
    assert.deepEqual(restored[0].repository, summary); assert.deepEqual(restored[1].projects.find(p => p.runId === runId)?.repository, summary);
    assert.equal(calls, 2, "actions and read-only projections do not regenerate the proposal");
  });
}

test("03B projection preserves legacy facts, missing outcomes, chronological attempts and separate scopes", async () => {
  const s = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-delivery-projection-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const push = async (type: StagedEvent["type"], payload: Record<string, unknown>) => { s.stage({ type, actor: "synthetic-fixture", payload: { runId: "run", ...payload } }); await s.seal(); };
  await push("identity.action", { event: "local_merge.merged", mergeId: "merge" });
  assert.deepEqual(projectRepositoryOutcomes(s, "run").source, { merge: { status: "unknown" }, revert: { status: "unknown" } });
  await push("identity.action", { event: "local_merge.refused", reason: "wrong digest" });
  assert.equal(projectRepositoryOutcomes(s, "run").workspace.status, "merged", "a refused request does not undo a merge");
  assert.equal(projectRepositoryOutcomes(s, "run").latestDecision, "local_merge.refused");
  await push("effect.terminal", { kind: "source_landing.terminal", disposition: "landed", mergeId: "merge" });
  await push("effect.terminal", { kind: "local_merge.revert_terminal", disposition: "reverted", mergeId: "merge", revertCommit: "inverse" });
  await push("effect.intent", { kind: "source_revert.intent", mergeId: "merge", revertCommit: "inverse" });
  let view = projectRepositoryOutcomes(s, "run");
  assert.equal(view.workspace.status, "reverted"); assert.equal(view.source.merge.status, "landed"); assert.equal(view.source.revert.status, "unknown");
  await push("identity.action", { event: "source_delivery.outcome", operation: "revert", deliveryStatus: "refused", reason: "source advanced", mergeId: "merge", revertCommit: "inverse" });
  await push("identity.action", { event: "source_delivery.attempt", operation: "revert", mergeId: "merge", revertCommit: "inverse" });
  view = projectRepositoryOutcomes(s, "run");
  assert.equal(view.source.revert.status, "unknown", "an interrupted new attempt has no invented outcome");
  assert.equal(view.source.merge.status, "landed", "revert observations do not overwrite merge history");
  const before = s.replay();
  assert.equal(projectRepositoryOutcomes(s, "other-run").workspace.status, "unknown");
  assert.deepEqual(s.replay(), before, "projection is read-only; no migrated/backfilled facts");
});
