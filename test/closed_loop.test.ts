import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { runCli } from "../src/cli/cli_core.js";
import type { SolveFn } from "../src/loop/review_intake.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { SolveToPrResult } from "../src/pipeline/keep_pipeline.js";
import type { PrManifest } from "../src/git/pull_request.js";

const SECRET = "loop-secret";
function linearBody(id: string, title: string): string {
  return JSON.stringify({ type: "Issue", action: "create", webhookTimestamp: Date.now(), data: { identifier: id, title, description: "please fix" } });
}
function sig(body: string): string { return createHmac("sha256", SECRET).update(body, "utf8").digest("hex"); }

function fakeSolve(disposition: string, band: "low" | "medium" | "high" = "medium"): SolveFn {
  return async (issue: Issue) => ({
    solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0 },
    manifest: {
      id: `pr-${issue.id}`, title: `PR for ${issue.id}`, body: "synthetic", branch: `keep/${issue.id}`, baseBranch: "main",
      diff: "", intent: issue.text, executed: [], checks: [], attribution: "keep", humanApprovalRequired: true,
      oversight: { band, disposition, mode: disposition === "blocked" ? "block-until-approved" : band === "low" ? "silent-auto" : "notify-async", requiresImmediateAttention: disposition === "blocked", reasons: ["synthetic"] },
    } as unknown as PrManifest,
    safety: {} as SolveToPrResult["safety"],
  } as unknown as SolveToPrResult);
}
const io = () => { const out: string[] = []; return { out, io: { write: (s: string) => out.push(s), prompt: async () => "approve" } }; };

test("W3 CLOSED LOOP: signed webhook → solve → human-gated review → decision, correlated end-to-end", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-w3-")), triggerSecrets: { linear: SECRET }, solve: fakeSolve("human-approval-required") });
  const body = linearBody("ENG-100", "add() subtracts");
  const r = await app.triggerIngress.receive({ source: "linear", rawBody: body, headers: { "Linear-Signature": sig(body) } });
  assert.equal(r.status, "accepted", "trigger accepted → solve ran → review recorded");

  const s1 = io();
  await runCli(["status"], s1.io, { app });
  assert.match(s1.out.join("\n"), /need your decision/, "the review surfaces to the human");

  await app.spine.seal();
  const events = app.spine.replay().map((e) => e.payload as Record<string, unknown>);
  const trig = events.find((p) => p["event"] === "trigger.accepted");
  const rev = events.find((p) => p["event"] === "review.pending");
  assert.ok(trig && rev, "both trigger + review recorded on the spine");
  assert.equal(rev!["correlationId"], trig!["issueId"], "review correlated to the originating trigger (traceability)");

  const s2 = io();
  await runCli(["review", String(rev!["reviewId"])], s2.io, { app });
  assert.match(s2.out.join("\n"), /Approved/, "the human decision closes the loop (nothing merged)");
});

test("W3: a routine auto-approved trigger closes the loop WITHOUT prompting the human", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-w3b-")), triggerSecrets: { linear: SECRET }, solve: fakeSolve("auto-approved", "low") });
  const body = linearBody("ENG-200", "trivial typo");
  await app.triggerIngress.receive({ source: "linear", rawBody: body, headers: { "Linear-Signature": sig(body) } });
  const s = io();
  await runCli(["status"], s.io, { app });
  assert.match(s.out.join("\n"), /Nothing needs your decision|auto-approved/, "routine work closed the loop without a decision prompt");
});

test("W3: with NO solve configured, the ingress records the trigger but creates no review (honest seam)", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-w3c-")), triggerSecrets: { linear: SECRET } });
  const body = linearBody("ENG-300", "no solve wired");
  const r = await app.triggerIngress.receive({ source: "linear", rawBody: body, headers: { "Linear-Signature": sig(body) } });
  assert.equal(r.status, "accepted");
  await app.spine.seal();
  const hasReview = app.spine.replay().some((e) => (e.payload as Record<string, unknown>)["event"] === "review.pending");
  assert.equal(hasReview, false, "no solve → no review; the trigger.accepted record stands");
});
