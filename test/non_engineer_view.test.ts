import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renderNonEngineerView } from "../src/review/non_engineer_view.js";
import type { DecisionPacket } from "../src/cli/decision_packet.js";

function pkt(over: Partial<DecisionPacket>): DecisionPacket {
  return {
    id: "pr-1", intent: "Fix the login button so it submits the form", diff: "", executed: [],
    evidence: [{ label: "Tests", value: "all passing" }, { label: "Type check", value: "clean" }],
    reversible: true, blastRadius: "the login page", whyAttention: [], band: "low",
    disposition: "auto-approved", requiresImmediateAttention: false, depth: "compact", attribution: "keep",
    ...over,
  } as DecisionPacket;
}

// Phrases that would nudge the reviewer toward approving — the view must contain none of them (I2).
const PERSUASIVE = [/you should approve/i, /we recommend/i, /keep recommends/i, /looks good/i, /safe to approve/i, /i suggest/i, /\badvise\b/i, /go ahead and approve/i, /this is fine/i];

test("S3 DISPOSITION proving: each disposition is stated plainly and is never hidden", () => {
  assert.match(renderNonEngineerView(pkt({ disposition: "auto-approved" })), /does NOT need a decision/);
  assert.match(renderNonEngineerView(pkt({ disposition: "human-approval-required", band: "medium", whyAttention: ["touches auth"] })), /needs your decision[\s\S]*will NOT proceed unless you approve/i);
  assert.match(renderNonEngineerView(pkt({ disposition: "blocked", band: "high" })), /STOPPED this change[\s\S]*will not proceed/i);
});

test("S3 NEUTRALITY (I2): non-persuasive, and says outright it is not recommending", () => {
  const v = renderNonEngineerView(pkt({ disposition: "human-approval-required", band: "medium", whyAttention: ["changes how passwords are checked"], verifyThis: "Is it okay for existing sessions to be logged out?" }));
  for (const rx of PERSUASIVE) assert.doesNotMatch(v, rx, `should not contain persuasive phrasing: ${rx}`);
  assert.match(v, /not recommending either way/);
});

test("S3 anti-overcorrection: routine auto-approved work is OPTIONAL — no 'only you can decide' burden", () => {
  const v = renderNonEngineerView(pkt({ disposition: "auto-approved", band: "low" }));
  assert.match(v, /spot-check is optional/);
  assert.doesNotMatch(v, /What only you can decide/);
});

test("S3 cognitive-forcing + honest limit: a decision item surfaces the specific check AND the intent-fit limit", () => {
  const v = renderNonEngineerView(pkt({ disposition: "human-approval-required", band: "medium", whyAttention: ["changes how passwords are checked"], verifyThis: "Is it okay for existing sessions to be logged out?" }));
  assert.match(v, /Check this specifically: Is it okay for existing sessions/);
  assert.match(v, /Keep can't judge that — only you know what you intended/);
});

test("S3 reversibility is stated in plain terms", () => {
  assert.match(renderNonEngineerView(pkt({ reversible: true })), /can be reverted/);
  assert.match(renderNonEngineerView(pkt({ reversible: false, disposition: "human-approval-required", band: "high" })), /hard to undo/);
});

test("S3 confidence is scoped honestly (about the checks, not intent-fit)", () => {
  const v = renderNonEngineerView(pkt({ disposition: "human-approval-required", band: "medium", confidence: 0.82, whyAttention: ["auth"] }));
  assert.match(v, /confidence in its own checks: 82%/);
  assert.match(v, /not about whether this is what you meant/);
});

test("S3 wiring: `keep review <id> --plain` renders the plain-language view end-to-end", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const { runCli } = await import("../src/cli/cli_core.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-s3-")) });
  const manifest = { id: "pr-42", title: "Change password hashing", body: "", branch: "keep/x", baseBranch: "main", diff: "", intent: "Upgrade password hashing to argon2", executed: [], checks: [], attribution: "keep", humanApprovalRequired: true, oversight: { band: "medium", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: false, reasons: ["touches auth"] } };
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: "pr-42", manifest, ts: Date.now() } });
  const out: string[] = [];
  await runCli(["review", "pr-42", "--plain"], { write: (s) => out.push(s), prompt: async () => "skip" }, { app });
  const text = out.join("\n");
  assert.match(text, /needs your decision/);
  assert.match(text, /Keep is not recommending either way/);
  assert.doesNotMatch(text, /diff|@@|\+\+\+/, "the plain view does not dump a diff at a non-engineer");
});
