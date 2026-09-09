import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { computeGateReport, generateGitHubWorkflow, type CiGateResult } from "../src/infra/ci_adapter.js";
import { InProcessA2ATransport } from "../src/infra/a2a_inprocess_transport.js";
import { A2AAgentAdapter, signAgentCard, type AgentCard, A2A_PROTOCOL_VERSION } from "../src/ecosystem/a2a.js";
import { composeInfra } from "../src/infra/compose_infra.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-infra2-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- CI adapter ---

test("CI report ALWAYS keeps human merge required (never auto-merge)", () => {
  const pass: CiGateResult[] = [{ gate: "tests", status: "pass", detail: "" }, { gate: "security", status: "pass", detail: "" }];
  const r = computeGateReport(pass);
  assert.equal(r.humanMergeRequired, true);
  assert.equal(r.outcome, "pass");
  assert.equal(r.exitCode, 0);
  assert.equal(r.prLabel, "agent-generated");
});

test("a failing gate produces fail + exit code 1", () => {
  const gates: CiGateResult[] = [{ gate: "tests", status: "pass", detail: "" }, { gate: "security", status: "fail", detail: "secret found" }];
  const r = computeGateReport(gates);
  assert.equal(r.outcome, "fail");
  assert.equal(r.exitCode, 1);
  assert.equal(r.humanMergeRequired, true); // still true even on fail
});

test("all gates pass but review required => needs-review, exit 0", () => {
  const gates: CiGateResult[] = [{ gate: "tests", status: "pass", detail: "" }];
  const r = computeGateReport(gates, { requireHumanReview: true });
  assert.equal(r.outcome, "needs-review");
  assert.equal(r.exitCode, 0);
});

test("generated workflow has fetch-depth:0, merge_group, and the aggregate check needing every gate", () => {
  const yaml = generateGitHubWorkflow({ gateJobs: ["tests", "security", "review"] });
  assert.ok(yaml.includes("fetch-depth: 0")); // full history for merge-base diffs
  assert.ok(yaml.includes("merge_group:")); // merge queue support
  assert.ok(yaml.includes("keep-all-gates-passed:")); // the aggregate check
  // The aggregate needs each gate job (renamed-job silent-break defense).
  for (const g of ["tests", "security", "review"]) assert.ok(yaml.includes(`- ${g}`));
  assert.ok(yaml.includes("agent-generated")); // labels agent PRs
});

// --- In-process A2A transport (real lifecycle) ---

test("A2A transport drives submitted->working->completed lifecycle", async () => {
  const t = new InProcessA2ATransport();
  t.registerSkill("refactor", async (args) => ({ output: { changed: args["file"] } }));
  const res = await t.sendTask("refactor", { file: "a.ts" });
  assert.equal(res.state, "completed");
  assert.deepEqual(res.output, { changed: "a.ts" });
  assert.deepEqual(t.lifecycle.states, ["submitted", "working", "completed"]);
});

test("A2A transport reports a failed skill with its error", async () => {
  const t = new InProcessA2ATransport();
  t.registerSkill("boom", async () => ({ error: "handler failed" }));
  const res = await t.sendTask("boom", {});
  assert.equal(res.state, "failed");
  assert.equal(res.error, "handler failed");
  assert.ok(t.lifecycle.states.includes("failed"));
});

test("A2A transport fails on an unknown skill", async () => {
  const t = new InProcessA2ATransport();
  const res = await t.sendTask("nope", {});
  assert.equal(res.state, "failed");
});

test("BYOA over the transport returns only the task-level outcome (trajectory caveat)", async () => {
  const t = new InProcessA2ATransport();
  t.registerSkill("build", async () => ({ output: "artifact-123" }));
  const key = randomBytes(32);
  const card: AgentCard = { name: "byoa", description: "d", protocolVersion: A2A_PROTOCOL_VERSION, skills: ["build"], url: "https://x/.well-known/agent-card.json" };
  const adapter = new A2AAgentAdapter("a1", signAgentCard(card, "k1", key), "cred", t);
  assert.equal(adapter.verifyIntake(key).verified, true);
  const r = await adapter.invoke({ capabilityId: "a1", operation: "build", args: {} });
  assert.equal(r.ok, true);
  assert.equal(r.output, "artifact-123"); // outcome only
});

// --- Infra composition root ---

test("composeInfra wires the builtin scanner always and isolation + capability hub", () => {
  const infra = composeInfra({ spine: newSpine() });
  assert.equal(infra.scanners.length, 1); // builtin backstop only
  assert.equal(infra.scanners[0]!.name, "builtin-pattern");
  assert.ok(infra.isolation);
  assert.ok(infra.capabilities);
  assert.equal(infra.git, undefined); // no repoDir => no git adapter
});

test("composeInfra adds an external scanner only when a binary path is given, and git only with a repoDir", () => {
  const infra = composeInfra({ spine: newSpine(), repoDir: "/tmp/repo", externalScanners: { semgrep: "semgrep" } });
  assert.equal(infra.scanners.length, 2); // builtin + semgrep
  assert.ok(infra.scanners.some((s) => s.name === "semgrep"));
  assert.ok(infra.git); // repoDir provided
});

test("composeInfra registers all tracker sources", () => {
  const infra = composeInfra({ spine: newSpine() });
  const sources = infra.triggers.supportedSources().sort();
  assert.deepEqual(sources, ["generic", "github-issues", "gitlab", "jira", "linear"]);
});
