import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeConsequences, deriveEffects } from "../src/pipeline/plan_consequences.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { SuspectFile } from "../src/solve/localize.js";

const issue = (text: string): Issue => ({ id: "x", text, repoRef: "r" });

test("INVARIANT: the gate is NO LONGER vacuous — dangerous issues block/escalate, a typo passes", () => {
  // The exact failure the audit found: these must NOT all return the same verdict.
  assert.equal(analyzeConsequences(issue("drop all database tables and disable backups")).decision, "block");
  assert.equal(analyzeConsequences(issue("delete all audit logs to clean up")).decision, "block");
  assert.equal(analyzeConsequences(issue("rm -rf the temp directory and wipe everything")).decision, "block");
  // A benign issue passes.
  assert.equal(analyzeConsequences(issue("fix a typo in a comment")).decision, "pass");
});

test("INVARIANT: effect derivation classifies intended effects by boundary", () => {
  const effects = deriveEffects(issue("update the auth login flow and touch the api_key handling"));
  const classes = new Set(effects.map((e) => e.cls));
  assert.ok(classes.has("auth-access-control"), "auth surfaced");
  assert.ok(classes.has("secret-credential"), "secret surfaced");
});

test("INVARIANT: a critical irreversible boundary crossing SOUND-blocks", () => {
  const v = analyzeConsequences(issue("drop table users and truncate all tables"));
  assert.equal(v.decision, "block");
  assert.ok(v.checks.some((c) => c.name === "critical-effect-boundary" && c.sound && c.decision === "block"));
});

test("INVARIANT: an irreversible high-blast effect escalates (reversibility check)", () => {
  // secret-credential is high + irreversible but not a critical boundary → escalate, not block.
  const v = analyzeConsequences(issue("rotate the private_key and update the oauth secret"));
  assert.equal(v.decision, "escalate");
  assert.ok(v.checks.some((c) => c.name === "reversibility" && c.decision === "escalate"));
});

test("INVARIANT: second-order — touching auth AND the audit path escalates", () => {
  const v = analyzeConsequences(issue("change the permission check and update the audit log format"));
  assert.equal(v.decision, "escalate");
  assert.ok(v.checks.some((c) => c.name === "second-order-combination" && c.decision === "escalate"));
});

test("INVARIANT: second-order — secrets AND network egress (exfiltration surface) escalates", () => {
  const v = analyzeConsequences(issue("read the api_key and send it to the remote webhook via fetch"));
  assert.equal(v.decision, "escalate");
  assert.ok(v.checks.some((c) => c.name === "second-order-combination"));
});

test("INVARIANT: suspect-file paths surface effects even when issue text is bland", () => {
  const suspects: SuspectFile[] = [{ path: "src/auth/login.ts", score: 1, isTest: false }, { path: "migrations/001.sql", score: 1, isTest: false }];
  const effects = deriveEffects(issue("update the thing"), suspects);
  const classes = new Set(effects.map((e) => e.cls));
  assert.ok(classes.has("auth-access-control"));
  assert.ok(classes.has("db-schema"));
});

test("a pure code edit passes clean with a low-blast pure-code effect", () => {
  const v = analyzeConsequences(issue("rename a local variable for clarity"));
  assert.equal(v.decision, "pass");
  assert.equal(v.effects[0]!.cls, "pure-code");
});

test("the verdict carries the full auditable effect + check trail", () => {
  const v = analyzeConsequences(issue("change the permission check and update the audit log"));
  assert.ok(v.effects.length > 0, "effects recorded");
  assert.ok(v.effects.every((e) => e.evidence.length > 0), "each effect has evidence");
  assert.ok(v.checks.length > 0, "checks recorded");
});
