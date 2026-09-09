import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import { BuiltinPatternScanner, ExternalScannerAdapter, parseSemgrep, parseSarif } from "../src/infra/scanner_adapter.js";
import { linearAdapter, jiraAdapter, githubIssuesAdapter, gitlabAdapter, registerAllTrackers } from "../src/infra/tracker_adapters.js";
import { StdioMcpTransport } from "../src/infra/mcp_stdio_transport.js";
import { TriggerRouter } from "../src/ecosystem/integrations.js";

const here = dirname(fileURLToPath(import.meta.url));
// tsc compiles tests into dist/test; non-TS fixtures stay in the source tree.
// Resolve the fixture from source: dist/test -> ../../test/fixtures.
const fixturesDir = join(here, "..", "..", "test", "fixtures");

// --- Process isolation (real subprocesses) ---

test("isolation: a hanging process is killed at the timeout (process-group kill)", async () => {
  const iso = new ProcessIsolationAdapter();
  const r = await iso.run("sleep", ["30"], { cwd: tmpdir(), timeoutMs: 200 });
  assert.equal(r.timedOut, true);
  assert.notEqual(r.signal, null); // killed by signal, didn't run 30s
});

test("isolation: env is scrubbed — un-allowlisted secrets are NOT visible to the child", async () => {
  const iso = new ProcessIsolationAdapter();
  process.env["KEEP_TEST_SECRET"] = "topsecret";
  process.env["KEEP_TEST_OK"] = "fine";
  const r = await iso.run("printenv", [], { cwd: tmpdir(), timeoutMs: 5000, envAllowlist: ["KEEP_TEST_OK", "PATH"] });
  assert.ok(!r.stdout.includes("topsecret")); // secret scrubbed
  assert.ok(r.stdout.includes("fine")); // allowlisted var present
  delete process.env["KEEP_TEST_SECRET"];
  delete process.env["KEEP_TEST_OK"];
});

test("isolation: argv-only — shell metacharacters in an arg are inert, not executed", async () => {
  const iso = new ProcessIsolationAdapter();
  const dir = mkdtempSync(join(tmpdir(), "keep-iso-"));
  // If this were shell-interpreted, "; echo PWNED" would run echo. argv-only => literal.
  const r = await iso.run("echo", ["hello; echo PWNED"], { cwd: dir, timeoutMs: 5000 });
  assert.ok(r.stdout.includes("hello; echo PWNED")); // passed literally
  assert.ok(!/^PWNED$/m.test(r.stdout)); // never executed as a second command
});

test("isolation: output is capped (bomb mitigation)", async () => {
  const iso = new ProcessIsolationAdapter();
  const r = await iso.run("node", ["-e", "process.stdout.write('x'.repeat(100000))"], { cwd: tmpdir(), timeoutMs: 5000, maxOutputBytes: 1000 });
  assert.ok(r.stdout.length <= 1000);
  assert.equal(r.truncated, true);
});

// --- Builtin scanner (real files) ---

test("builtin scanner finds a hardcoded secret and eval with correct line numbers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-scan-"));
  const f = join(dir, "bad.js");
  writeFileSync(f, ["const x = 1;", "const password = \"hunter2hunter2\";", "eval(userInput);"].join("\n"));
  const scanner = new BuiltinPatternScanner();
  const res = await scanner.scan({ language: "js", compilable: false, diffFiles: [f] });
  assert.ok(res.fullDepth);
  const secret = res.findings.find((x) => x.detector === "builtin.secret");
  const evalF = res.findings.find((x) => x.detector === "builtin.eval");
  assert.ok(secret && secret.line === 2);
  assert.ok(evalF && evalF.line === 3);
});

test("builtin scanner reports nothing on a clean file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-scan2-"));
  const f = join(dir, "good.js");
  writeFileSync(f, "export const add = (a, b) => a + b;\n");
  const res = await new BuiltinPatternScanner().scan({ language: "js", compilable: false, diffFiles: [f] });
  assert.equal(res.findings.length, 0);
});

// --- External scanner: graceful degradation + parsers ---

test("external scanner degrades gracefully when the binary is absent (no throw, fullDepth=false)", async () => {
  const adapter = new ExternalScannerAdapter("semgrep", "/nonexistent/semgrep-binary");
  const res = await adapter.scan({ language: "py", compilable: false, diffFiles: ["x.py"] });
  assert.equal(res.fullDepth, false);
  assert.equal(res.findings.length, 0);
  assert.ok(res.note && res.note.includes("unavailable"));
});

test("CodeQL adapter degrades on a non-compilable request (never deadlocks)", async () => {
  const adapter = new ExternalScannerAdapter("codeql", "/nonexistent/codeql");
  const res = await adapter.scan({ language: "py", compilable: false, diffFiles: ["x.py"] });
  assert.equal(res.fullDepth, false);
  assert.ok(res.note && res.note.includes("compilable"));
});

test("semgrep JSON parser maps results to Findings", () => {
  const json = JSON.stringify({ results: [{ path: "a.py", check_id: "rule.x", start: { line: 12 }, extra: { severity: "ERROR", message: "bad" } }] });
  const findings = parseSemgrep(json);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.line, 12);
  assert.equal(findings[0]!.severity, "high");
});

test("SARIF parser maps CodeQL results to Findings", () => {
  const json = JSON.stringify({ runs: [{ results: [{ ruleId: "js/xss", message: { text: "xss" }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.js" }, region: { startLine: 5 } } }] }] }] });
  const findings = parseSarif(json);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.file, "a.js");
  assert.equal(findings[0]!.line, 5);
});

// --- Tracker normalizers (real payloads) ---

test("Linear payload normalizes to a Keep trigger", () => {
  const t = linearAdapter.normalize({ type: "Issue", action: "create", data: { identifier: "ENG-42", title: "Fix login", description: "broken", labels: [{ name: "bug" }] } });
  assert.equal(t!.kind, "ticket.created");
  assert.equal(t!.ticketId, "ENG-42");
  assert.deepEqual(t!.labels, ["bug"]);
});

test("Jira payload normalizes to a Keep trigger", () => {
  const t = jiraAdapter.normalize({ webhookEvent: "jira:issue_created", issue: { key: "PROJ-7", fields: { summary: "Add retry", description: "d", labels: ["backend"] } } });
  assert.equal(t!.kind, "ticket.created");
  assert.equal(t!.ticketId, "PROJ-7");
});

test("GitHub Issues payload normalizes and unknown actions are ignored", () => {
  const t = githubIssuesAdapter.normalize({ action: "opened", issue: { number: 99, title: "Bug", body: "b", labels: [{ name: "p1" }] } });
  assert.equal(t!.ticketId, "99");
  assert.equal(githubIssuesAdapter.normalize({ action: "assigned", issue: { number: 1 } }), undefined);
});

test("GitLab issue hooks and reopened issues preserve their distinct trigger kind", () => {
  const gitlab = gitlabAdapter.normalize({ object_kind: "issue", object_attributes: { action: "reopen", iid: 7, title: "again", description: "body" }, labels: [{ title: "urgent" }] });
  assert.equal(gitlab?.source, "gitlab"); assert.equal(gitlab?.kind, "ticket.reopened"); assert.deepEqual(gitlab?.labels, ["urgent"]);
  const github = githubIssuesAdapter.normalize({ action: "reopened", issue: { number: 8, title: "again", body: "body", labels: [] } });
  assert.equal(github?.kind, "ticket.reopened");
});

test("registerAllTrackers registers all five sources (incl. GitLab and the generic provider-agnostic escape hatch)", () => {
  const router = new TriggerRouter();
  const sources = registerAllTrackers(router);
  assert.equal(sources.length, 5);
  assert.ok(sources.includes("gitlab"));
  assert.ok(sources.includes("linear") && sources.includes("jira") && sources.includes("github-issues") && sources.includes("generic"));
});

// --- Stdio MCP transport (real subprocess) ---

test("stdio MCP transport talks to a real MCP server subprocess (initialize + list + call)", async () => {
  const transport = new StdioMcpTransport("node", [join(fixturesDir, "mock_mcp_server.mjs")]);
  await transport.start();
  assert.equal(transport.serverProtocolVersion, "2026-07-28"); // negotiated from the server
  const tools = await transport.listTools();
  assert.deepEqual(tools.sort(), ["add", "echo"]);
  const sum = await transport.callTool("add", { a: 2, b: 3 });
  assert.equal(sum, 5);
  await transport.stop();
});

test("stdio MCP transport: a missing server binary fails FAST with a clear error (no 10s hang, no uncaught)", async () => {
  const transport = new StdioMcpTransport("node", [join(fixturesDir, "does_not_exist_9k2.mjs")]);
  const t0 = Date.now();
  await assert.rejects(() => transport.start(), (e: unknown) => e instanceof Error && /MCP server (failed to start|closed)/.test((e as Error).message));
  assert.ok(Date.now() - t0 < 5000, "failed fast (well under the 10s request timeout), not a hang");
  await transport.stop();
});
