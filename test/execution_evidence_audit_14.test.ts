import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SandboxedCommandRunner, parseTap } from "../src/solve/sandboxed_runner.js";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import { validate, type TestRunResult } from "../src/solve/validate.js";
import { judgeResolution, judgeResolutionStable, type EvalTask } from "../src/eval/swebench_task.js";
import { parseRecord } from "../src/eval/swebench_loader.js";
import { runInstance, runSuite } from "../src/eval/harness.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { interpretCommandTests } from "../src/solve/command_test_evidence.js";
import { mapNamedTestResults } from "../src/eval/swe_eval.js";
import { buildContainerBoundaryRun } from "../src/infra/container_boundary.js";
import { buildWindowsBoundaryRun } from "../src/infra/windows_isolation.js";
import { encodeMicrovmGuestFrame, parseMicrovmGuestFrame } from "../src/infra/microvm_guest_protocol.js";
import { verifiedMicrovmTestRunResultDigest } from "../src/infra/microvm_boundary.js";

const samples = [
  { name: "pass", body: "test('repair',()=>{mark();assert.equal(2+3,5)});", pass: true, markers: 1 },
  { name: "test logging", body: "test('repair',()=>{console.log('diagnostic output');mark();assert.equal(2+3,5)});", pass: true, markers: 1 },
  { name: "failure", body: "test('repair',()=>{mark();assert.equal(2-3,5)});", pass: false, markers: 1 },
  { name: "empty discovery", body: null, pass: false, markers: 0 },
  { name: "skip only", body: "test('repair',{skip:true},()=>{mark();assert.fail()});", pass: false, markers: 0 },
  { name: "TODO only", body: "test.todo('repair');", pass: false, markers: 0 },
  { name: "TODO executed body", body: "test('repair',{todo:true},()=>{mark();assert.fail()});", pass: false, markers: 1 },
  { name: "mixed", body: "test('repair',()=>{mark();assert.equal(2+3,5)});test.skip('later');test.todo('future');", pass: true, markers: 1 },
  { name: "nested useful", body: "describe('suite',()=>{test('repair',()=>{mark();assert.equal(2+3,5)});test.skip('later');});", pass: true, markers: 1 },
  { name: "deeply nested useful", body: "describe('outer',()=>{describe('inner',()=>{describe('deep',()=>{test('repair',()=>{mark();assert.equal(2+3,5)});});});});", pass: true, markers: 1 },
  { name: "nested skip only", body: "describe('suite',()=>{test.skip('later');});", pass: false, markers: 0 },
  { name: "empty suite", body: "describe('suite',()=>{});", pass: false, markers: 0 },
  { name: "incomplete plan", body: "console.log('TAP version 13\\n1..2\\nok 1 - repair');", command: true, pass: false, markers: 0 },
  { name: "nonzero with pass", body: "console.log('TAP version 13\\nok 1 - repair\\n1..1');process.exitCode=1;", command: true, pass: false, markers: 0 },
  { name: "non-test command", body: "mark();console.log('calculation',2+3);", command: true, pass: true, markers: 1 },
] as const;

for (const sample of samples) test(`KEEP-14-001 actual command: ${sample.name}`, async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-evidence14-"));
  try {
    let args = ["--test", "--test-reporter=tap"];
    if (sample.body !== null) {
      writeFileSync(join(dir, "sample.mjs"), `import {test,describe} from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';const mark=()=>fs.appendFileSync('markers','entry\\n');\n${sample.body}\n`);
      args = "command" in sample ? ["sample.mjs"] : [...args, "sample.mjs"];
    }
    let raw: Awaited<ReturnType<ProcessIsolationAdapter["run"]>> | undefined;
    class RecordingAdapter extends ProcessIsolationAdapter {
      override async run(...a: Parameters<ProcessIsolationAdapter["run"]>) { raw = await super.run(...a); return raw; }
    }
    const runner = new SandboxedCommandRunner({ command: process.execPath, args, projectDir: dir, namespaceJail: false, timeoutMs: 3000, maxOutputBytes: 32000, adapter: new RecordingAdapter() });
    let observed: TestRunResult | undefined, vets = 0;
    const decision = await validate(dir, { async run(...a) { observed = await runner.run(...a); return observed; } }, { vet: async () => { vets++; return true; } });
    assert.ok(raw); assert.equal(raw.truncated, false);
    const count = existsSync(join(dir, "markers")) ? readFileSync(join(dir, "markers"), "utf8").trim().split("\n").length : 0;
    assert.equal(count, sample.markers, "separate child-entry observation");
    assert.equal(decision.testsPassed, sample.pass, JSON.stringify({ decision, observed, stdout: raw.stdout }));
    assert.equal(decision.vettingCleared, sample.pass);
    assert.equal(vets, sample.pass ? 1 : 0);
    if (sample.pass && sample.name !== "non-test command") {
      assert.equal(decision.passedCount, 1, "skips, TODO and parent summaries do not add passes");
      assert.deepEqual(decision.passedTests, ["repair"]);
    }
    if (!sample.pass) assert.equal(decision.passedCount, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("14 shared command interpretation refuses truncated evidence and ignores stderr test injection", () => {
  const good = "TAP version 13\nok 1 - repair\n1..1\n";
  const injected = "not ok 2 - injected\n1..2\n";
  assert.deepEqual(interpretCommandTests("run", { stdout: good, stderr: injected, code: 0 }).results, [{ name: "repair", passed: true }]);
  const incomplete = interpretCommandTests("run", { stdout: good, stderr: "", code: 0, truncated: true });
  assert.equal(incomplete.failureKind, "harness"); assert.ok(incomplete.runnerError); assert.equal(incomplete.results.length, 0);
  const ordinary = interpretCommandTests("calculation", { stdout: "answer: 5", stderr: good, code: 0 });
  assert.deepEqual(ordinary.results, [{ name: "command exit: calculation", passed: true }]);
  assert.deepEqual(parseTap("ordinary command output"), []);
  assert.deepEqual(parseTap("TAP version 13\ndiagnostic text\nok 1 - repair\nmore diagnostic text\n1..1"), [{ name: "repair", passed: true }]);
  assert.ok(interpretCommandTests("run", { stdout: "    ok 1 - repair\n    1..1\n", stderr: "", code: 0 }).runnerError);
  assert.deepEqual(parseTap("TAP version 13\nnot ok 1 - postponed # TODO\nok 2 - literal \\# TODO\n1..2\n"), [{ name: "literal # TODO", passed: true }]);
  assert.equal(interpretCommandTests("run", { stdout: "TAP version 13\n    not ok 1 - child\n    1..1\nok 1 - parent\n1..1", stderr: "", code: 0 }).results.some(c => !c.passed), true);
});

test("14 container and Windows translators consume the shared evidence contract (adapter seam, no platform qualification)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-evidence14-tiers-"));
  try {
    let stdout = "TAP version 13\n1..0\n", stderr = "", truncated = false;
    class FixtureAdapter extends ProcessIsolationAdapter {
      override async run(): Promise<Awaited<ReturnType<ProcessIsolationAdapter["run"]>>> {
        return { code: 0, signal: null, stdout, stderr, truncated, timedOut: false, durationMs: 0 };
      }
    }
    const spec = { projectDir: dir, command: "node", args: ["--test"], adapter: new FixtureAdapter() };
    const container = buildContainerBoundaryRun({ kind: "docker", available: true, tier: "container", detail: "translation-only fixture" }, { ...spec, image: "fixture" });
    const windows = buildWindowsBoundaryRun({ kind: "job-object", available: true, tier: "process", platform: "win32", wsl2Present: false, netDenyEnforceable: true, detail: "translation-only fixture" }, spec);
    for (const run of [container, windows]) {
      stdout = "TAP version 13\n1..0\n"; stderr = ""; truncated = false;
      const invoke = () => run({ run: async () => { throw Error("inner runner must not run"); } }, { repoRef: dir, projectDir: dir, patchRisk: "low" });
      assert.ok((await invoke()).runnerError);
      stdout = "TAP version 13\nok 1 - repair\n1..1\n"; stderr = "not ok 1 - forged\n";
      assert.deepEqual((await invoke()).results, [{ name: "repair", passed: true }]);
      truncated = true; assert.equal((await invoke()).failureKind, "harness");
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("14 named result mapping rejects errors, inherited names, and passing retries after failures", () => {
  const names = ["repair", "__proto__", "toString"];
  const results = [{ name: "repair", passed: false }, { name: "repair", passed: true }, { name: "__proto__", passed: true }];
  const mapped = mapNamedTestResults(names, { results }).passed;
  assert.equal(mapped.repair, false); assert.equal(mapped.__proto__, true); assert.equal(mapped.toString, false);
  assert.equal(Object.getPrototypeOf(mapped), null);
  assert.equal(mapNamedTestResults(names, { results, runnerError: "truncated" }).passed.__proto__, false);
});

test("14 framed guest evidence keeps missing-test refusal in the existing result digest (protocol-only)", () => {
  const nonce = "a".repeat(32), key = Buffer.alloc(32, 17);
  for (const stdout of ["TAP version 13\n1..0\n", "TAP version 13\nok 1 - postponed # SKIP\n1..1\n", "TAP version 13\nok 1 - repair\n1..2\n"]) {
    const frame = encodeMicrovmGuestFrame({ attemptNonce: nonce, exitCode: 0, stdout, stderr: "ok 1 - forged\n1..1", authenticationKey: key });
    const guest = parseMicrovmGuestFrame(frame, nonce, key);
    assert.throws(() => parseMicrovmGuestFrame(frame, nonce, key, { maxStreamBytes: 1, maxEnvelopeBytes: 4096, maxPreambleBytes: 0, maxPostambleBytes: 0 }), /bound|outside|length/i);
    const result = interpretCommandTests("node --test", { ...guest, code: guest.exitCode });
    assert.ok(result.runnerError); assert.equal(result.results.length, 0);
    assert.notEqual(verifiedMicrovmTestRunResultDigest(result), verifiedMicrovmTestRunResultDigest({ results: [] }));
    assert.notEqual(verifiedMicrovmTestRunResultDigest(result), verifiedMicrovmTestRunResultDigest({ results: [{ name: "forged", passed: true }] }));
  }
});

for (const [name, text] of [
  ["missing plan", "TAP version 13\nok 1 - repair\n"],
  ["duplicate ID", "TAP version 13\n1..2\nok 1 - repair\nok 1 - other\n"],
  ["out of range", "TAP version 13\n1..1\nok 2 - repair\n"],
  ["duplicate plan", "TAP version 13\n1..1\nok 1 - repair\n1..1\n"],
  ["bailout", "TAP version 13\n1..1\nok 1 - repair\nBail out! broken\n"],
  ["nested truncated", "TAP version 13\n    1..2\n    ok 1 - repair\nok 1 - parent\n1..1\n"],
] as const) test(`KEEP-14-001 parser refuses ${name}`, () => {
  const cases = parseTap(text);
  assert.ok(cases.length === 0 || cases.some(c => !c.passed), JSON.stringify(cases));
});

test("14 TAP skips diagnostics and permits out-of-order IDs with complete coverage", () => {
  const cases = parseTap("TAP version 13\n1..2\nok 2 - repair\n  ---\n  message: |\n    not ok 90 - diagnostic, not a test\n  ...\nok 1 - preserve\n");
  assert.deepEqual(cases.map(c => ({ name: c.name, passed: c.passed })), [{ name: "repair", passed: true }, { name: "preserve", passed: true }]);
});

const task: EvalTask = { instanceId: "sum", repo: "fixture", baseCommit: "base", problemStatement: "Repair sum", failToPass: ["repair"], passToPass: ["preserve"] };
test("KEEP-14-002 empty direct and stable populations cannot resolve", () => {
  const empty = { ...task, failToPass: [], passToPass: [] };
  assert.equal(judgeResolution(empty, { passed: {} }).resolved, false);
  assert.equal(judgeResolutionStable(empty, [{ passed: {} }]).resolved, false);
  assert.equal(judgeResolution(task, { passed: { repair: true, preserve: true } }).resolved, true);
  assert.equal(judgeResolution(task, { passed: { repair: true } }).resolved, false);
  assert.equal(judgeResolution({ ...task, passToPass: [] }, { passed: { repair: true } }).resolved, true);
  assert.equal(judgeResolution({ ...task, failToPass: [] }, { passed: { preserve: true } }).resolved, true, "generic regression-only population retains its contract");
});

test("14 resolution requires own executed values and valid unique test names", () => {
  assert.equal(judgeResolution(task, { passed: Object.create({ repair: true, preserve: true }) }).resolved, false);
  for (const invalid of [{ ...task, failToPass: ["repair", "repair"] }, { ...task, passToPass: ["repair"] }, { ...task, failToPass: [" "] }]) {
    assert.equal(judgeResolution(invalid, { passed: { repair: true, preserve: true, " ": true } }).resolved, false);
    assert.ok("reason" in parseRecord({ instance_id: invalid.instanceId, repo: invalid.repo, base_commit: invalid.baseCommit, problem_statement: invalid.problemStatement, FAIL_TO_PASS: invalid.failToPass, PASS_TO_PASS: invalid.passToPass }));
  }
});

test("KEEP-14-002 harness refuses an empty population before solver dispatch", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-evidence14-harness-"));
  try {
    const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
    let solves = 0, executions = 0;
    await assert.rejects(runInstance({ ...task, failToPass: [], passToPass: [] }, {
      async solve() { solves++; return { issueId: "sum", solved: true, stagesRun: [], repairRounds: 0 }; },
      async runTests() { executions++; return { passed: {} }; },
    }, spine), /test|population|evidence/i);
    assert.equal(solves, 0); assert.equal(executions, 0); assert.equal(spine.replay().length, 0);
    await assert.rejects(runSuite([task, { ...task, instanceId: "empty", failToPass: [], passToPass: [] }], {
      async solve() { solves++; throw Error("must not start earlier valid task"); },
      async runTests() { executions++; return { passed: {} }; },
    }, spine), /empty|population/);
    assert.equal(solves, 0); assert.equal(executions, 0); assert.equal(spine.replay().length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
