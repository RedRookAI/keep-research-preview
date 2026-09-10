import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { getEventListeners } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProcessIsolationAdapter, type IsolationPolicy, type IsolatedProcess } from "../src/infra/process_isolation.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { BoundaryExecutor, IsolatedTestRunner, MinimumTierExecutor, ProcessIsolationExecutor, consumeVerifiedIsolatedRunOutcome } from "../src/isolation/isolated_executor.js";
import { withExecutionLifetime } from "../src/infra/execution_lifetime.js";
import type { PlatformIsolation } from "../src/infra/isolation_backend.js";
import type { IsolationClaim } from "../src/isolation/isolation_attestation.js";
import { validate } from "../src/solve/validate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InstalledEffectAdmission } from "../src/control/installed_effect_admission.js";

const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
class ObservedAdapter extends ProcessIsolationAdapter {
  readonly processes: IsolatedProcess[] = [];
  override start(command: string, args: readonly string[], policy: IsolationPolicy): IsolatedProcess {
    const child = super.start(command, args, policy); this.processes.push(child); return child;
  }
  async finish(): Promise<void> { await Promise.all(this.processes.map(p => p.done)); }
}
function setup(track: string, delayMs = 0, outerTimeout?: number) {
  const dir = mkdtempSync(join(tmpdir(), `keep-cancel-${track}-`));
  const start = join(dir, "started"), finish = join(dir, "finished"), adapter = new ObservedAdapter();
  const spine = new Spine(new FileSpineStore(join(dir, "state"), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  let admissions = 0;
  const command = new SandboxedCommandRunner({
    command: process.execPath,
    args: ["-e", "const fs=require('node:fs');fs.writeFileSync(process.argv[1],String(process.pid));setTimeout(()=>{fs.writeFileSync(process.argv[2],'finished');console.log('ok 1 - useful work')},Number(process.argv[3]));", start, finish, String(delayMs)],
    projectDir: dir, namespaceJail: false, timeoutMs: 2000, maxOutputBytes: 1024, adapter,
    effectAdmission: new InstalledEffectAdmission(() => { admissions++; }),
  });
  const executor = new ProcessIsolationExecutor(spine, outerTimeout === undefined ? {} : { timeoutMs: outerTimeout });
  const wrapped = new IsolatedTestRunner(command, executor, dir);
  return { dir, start, finish, adapter, spine, command, executor, wrapped, admissions: () => admissions };
}
async function started(path: string): Promise<void> {
  const until = Date.now() + 1500;
  while (!existsSync(path)) { if (Date.now() >= until) throw new Error("finite owned child did not start"); await pause(5); }
}

for (const track of ["personal", "alpha"]) {
  test(`KEEP-11A-003 ${track}: pre-aborted wrapper call does not admit or create a child`, async () => {
    const f = setup(track), controller = new AbortController(); controller.abort();
    const result = await validate(f.dir, f.wrapped, {}, { signal: controller.signal });
    await f.adapter.finish();
    assert.equal(result.testsPassed, false); assert.equal(f.admissions(), 0);
    assert.equal(f.adapter.processes.length, 0); assert.equal(existsSync(f.start), false);
  });
  test(`KEEP-11A-003 ${track}: expired wrapper deadline does not admit or create a child`, async () => {
    const f = setup(track);
    const result = await validate(f.dir, f.wrapped, {}, { deadline: Date.now() - 1 });
    await f.adapter.finish();
    assert.equal(result.testsPassed, false); assert.equal(f.admissions(), 0);
    assert.equal(f.adapter.processes.length, 0); assert.equal(existsSync(f.start), false);
  });
  test(`KEEP-11A-003 ${track}: valid wrapper work still completes`, async () => {
    const f = setup(track);
    const result = await validate(f.dir, f.wrapped, {}, { deadline: Date.now() + 2000 });
    await f.adapter.finish(); assert.equal(result.testsPassed, true);
    assert.equal(f.admissions(), 1); assert.equal(readFileSync(f.finish, "utf8"), "finished");
  });
}

test("KEEP-11A-003 running command cancellation stops the finite child before its later write", async () => {
  const f = setup("cancel", 700), controller = new AbortController();
  const pending = f.command.run(f.dir, { signal: controller.signal });
  await started(f.start); controller.abort();
  const result = await pending; await f.adapter.finish();
  assert.ok(result.runnerError); assert.equal(existsSync(f.finish), false);
  const actual = await f.adapter.processes[0]!.done;
  assert.equal(actual.signal, "SIGKILL");
});

test("KEEP-11A-003 outer timeout cannot claim a started child never executed or leave its later write", async () => {
  const f = setup("outer", 700, 200);
  const result = await validate(f.dir, f.wrapped);
  const markerAtReturn = existsSync(f.finish);
  await f.adapter.finish(); // preserve the uncorrected late outcome before asserting
  assert.equal(result.testsPassed, false); assert.equal(f.adapter.processes.length, 1);
  const events = f.spine.currentEvents().filter(e => e.payload.event === "isolated_execution");
  assert.ok(events.length > 0);
  assert.equal(events.at(-1)!.payload.executed, true, "once dispatched, a timeout cannot mean no execution");
  assert.equal(markerAtReturn, false); assert.equal(existsSync(f.finish), false);
  assert.equal((await f.adapter.processes[0]!.done).signal, "SIGKILL");
});

test("KEEP-11A-003 opaque timeout records unconfirmed work rather than invented termination", async () => {
  const f = setup("opaque"), executor = new ProcessIsolationExecutor(f.spine, { timeoutMs: 10 });
  let finish!: () => void;
  const completion = new Promise<void>(resolve => { finish = resolve; });
  const runner = { async run() { await completion; return { results: [{ name: "eventual", passed: true }] }; } };
  const outcome = await executor.runIsolated(runner, { projectDir: f.dir, repoRef: f.dir, patchRisk: "medium" });
  finish(); await completion;
  assert.equal(outcome.executed, true);
  const detail = JSON.stringify(outcome);
  assert.doesNotMatch(detail, /killed/); assert.match(detail, /unconfirmed|may continue|still running/);
});

test("KEEP-11A-003 minimum tier forwards cancellation and boundary refuses before callback", async () => {
  const f = setup("forward"), controller = new AbortController();
  const min = new MinimumTierExecutor(f.executor, "process"); controller.abort();
  const spec = { projectDir: f.dir, repoRef: f.dir, patchRisk: "medium" as const };
  assert.equal((await min.runIsolated(f.command, spec, { signal: controller.signal })).executed, false);
  let calls = 0;
  const boundary = new BoundaryExecutor("container", async () => { calls++; return { results: [{ name: "t", passed: true }] }; });
  assert.equal((await boundary.runIsolated(f.command, spec, { signal: controller.signal })).executed, false);
  assert.equal(calls, 0); assert.equal(f.admissions(), 0);
  assert.equal((await f.wrapped.runWithEvidence(f.dir, false, { signal: controller.signal })).executed, false);
  assert.ok((await f.wrapped.run(f.dir, { deadline: Date.now() - 1 })).runnerError);
  assert.equal(f.admissions(), 0);
});

test("KEEP-11A-003 abort during admission is refused before adapter entry", async () => {
  const f = setup("admit"), controller = new AbortController();
  const command = new SandboxedCommandRunner({ command: process.execPath, args: ["-e", "console.log('ok 1')"], projectDir: f.dir,
    namespaceJail: false, adapter: f.adapter, effectAdmission: new InstalledEffectAdmission(() => controller.abort()) });
  const result = await command.run(f.dir, { signal: controller.signal });
  assert.ok(result.runnerError); assert.equal(result.processCompletion, "not-started");
  assert.equal(f.adapter.processes.length, 0);
});

test("KEEP-11A-003 adapter rechecks abort after spawn-plan preparation", async () => {
  const f = setup("prepare"), controller = new AbortController();
  const original = (f.adapter as unknown as { iso: PlatformIsolation }).iso;
  Object.defineProperty(f.adapter, "iso", { value: { ...original, planSpawn(...args: Parameters<PlatformIsolation["planSpawn"]>) { const plan = original.planSpawn(...args); controller.abort(); return plan; } } });
  const child = f.adapter.start(process.execPath, ["-e", "throw Error('must not run')"], { cwd: f.dir, timeoutMs: 1000, signal: controller.signal });
  assert.equal(child.pid, undefined); assert.equal((await child.done).completion, "not-started");
});

test("KEEP-11A-003 ignored kill has bounded unconfirmed result, not fictitious closure", async () => {
  const f = setup("ignored-kill");
  const original = (f.adapter as unknown as { iso: PlatformIsolation }).iso;
  let attempts = 0;
  Object.defineProperty(f.adapter, "iso", { value: { ...original, killTree() { attempts++; } } });
  const child = f.adapter.start(process.execPath, ["-e", "const fs=require('fs');setTimeout(()=>fs.writeFileSync(process.argv[1],'finished'),200)", f.finish],
    { cwd: f.dir, timeoutMs: 50, terminationGraceMs: 20 });
  const result = await child.done;
  assert.equal(result.completion, "unconfirmed"); assert.equal(result.timedOut, true); assert.equal(attempts, 1);
  await started(f.finish); // finite owned child really continued; do not leave unbounded work
  assert.equal(readFileSync(f.finish, "utf8"), "finished");
});

test("KEEP-11A-003 process-group cancellation stops ordinary descendant writes", async () => {
  const f = setup("descendant"), controller = new AbortController();
  const grandchild = "const fs=require('fs');fs.writeFileSync(process.argv[1],'started');setTimeout(()=>fs.writeFileSync(process.argv[2],'late'),450)";
  const child = f.adapter.start(process.execPath, ["-e", "require('child_process').spawn(process.execPath,['-e',process.argv[1],process.argv[2],process.argv[3]],{stdio:'inherit'});setTimeout(()=>{},700)", grandchild, f.start, f.finish],
    { cwd: f.dir, timeoutMs: 1500, signal: controller.signal });
  await started(f.start); controller.abort();
  const result = await child.done;
  assert.equal(result.signal, "SIGKILL"); assert.equal(result.completion, "direct-child-closed");
  await pause(500); assert.equal(existsSync(f.finish), false);
});

test("KEEP-11A-003 closed parent with detached own-stdio descendant is not a group-empty claim", async () => {
  const f = setup("detached");
  const child = f.adapter.start(process.execPath, ["-e", "const c=require('child_process').spawn(process.execPath,['-e',\"setTimeout(()=>require('fs').writeFileSync(process.argv[1],'late'),200)\",process.argv[1]],{detached:true,stdio:'ignore'});c.unref()", f.finish], { cwd: f.dir, timeoutMs: 1500 });
  const result = await child.done;
  assert.equal(result.completion, "direct-child-closed"); assert.equal(existsSync(f.finish), false);
  await started(f.finish); // closes before detached descendant; explicitly not containment
});

test("KEEP-11A-003 inherited stdio delays close until finite descendant completes", async () => {
  const f = setup("stdio");
  const child = f.adapter.start(process.execPath, ["-e", "const c=require('child_process').spawn(process.execPath,['-e',\"setTimeout(()=>require('fs').writeFileSync(process.argv[1],'late'),100)\",process.argv[1]],{stdio:'inherit'});c.unref()", f.finish], { cwd: f.dir, timeoutMs: 1500 });
  const result = await child.done;
  assert.equal(result.completion, "direct-child-closed"); assert.equal(readFileSync(f.finish, "utf8"), "late");
});

test("KEEP-11A-003 shared signal listeners are removed per run without cancelling useful siblings", async () => {
  const controller = new AbortController(); let foreign = 0;
  const listener = () => foreign++; controller.signal.addEventListener("abort", listener);
  const before = getEventListeners(controller.signal, "abort").length;
  for (let i = 0; i < 8; i++) {
    const result = await withExecutionLifetime(async () => i, { signal: controller.signal });
    assert.equal(result.value, i); assert.equal(getEventListeners(controller.signal, "abort").length, before);
  }
  controller.abort(); assert.equal(foreign, 1); controller.signal.removeEventListener("abort", listener);
});

test("KEEP-11A-003 child close/cancel ordering cannot accept output after caller cancellation", async () => {
  const f = setup("close-race"), controller = new AbortController();
  class CancelAfterReturn extends ProcessIsolationAdapter {
    override async run(command: string, args: readonly string[], policy: IsolationPolicy) {
      const result = await super.run(command, args, policy); controller.abort(); return result;
    }
  }
  const command = new SandboxedCommandRunner({ command: process.execPath, args: ["-e", "console.log('ok 1 - passed')"], projectDir: f.dir, namespaceJail: false, adapter: new CancelAfterReturn() });
  const result = await command.run(f.dir, { signal: controller.signal });
  assert.ok(result.runnerError); assert.equal(result.results.length, 0);
  assert.equal(result.processCompletion, "direct-child-closed");
});

test("KEEP-11A-003 deadline and abort request one stop and clean adapter listeners", async () => {
  const f = setup("double"), controller = new AbortController();
  const original = (f.adapter as unknown as { iso: PlatformIsolation }).iso;
  let kills = 0;
  Object.defineProperty(f.adapter, "iso", { value: { ...original, killTree(child: Parameters<PlatformIsolation["killTree"]>[0]) { kills++; original.killTree(child); } } });
  const child = f.adapter.start(process.execPath, ["-e", "setTimeout(()=>{},500)"], { cwd: f.dir, timeoutMs: 25, signal: controller.signal });
  controller.abort(); controller.abort(); await child.done;
  assert.equal(kills, 1); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("KEEP-11A-003 post-spawn error cannot masquerade as no process", async () => {
  const f = setup("kill-error");
  const original = (f.adapter as unknown as { iso: PlatformIsolation }).iso;
  Object.defineProperty(f.adapter, "iso", { value: { ...original, killTree(child: Parameters<PlatformIsolation["killTree"]>[0]) { child.emit("error", new Error("synthetic post-spawn kill failure")); } } });
  const child = f.adapter.start(process.execPath, ["-e", "setTimeout(()=>require('fs').writeFileSync(process.argv[1],'late'),150)", f.finish], { cwd: f.dir, timeoutMs: 30, terminationGraceMs: 10 });
  const result = await child.done;
  assert.ok(child.pid); assert.equal(result.completion, "unconfirmed");
  assert.match(result.terminationError ?? "", /synthetic post-spawn/);
  await started(f.finish); // supplied error event, not an actual OS permission failure
});

test("KEEP-11A-003 late opaque success and rejection cannot revise terminal cancellation", async () => {
  for (const rejectLate of [false, true]) {
    let settle!: () => void;
    const promise = new Promise<number>((resolve, reject) => { settle = () => rejectLate ? reject(new Error("late")) : resolve(7); });
    const outcome = await withExecutionLifetime(async () => promise, { terminationGraceMs: 5 }, 5);
    assert.equal(outcome.completion, "unconfirmed"); assert.equal(outcome.value, undefined);
    settle(); await pause(5);
    assert.equal(outcome.completion, "unconfirmed"); assert.equal(outcome.value, undefined);
  }
});

test("KEEP-11A-003 opaque boundary timeout does not attest or promote late passing result", async () => {
  const f = setup("boundary"); let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  const boundary = new BoundaryExecutor("microvm", async () => { await pending; return { results: [{ name: "late", passed: true }] }; }, f.spine);
  const result = await boundary.runIsolated(f.command, { projectDir: f.dir, repoRef: f.dir, patchRisk: "low" }, { deadline: Date.now() + 5, terminationGraceMs: 5 });
  assert.equal(result.executed, true); assert.equal(result.completion, "unconfirmed"); assert.ok(result.result?.runnerError);
  finish(); await pending; await pause(5);
  assert.equal(boundary.attest({ attest() { throw new Error("cancelled run must not request attestation"); } }, f.dir, Date.now()), undefined);
});

test("KEEP-11A-003 durable event keeps invoked/unconfirmed/version after reconstruction", async () => {
  const f = setup("durable"), executor = new ProcessIsolationExecutor(f.spine, { timeoutMs: 5, terminationGraceMs: 5 });
  let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; });
  await executor.runIsolated({ async run() { await pending; return { results: [] }; } }, { projectDir: f.dir, repoRef: f.dir, patchRisk: "low" });
  finish(); await pending; await f.spine.seal();
  const restored = new Spine(new FileSpineStore(join(f.dir, "state"), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const event = restored.replay().find(e => e.payload.event === "isolated_execution")!;
  assert.equal(event.payload.executed, true); assert.equal(event.payload.completion, "unconfirmed"); assert.equal(event.payload.lifecycleContractVersion, 2);
});

test("KEEP-11A-003 invalid bounds refuse; far future deadline does not overflow into immediate timeout", async () => {
  let calls = 0;
  const run = async () => { calls++; await pause(5); return 7; };
  for (const context of [{ deadline: NaN }, { terminationGraceMs: -1 }, { terminationGraceMs: Infinity }]) {
    assert.equal((await withExecutionLifetime(run, context)).invoked, false);
  }
  assert.equal(calls, 0);
  assert.equal((await withExecutionLifetime(run, { deadline: Date.now() + 3_000_000_000 })).value, 7);
});

test("KEEP-11A-003 invalid adapter timeout has empty byte buffers and a configuration error", async () => {
  const f = setup("invalid");
  const child = f.adapter.start(process.execPath, [], { cwd: f.dir, timeoutMs: NaN });
  const result = await child.done;
  assert.equal(child.pid, undefined); assert.equal(result.stdoutBytes?.byteLength, 0); assert.equal(result.stderrBytes?.byteLength, 0);
  assert.equal(result.cancelled, false); assert.match(result.terminationError ?? "", /invalid execution timeout/);
});

test("KEEP-11A-003 unconfirmed child does not keep its caller alive through owned pipes", async () => {
  const f = setup("caller");
  const module = new URL("../src/infra/process_isolation.js", import.meta.url).href;
  const script = `import { ProcessIsolationAdapter } from ${JSON.stringify(module)};
    const adapter=new ProcessIsolationAdapter(); adapter.iso={...adapter.iso,killTree(){}};
    const run=adapter.start(process.execPath,['-e',"setTimeout(()=>require('fs').writeFileSync(process.argv[1],'late'),500)",process.argv[1]],{cwd:process.argv[2],timeoutMs:50,terminationGraceMs:20});
    const result=await run.done; console.log(JSON.stringify(result));`;
  const caller = f.adapter.start(process.execPath, ["--input-type=module", "-e", script, f.finish, f.dir], { cwd: f.dir, timeoutMs: 1500 });
  const result = await caller.done;
  assert.equal(result.code, 0); assert.equal(result.timedOut, false);
  assert.equal(JSON.parse(result.stdout).completion, "unconfirmed");
  assert.equal(existsSync(f.finish), false, "caller exits before the unconfirmed child's finite later work");
  await started(f.finish);
});

test("KEEP-11A-003 honest completed runner error retains ownership, never passing evidence", async () => {
  const f = setup("error-owner");
  class FailedCompiler extends SandboxedCommandRunner {
    override async run() { return { results: [], runnerError: "compile failed" }; }
  }
  const runner = new IsolatedTestRunner(new FailedCompiler({ command: process.execPath, args: [], projectDir: f.dir }), f.executor, f.dir);
  const result = await runner.runWithEvidence(f.dir, true);
  assert.equal(consumeVerifiedIsolatedRunOutcome(result, f.dir), true);
  assert.equal(result.result?.runnerError, "compile failed"); assert.equal(result.result?.results.length, 0);
  assert.equal(f.executor.attest({ attest() { throw Error("no success attestation"); } }, f.dir, Date.now()), undefined);
});

test("KEEP-11A-003 command result retains post-spawn error reason without invented user cancellation", async () => {
  const f = setup("error-reason");
  const original = (f.adapter as unknown as { iso: PlatformIsolation }).iso;
  Object.defineProperty(f.adapter, "iso", { value: { ...original, killTree(child: Parameters<PlatformIsolation["killTree"]>[0]) { child.emit("error", new Error("synthetic post-spawn failure")); } } });
  const runner = new SandboxedCommandRunner({ command: process.execPath, args: ["-e", "setTimeout(()=>require('fs').writeFileSync(process.argv[1],'late'),150)", f.finish],
    projectDir: f.dir, timeoutMs: 30, adapter: f.adapter, namespaceJail: false });
  const result = await runner.run(f.dir, { terminationGraceMs: 10 });
  assert.match(result.runnerError ?? "", /synthetic post-spawn failure/);
  assert.doesNotMatch(result.runnerError ?? "", /test run cancelled/);
  await started(f.finish);
});

test("KEEP-11A-003 earlier slow run cannot restore instance evidence after newer refusal", async () => {
  const f = setup("attest-race"), controller = new AbortController();
  let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; });
  const spec = { projectDir: f.dir, repoRef: f.dir, patchRisk: "low" as const };
  const old = f.executor.runIsolated({ async run() { await pending; return { results: [{ name: "old", passed: true }] }; } }, spec);
  controller.abort();
  assert.equal((await f.executor.runIsolated(f.command, spec, { signal: controller.signal })).executed, false);
  finish(); await old;
  assert.equal(f.executor.attest({ attest() { throw Error("stale evidence reused"); } }, f.dir, Date.now()), undefined);
});

test("KEEP-11A-003 boundary refusal cannot reuse a preceding run's attestation", async () => {
  const f = setup("attest-refusal"); let calls = 0;
  const boundary = new BoundaryExecutor("process", async () => { calls++; return { results: [{ name: "useful", passed: true }] }; });
  const spec = { projectDir: f.dir, repoRef: f.dir, patchRisk: "low" as const };
  const attestor = { attest: (claim: IsolationClaim) => ({ claim, signature: "synthetic" }) };
  assert.equal((await boundary.runIsolated(f.command, spec)).executed, true);
  assert.ok(boundary.attest(attestor, f.dir, Date.now()));
  assert.equal((await boundary.runIsolated(f.command, { ...spec, patchRisk: "high" })).executed, false);
  assert.equal(calls, 1); assert.equal(boundary.attest(attestor, f.dir, Date.now()), undefined);
});
