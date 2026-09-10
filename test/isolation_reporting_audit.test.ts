import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProcessIsolationAdapter, type IsolationPolicy, type IsolatedRunResult } from "../src/infra/process_isolation.js";
import { SandboxedCommandRunner, sandboxedRunnerFor, type SandboxedCommandConfig } from "../src/solve/sandboxed_runner.js";
import { BoundaryExecutor, buildEnforcingRunner, IsolatedTestRunner, MinimumTierExecutor, ProcessIsolationExecutor } from "../src/isolation/isolated_executor.js";
import { processPlanObservation } from "../src/infra/isolation_backend.js";
import { validate } from "../src/solve/validate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { createRunAttestationChannel } from "../src/isolation/isolation_attestation.js";
import { isolationCeilingFromEvidence } from "../src/isolation/isolation_tier.js";

class UnavailableNamespaceAdapter extends ProcessIsolationAdapter {
  readonly results: IsolatedRunResult[] = [];
  override async run(command: string, args: readonly string[], policy: IsolationPolicy) {
    const result = await super.run(command, args, { ...policy, ...(policy.namespaceJail ? { namespaceJail: { ...policy.namespaceJail,
      support: { userNs: false, mountNs: false, netNs: false, pidNs: false } } } : {}) });
    this.results.push(result); return result;
  }
}
type Observation = { namespacePolicy: string; requestedNamespaces: string[]; degraded: string[]; namespaceSetup: string };
const observation = (value: unknown): Observation | undefined => (value as { processIsolation?: Observation }).processIsolation;
function setup(track: string, namespaceJail = true) {
  const root = mkdtempSync(join(tmpdir(), `keep-iso-report-${track}-`)), dir = join(root, "project"), outside = join(root, "sibling");
  mkdirSync(dir); const adapter = new UnavailableNamespaceAdapter();
  const spine = new Spine(new FileSpineStore(join(root, "state")), new InProcessLock(), new SchemaRegistry());
  const command = new SandboxedCommandRunner({ command: process.execPath, args: ["-e", "require('fs').writeFileSync(process.argv[1],'synthetic');console.log('ok 1 - useful')", outside],
    projectDir: dir, namespaceJail, adapter, timeoutMs: 2000 });
  return { root, dir, outside, adapter, spine, command };
}

for (const track of ["personal", "alpha"]) {
  test(`KEEP-11A-001 ${track}: real unavailable-plan degradation survives command/validation/event`, async () => {
    const f = setup(track);
    const executor = new ProcessIsolationExecutor(f.spine);
    const wrapped = new IsolatedTestRunner(f.command, executor, f.dir);
    const result = await validate(f.dir, wrapped);
    assert.equal(result.testsPassed, true); assert.equal(readFileSync(f.outside, "utf8"), "synthetic");
    const raw = f.adapter.results[0]!;
    assert.deepEqual(raw.degraded, ["mount-ns", "pid-ns", "net-ns"]);
    const report = observation(result);
    assert.ok(report, "validation must carry the effective-boundary observation");
    assert.deepEqual(report.degraded, raw.degraded); assert.equal(report.namespacePolicy, "best-effort");
    assert.equal(report.namespaceSetup, "unavailable");
    const channel = createRunAttestationChannel();
    const checked = channel.verifier.verify(executor.attest(channel.attestor, f.dir, Date.now()));
    assert.ok(checked.measuredDegradations.includes("mount-ns"));
    assert.equal(isolationCeilingFromEvidence(checked), "refuse-risky");
    const event = f.spine.currentEvents().find(e => e.payload.event === "isolated_execution")!;
    assert.deepEqual(observation(event.payload), report);
    await f.spine.seal();
    const restored = new Spine(new FileSpineStore(join(f.root, "state")), new InProcessLock(), new SchemaRegistry());
    assert.deepEqual(observation(restored.replay().find(e => e.payload.event === "isolated_execution")!.payload), report);
  });
  test(`KEEP-11A-001 ${track}: explicit process fallback remains useful and visible`, async () => {
    const f = setup(track, false);
    const result = await f.command.run(f.dir);
    assert.equal(result.runnerError, undefined); assert.equal(readFileSync(f.outside, "utf8"), "synthetic");
    assert.equal(observation(result)?.namespacePolicy, "disabled");
    assert.equal(observation(result)?.namespaceSetup, "not-requested");
  });
  test(`KEEP-11A-001 ${track}: existing required stronger tier refuses before child/sibling write`, async () => {
    const f = setup(track);
    const wrapped = new IsolatedTestRunner(f.command, new MinimumTierExecutor(new ProcessIsolationExecutor(f.spine), "container", f.spine), f.dir);
    const result = await validate(f.dir, wrapped);
    assert.equal(result.testsPassed, false); assert.equal(f.adapter.results.length, 0); assert.equal(existsSync(f.outside), false);
    assert.match(result.detail, /required container/);
  });
  test(`KEEP-11A-001 ${track}: unknown namespace policy refuses before adapter entry`, async () => {
    const f = setup(track);
    const config = { command: process.execPath, args: ["-e", "require('fs').writeFileSync(process.argv[1],'bad')", f.outside],
      projectDir: f.dir, adapter: f.adapter, namespaceJail: "unknown-required-policy" } as unknown as SandboxedCommandConfig;
    const result = await validate(f.dir, new IsolatedTestRunner(new SandboxedCommandRunner(config), new ProcessIsolationExecutor(f.spine), f.dir));
    assert.equal(result.testsPassed, false); assert.equal(f.adapter.results.length, 0); assert.equal(existsSync(f.outside), false);
    assert.match(result.detail, /unsupported namespaceJail policy/);
    assert.equal(result.processIsolation?.namespacePolicy, "unsupported");
    assert.deepEqual(observation(f.spine.currentEvents().find(e => e.payload.event === "isolated_execution")!.payload), result.processIsolation);
  });
}

test("KEEP-11A-001 missing custom-adapter observation is unknown, not clean containment", async () => {
  const f = setup("missing");
  class MissingObservation extends ProcessIsolationAdapter {
    override async run(): Promise<IsolatedRunResult> {
      return { code: 0, signal: null, stdout: "ok 1 - synthetic", stderr: "", timedOut: false, truncated: false, durationMs: 0 };
    }
  }
  const runner = new SandboxedCommandRunner({ command: "synthetic", args: [], projectDir: f.dir, adapter: new MissingObservation() });
  const executor = new ProcessIsolationExecutor(f.spine);
  const result = await validate(f.dir, new IsolatedTestRunner(runner, executor, f.dir));
  assert.equal(result.testsPassed, true, "synthetic result is separate from containment assurance");
  assert.equal(observation(result)?.namespaceSetup, "unverified");
  const channel = createRunAttestationChannel();
  const checked = channel.verifier.verify(executor.attest(channel.attestor, f.dir, Date.now()));
  assert.equal(isolationCeilingFromEvidence(checked), "refuse-risky");
});

test("KEEP-11A-001 a plan with every namespace available still has no verified setup", () => {
  const report = processPlanObservation({ projectDir: "/synthetic", maxOpenFiles: 30 }, 1, []);
  assert.equal(report.namespaceSetup, "unverified"); assert.equal(report.rlimitSetup, "unverified");
  assert.deepEqual(report.requestedNamespaces, ["mount-ns", "pid-ns", "net-ns"]);
  assert.deepEqual(report.requestedRlimits, ["cpuLimit", "open-files"]);
  assert.equal(Object.isFrozen(report), true); assert.equal(Object.isFrozen(report.degraded), true);
});

test("KEEP-11A-001 allowNet changes the request, never certifies effective networking", () => {
  const degraded = ["mount-ns", "pid-ns"];
  const report = processPlanObservation({ projectDir: "/synthetic", allowNet: true }, undefined, degraded);
  degraded.length = 0;
  assert.deepEqual(report.degraded, ["mount-ns", "pid-ns"]);
  assert.deepEqual(report.requestedNamespaces, ["mount-ns", "pid-ns"]);
  assert.equal(report.namespaceSetup, "unavailable");
});

for (const factory of ["runnerFor", "buildEnforcingRunner"]) {
  test(`KEEP-11A-001 ${factory} preserves explicit useful fallback`, async () => {
    const f = setup(factory);
    const args = ["-e", "require('fs').writeFileSync(process.argv[1],'useful');console.log('ok 1 - fallback')", f.outside];
    const runner = factory === "runnerFor"
      ? sandboxedRunnerFor(() => f.dir, process.execPath, args, { namespaceJail: false })(f.dir)
      : buildEnforcingRunner(f.dir, process.execPath, args, { namespaceJail: false });
    const result = await validate(f.dir, runner);
    assert.equal(result.testsPassed, true); assert.equal(readFileSync(f.outside, "utf8"), "useful");
    assert.equal(result.processIsolation?.namespacePolicy, "disabled");
  });
}

for (const kind of ["product-failure", "missing-command", "timeout"]) {
  test(`KEEP-11A-001 ${kind} retains its available process observations`, async () => {
    const f = setup(kind);
    const runner = new SandboxedCommandRunner({ command: kind === "missing-command" ? join(f.dir, "no-command") : process.execPath,
      args: ["-e", kind === "timeout" ? "setTimeout(()=>{},5000)" : "console.log('not ok 1 - failed');process.exit(1)"],
      projectDir: f.dir, namespaceJail: false, timeoutMs: kind === "timeout" ? 40 : 2000 });
    const result = await validate(f.dir, new IsolatedTestRunner(runner, new ProcessIsolationExecutor(f.spine), f.dir));
    assert.equal(result.testsPassed, false); assert.equal(result.processIsolation?.namespacePolicy, "disabled");
    assert.deepEqual(observation(f.spine.currentEvents().find(e => e.payload.event === "isolated_execution")!.payload), result.processIsolation);
  });
}

test("KEEP-11A-001 cancellation after return and boundary events retain the same report", async () => {
  const f = setup("returned-cancel"), controller = new AbortController();
  const report = processPlanObservation(undefined, undefined, []);
  const boundary = new BoundaryExecutor("process", async () => {
    controller.abort(); return { results: [{ name: "late", passed: true }], processIsolation: report };
  }, f.spine);
  const result = await validate(f.dir, new IsolatedTestRunner(f.command, boundary, f.dir), {}, { signal: controller.signal });
  assert.equal(result.testsPassed, false); assert.deepEqual(result.processIsolation, report);
  assert.deepEqual(observation(f.spine.currentEvents().find(e => e.payload.event === "isolated_execution")!.payload), report);
});

for (const missing of [false, true]) {
  test(`KEEP-11A-001 process BoundaryExecutor appraisal retains ${missing ? "missing" : "actual degraded"} setup evidence`, async () => {
    const f = setup(`boundary-appraisal-${missing}`);
    const boundary = new BoundaryExecutor("process", async (runner, spec, context) => {
      const result = await runner.run(spec.repoRef, context);
      if (!missing) return result;
      const { processIsolation: _discarded, ...rest } = result;
      return rest;
    }, f.spine);
    const before = createRunAttestationChannel();
    const unrun = before.verifier.verify(boundary.attest(before.attestor, f.dir, Date.now()));
    assert.ok(unrun.measuredDegradations.includes("missing-process-isolation-observation"));
    assert.equal(isolationCeilingFromEvidence(unrun), "refuse-risky");
    const result = await validate(f.dir, new IsolatedTestRunner(f.command, boundary, f.dir));
    assert.equal(result.testsPassed, true);
    assert.equal(readFileSync(f.outside, "utf8"), "synthetic", "the fallback performed useful real work, not isolation");
    const channel = createRunAttestationChannel();
    const attestation = boundary.attest(channel.attestor, f.dir, Date.now());
    assert.ok(attestation);
    const checked = channel.verifier.verify(attestation);
    assert.ok(checked.measuredDegradations.includes(missing ? "missing-process-isolation-observation" : "mount-ns"));
    assert.equal(isolationCeilingFromEvidence(checked), "refuse-risky");
    if (!missing) assert.deepEqual(observation(f.spine.currentEvents().find(e => e.payload.event === "isolated_execution")!.payload), result.processIsolation);
  });
}

test("KEEP-11A-001 malformed adapter observation cannot claim verified containment", async () => {
  const f = setup("malformed");
  class MalformedObservation extends ProcessIsolationAdapter {
    override async run(): Promise<IsolatedRunResult> {
      return { code: 0, signal: null, stdout: "ok 1 - synthetic", stderr: "", timedOut: false, truncated: false, durationMs: 0,
        degraded: ["mount-ns"], processIsolation: { namespaceSetup: "verified", privateExtra: "do-not-persist" } as never };
    }
  }
  const runner = new SandboxedCommandRunner({ command: "synthetic", args: [], projectDir: f.dir, adapter: new MalformedObservation() });
  const result = await validate(f.dir, new IsolatedTestRunner(runner, new ProcessIsolationExecutor(f.spine), f.dir));
  assert.equal(result.testsPassed, true); assert.equal(result.processIsolation?.basis, "missing-adapter-observation");
  assert.equal(result.processIsolation?.namespaceSetup, "unverified");
  assert.deepEqual(result.processIsolation?.degraded, ["mount-ns"]);
  assert.doesNotMatch(JSON.stringify(f.spine.currentEvents()), /do-not-persist/);
});

test("KEEP-11A-001 real host default reports unavailable or unverified, never established confinement", async () => {
  const f = setup("host-default");
  // Real host probe and real command, no injected support map. This only checks
  // honest reporting; it is not a successful nested-jail qualification.
  const runner = new SandboxedCommandRunner({ command: process.execPath, args: ["-e", "console.log('ok 1 - host')"], projectDir: f.dir, timeoutMs: 2000 });
  const result = await validate(f.dir, new IsolatedTestRunner(runner, new ProcessIsolationExecutor(f.spine), f.dir));
  assert.equal(result.testsPassed, true);
  assert.equal(result.processIsolation?.basis, "adapter-spawn-plan");
  assert.ok(["unavailable", "unverified"].includes(result.processIsolation!.namespaceSetup));
  assert.equal(result.processIsolation?.rlimitSetup, "unverified");
});

test("KEEP-11A-001 observation survives cancellation during post-test vetting", async () => {
  const f = setup("vet-cancel", false), controller = new AbortController();
  const result = await validate(f.dir, f.command, { vet: async () => { controller.abort(); return true; } }, { signal: controller.signal });
  assert.equal(result.testsPassed, false); assert.equal(result.processIsolation?.namespacePolicy, "disabled");
  assert.equal(readFileSync(f.outside, "utf8"), "synthetic");
});
