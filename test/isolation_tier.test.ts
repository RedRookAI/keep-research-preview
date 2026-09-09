import { test } from "node:test";
import assert from "node:assert/strict";
import { selectTier, isolationAutonomyCeiling, executionAllowed, TIER_STRENGTH, type IsolationCapabilities } from "../src/isolation/isolation_tier.js";
import { ProcessIsolationExecutor, BoundaryExecutor, selectExecutor, isPathWithinProject } from "../src/isolation/isolated_executor.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function newSpine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-iso-"))), new InProcessLock(), new SchemaRegistry()); }
const caps = (o: Partial<IsolationCapabilities>): IsolationCapabilities => ({ kvmAvailable: false, gvisorAvailable: false, containerRuntime: false, canScopeProcess: false, ...o });
const passingRunner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

test("INVARIANT: selectTier picks the STRONGEST available and declares it honestly", () => {
  assert.equal(selectTier(caps({ kvmAvailable: true })).tier, "microvm");
  assert.equal(selectTier(caps({ gvisorAvailable: true })).tier, "gvisor");
  assert.equal(selectTier(caps({ containerRuntime: true })).tier, "container");
  assert.equal(selectTier(caps({ canScopeProcess: true })).tier, "process");
  assert.equal(selectTier(caps({})).tier, "none");
});

test("INVARIANT: honesty — no microVM claim without KVM (back-of-house laptop is truthful)", () => {
  const sel = selectTier(caps({ canScopeProcess: true })); // a laptop: can scope a process, no KVM
  assert.equal(sel.tier, "process");
  assert.ok(!/microVM/i.test(sel.summary) || /back-of-house/i.test(sel.summary), "does not falsely claim microVM");
});

test("INVARIANT: isolation strength feeds the autonomy ceiling (2nd/3rd-order feedback)", () => {
  // Stronger isolation → higher ceiling.
  assert.equal(isolationAutonomyCeiling("microvm"), "full");
  assert.equal(isolationAutonomyCeiling("container"), "reduced");
  assert.equal(isolationAutonomyCeiling("process"), "minimal");
  assert.equal(isolationAutonomyCeiling("none"), "refuse-risky");
  assert.ok(TIER_STRENGTH.microvm > TIER_STRENGTH.process, "strength ordering holds");
});

test("INVARIANT: 'none' isolation REFUSES risky execution (not silently run)", () => {
  assert.equal(executionAllowed("none", "high").allowed, false);
  assert.equal(executionAllowed("none", "medium").allowed, false);
  assert.equal(executionAllowed("none", "low").allowed, true);
});

test("INVARIANT: process isolation refuses a HIGH-risk patch (insufficient boundary)", () => {
  assert.equal(executionAllowed("process", "high").allowed, false);
  assert.equal(executionAllowed("process", "medium").allowed, true);
});

test("INVARIANT: ProcessIsolationExecutor runs a scoped test + audits to the spine", async () => {
  const spine = newSpine();
  const exec = new ProcessIsolationExecutor(spine);
  const out = await exec.runIsolated(passingRunner, { projectDir: "/proj", repoRef: "/proj/work", patchRisk: "low" });
  assert.equal(out.executed, true);
  assert.equal(out.tier, "process");
  await spine.seal();
  assert.ok(spine.replay().some((e: { payload?: { event?: string } }) => e.payload?.event === "isolated_execution"), "execution audited");
});

test("INVARIANT: a path-traversal escape outside the project dir is REFUSED", () => {
  assert.equal(isPathWithinProject("/proj", "/proj/work"), true);
  assert.equal(isPathWithinProject("/proj", "/proj/../etc/passwd"), false);
  assert.equal(isPathWithinProject("/proj", "/home/user/.ssh/id_rsa"), false);
  assert.equal(isPathWithinProject("/proj", "../../etc"), false);
});

test("INVARIANT: ProcessIsolationExecutor refuses execution that escapes the project scope", async () => {
  const exec = new ProcessIsolationExecutor(newSpine());
  const out = await exec.runIsolated(passingRunner, { projectDir: "/proj", repoRef: "/home/user/evil", patchRisk: "low" });
  assert.equal(out.executed, false);
  assert.match(out.refusedReason!, /escapes the project/);
});

test("INVARIANT: a strong-tier BoundaryExecutor with NO host boundary REFUSES rather than running unisolated (fail-safe)", async () => {
  const exec = new BoundaryExecutor("microvm", undefined, newSpine()); // declared microvm but no boundary wired
  const out = await exec.runIsolated(passingRunner, { projectDir: "/proj", repoRef: "/proj/work", patchRisk: "medium" });
  assert.equal(out.executed, false, "does NOT silently fall back to running unisolated");
  assert.match(out.refusedReason!, /VERIFIED-SEAM|no host boundary/);
});

test("INVARIANT: a wired boundary runs under the strong tier", async () => {
  let ran = false;
  const boundaryRun = async () => { ran = true; return { results: [{ name: "t", passed: true }] } as TestRunResult; };
  const exec = new BoundaryExecutor("microvm", boundaryRun, newSpine());
  const out = await exec.runIsolated(passingRunner, { projectDir: "/proj", repoRef: "/proj/work", patchRisk: "high" });
  assert.equal(out.executed, true);
  assert.equal(ran, true);
});

test("selectExecutor picks process isolation for the back-of-house laptop", () => {
  const exec = selectExecutor(caps({ canScopeProcess: true }));
  assert.equal(exec.tier, "process");
});
