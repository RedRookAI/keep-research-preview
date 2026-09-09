import { test } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { scanIngress, assertClosedWorld, INGRESS_SWEEP_SENTINEL } from "../src/ingress/ingress_scan_port.js";

// Increment 3 (step C) — BUILD-TIME CLOSED-WORLD SCANNER (static closure). Frontier property: no listener / callback /
// code-generation construct exists OUTSIDE an approved adapter module — else the sealed registry is bypassable. Proven
// by disproof — the fixture tree contains a deliberate violation per construct; neutering a classifier arm in
// tools/ingress_sweep.mjs drops that construct from the findings and reddens the matching assertion.

// The compiled test runs from dist/test; the repo root is two levels up, where tools/ + test/fixtures/ live in source.
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const fixtureRoot = join(repoRoot, "test", "fixtures", "ingress_scan");
const enginePath = join(repoRoot, "tools", "ingress_sweep.mjs");

test("scanner flags every forbidden construct in a non-allowlisted module", () => {
  const res = scanIngress({ root: fixtureRoot, allow: ["adapter.ts"], enginePath });
  const files = new Set(res.findings.map((f) => f.file));
  assert.ok(files.has("violations.ts"), "violations.ts must be flagged");
  assert.ok(!files.has("adapter.ts"), "an allowlisted adapter is not flagged");
  assert.ok(!files.has("clean.ts"), "a clean module is not flagged");
  const c = new Set(res.findings.map((f) => f.construct));
  assert.ok(c.has("eval"));
  assert.ok(c.has("new-Function"));
  assert.ok(c.has("dynamic-import"));
  assert.ok(c.has("addEventListener"));
  assert.ok(c.has("computed-require"));
  assert.ok(c.has("new-Worker"));
  assert.ok(c.has("computed-member-call"));
  assert.ok([...c].some((x) => x.startsWith("listener:")), "a raw server listener is flagged");
  assert.ok([...c].some((x) => x.startsWith("timer:")), "a timer is flagged");
  assert.ok([...c].some((x) => x.startsWith("process-handler:")), "a process signal handler is flagged");
  // the trivial per-file BYPASSES a naive scanner misses:
  assert.ok(c.has("Function-call"), "Function(code) without new is flagged");
  assert.ok([...c].some((x) => x.startsWith("vm-codegen:")), "vm code generation is flagged");
  assert.ok([...c].some((x) => x.startsWith("forbidden-module-import:")), "importing an ambient-authority module is flagged");
  assert.ok(c.has("forbidden-ref:eval"), "same-file alias `const e = eval` is flagged");
  assert.ok(c.has("computed-member-call"), "obj[expr]() ambiguity is flagged");
  assert.ok(c.has("constructor-codegen"), "(fn).constructor(code) Function-constructor codegen is flagged");
  assert.ok([...c].some((x) => x.startsWith("tainted-alias-call:")), "extract-to-local-then-call (const e=globalThis.eval; e(x)) is flagged");
  assert.ok(c.has("reflected-invoke"), "globalThis.eval.call(null, src) is flagged");
  assert.ok(c.has("reflected-apply"), "Reflect.apply(globalThis.eval, ...) is flagged");
  assert.ok(c.has("forbidden-member:eval"), "reading globalThis.eval as a value (object literal / ternary launder) is flagged");
  assert.ok([...c].some((x) => x.startsWith("destructured-forbidden:")), "const { eval: e } = globalThis is flagged");
  assert.ok([...c].some((x) => x.startsWith("process-handler-alias:")), "const p = process; p.on(...) is flagged");
  assert.ok(c.has("computed-global-access"), "globalThis[computed] (incl. via a global alias) is flagged");
  assert.ok([...c].some((x) => x.startsWith("object-key-forbidden:")), "destructuring-assignment ({eval:e}=globalThis) is flagged");
  assert.ok(c.has("conditional-new"), "new (cond ? globalThis.Function : X)(...) is flagged");
  // r18 batch: extension coverage, process callback API, event-handler property, schedulers, module loaders
  assert.ok(res.findings.some((fd) => fd.file === "extra.mts"), "a forbidden construct in a .mts file is scanned + flagged");
  assert.ok([...c].some((x) => x.startsWith("event-handler-property:")), "window.onmessage = cb is flagged");
  assert.ok([...c].some((x) => x === "timer:queueMicrotask" || x === "timer:nextTick"), "scheduler (queueMicrotask/nextTick) is flagged");
  assert.ok([...c].some((x) => x.includes("setUncaughtExceptionCaptureCallback")), "process.setUncaughtExceptionCaptureCallback is flagged");
  assert.ok([...c].some((x) => x.includes("getBuiltinModule")), "process.getBuiltinModule is flagged");
  // `server[\"listen\"]()` (string-literal element access) counts as a listener, not a computed-member call
  assert.ok([...res.findings].some((f) => f.construct === "listener:listen"), "string-literal element access is a listener");
});

test("assertClosedWorld throws on findings, passes when the world is closed", () => {
  const withViolations = scanIngress({ root: fixtureRoot, allow: ["adapter.ts"], enginePath });
  assert.throws(() => assertClosedWorld(withViolations), /closed-world ingress violation/);
  // allowlisting every module (as if each were an audited adapter) => no findings => closed
  const closed = scanIngress({ root: fixtureRoot, allow: ["violations.ts", "adapter.ts", "extra.mts"], enginePath });
  assert.deepEqual(closed.findings, []);
  assert.doesNotThrow(() => assertClosedWorld(closed));
  assert.equal(closed.scanned, 1); // only clean.ts scanned; the three allowlisted skipped
});

test("fail-closed: a missing engine, not a false 'all clear'", () => {
  assert.throws(
    () => scanIngress({ root: fixtureRoot, enginePath: join(repoRoot, "tools", "ingress_sweep_DOES_NOT_EXIST.mjs") }),
    /fail-closed/,
  );
});

test("the success sentinel is required (a crashed scan can never certify by silence)", () => {
  // sanity: the port exports the exact sentinel the engine stamps
  assert.equal(INGRESS_SWEEP_SENTINEL, "INGRESS-SWEEP-OK");
});
