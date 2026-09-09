import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  measureModule,
  verifyTcb,
  pinTcb,
  runTcbSelfCheck,
  TCB_MODULE_PATHS,
  type MeasuredModule,
  type TcbManifest,
} from "../src/tcb/verify_tcb.js";
import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

// Core Addition A — verify-minimal-TCB. These measure the REAL trusted-core source files, pin them,
// and prove any drift (changed / added / missing module, or a new dependency) is caught. Verify by
// disproof.

// tests run from dist/test/, so the repo root (where src/*.ts lives) is two levels up.
const ROOT = join(import.meta.dirname, "..", "..");

/** Measure the real TCB source files from disk. */
function measureRealTcb(): Map<string, MeasuredModule> {
  const m = new Map<string, MeasuredModule>();
  for (const p of TCB_MODULE_PATHS) {
    m.set(p, measureModule(readFileSync(join(ROOT, p), "utf8")));
  }
  return m;
}

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "tcb-spine-"))), new InProcessLock(), new SchemaRegistry());
}

test("TCB: the real enumerated trusted core verifies against its pinned manifest", () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {}); // allowed deps default to the modules' own current imports
  assert.equal(verifyTcb(manifest, measured).verified, true);
});

test("TCB: a CHANGED trusted-module hash → drift", () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {});
  const tampered = new Map(measured);
  const victim = TCB_MODULE_PATHS[0]!;
  tampered.set(victim, { hash: "0".repeat(64), imports: measured.get(victim)!.imports });
  const v = verifyTcb(manifest, tampered);
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.drifts.some((d) => d === `changed-hash:${victim}`));
});

test("TCB: an ADDED unexpected trusted module → drift (minimality violated)", () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {});
  const extra = new Map(measured);
  extra.set("src/evil/backdoor.ts", { hash: "a".repeat(64), imports: [] });
  const v = verifyTcb(manifest, extra);
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.drifts.some((d) => d.startsWith("unexpected-tcb-module")));
});

test("TCB: a MISSING trusted module → drift (a barrier removed)", () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {});
  const short = new Map(measured);
  const removed = TCB_MODULE_PATHS[2]!;
  short.delete(removed);
  const v = verifyTcb(manifest, short);
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.drifts.some((d) => d === `missing-tcb-module:${removed}`));
});

test("TCB: a trusted module gaining a NEW disallowed dependency → drift (TCB silently expanded)", () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {});
  const victim = TCB_MODULE_PATHS[0]!;
  const withNewDep = new Map(measured);
  // same hash pin won't match if we change imports+content, so simulate: keep pinned hash, add an import
  // by re-pinning THIS module's hash to the tampered content's hash but leaving allowedDeps as the golden.
  const tamperedSource = readFileSync(join(ROOT, victim), "utf8") + '\nimport { x } from "../evil/sink.js";\n';
  const meas = measureModule(tamperedSource);
  // pin the manifest to the tampered hash so ONLY the dependency check fires (isolate the drift kind)
  const isolated: TcbManifest = {
    modules: manifest.modules.map((m) => (m.path === victim ? { ...m, pinnedHash: meas.hash } : m)),
  };
  withNewDep.set(victim, meas);
  const v = verifyTcb(isolated, withNewDep);
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.drifts.some((d) => d.startsWith(`new-dependency:${victim}`)));
});

test("TCB: the self-check records the result to the spine and returns intact=false on drift", async () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {});
  const spine = newSpine();
  const tampered = new Map(measured);
  tampered.set(TCB_MODULE_PATHS[1]!, { hash: "0".repeat(64), imports: [] });
  const before = spine.replay().length;
  const res = runTcbSelfCheck(manifest, tampered, spine);
  await spine.seal();
  assert.equal(res.intact, false);
  assert.ok(spine.replay().length > before, "the drift was recorded to the spine");
  assert.ok(spine.replay().some((e) => (e.payload as Record<string, unknown>)?.event === "tcb.drift"));
});

test("TCB: an intact self-check returns intact=true and records tcb.verified", async () => {
  const measured = measureRealTcb();
  const manifest = pinTcb(measured, {});
  const spine = newSpine();
  const res = runTcbSelfCheck(manifest, measured, spine);
  await spine.seal();
  assert.equal(res.intact, true);
  assert.ok(spine.replay().some((e) => (e.payload as Record<string, unknown>)?.event === "tcb.verified"));
});

// ── the gate veto ──
const green: GateInputs = { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true };

test("TCB+GATE: a drifted TCB vetoes an otherwise-green op → human-hold", () => {
  const r = composeGate({ ...green, tcbIntact: false }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("tcb-drift"));
});

test("TCB+GATE: an intact TCB does not veto", () => {
  assert.equal(composeGate({ ...green, tcbIntact: true }, defaultGatePolicy()).route, "auto-proceed");
});
