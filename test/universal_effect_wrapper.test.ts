import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import {
  CapabilityHub,
  capabilityInvocationDigest,
  scanForBypasses,
  verifyCompleteMediation,
  EFFECTFUL_ENTRY_POINTS,
  GATE_MARKER,
  type CapabilityAdapter,
  type CapabilityResult,
  type EffectfulEntryPoint,
} from "../src/ecosystem/capability_port.js";

// BUILD-ORDER 8.43 — the UNIVERSAL EXTERNAL-EFFECT WRAPPER (Policy Enforcement Point). These are the PROOF that
// external-effect mediation is COMPLETE (Saltzer & Schroeder): every capability call is checked against the RESOLVED
// 8.44B class at ONE chokepoint (CapabilityHub.invoke), unknown => HOLD, and an INVENTORY + scan proves no effectful
// entry point reaches the world un-gated. Deterministic fixtures, no network.

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-uew-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

test("dispatch claim captures nested args, permit and context before awaiting", async () => {
  const spine = newSpine(), hub = new CapabilityHub(spine);
  const args = { nested: { amount: 1.25 } };
  const inv = { capabilityId: "capture", operation: "email.send", args };
  const descriptor = { id: "capture", kind: "connector" as const, name: "capture", trust: "verified" as const, credentialId: "fixture" };
  const permit = { tenant: "keep.n1.default", agent: "owner", operationId: "original", admissionDigest: "a".repeat(64), effectDigest: capabilityInvocationDigest(inv, descriptor) };
  let resume!: () => void;
  const wait = new Promise<void>(resolve => { resume = resolve; });
  let suppliedDigest = "", entries = 0;
  hub.installFleetDispatchClaimer(async (captured, digest) => {
    suppliedDigest = digest;
    await wait;
    assert.equal(captured.operationId, "original");
    return true;
  });
  assert.throws(() => hub.installFleetPermitVerifier(async () => true), /already installed/);
  hub.register({ descriptor, invoke: async (captured, context) => {
    entries++;
    assert.deepEqual(captured.args, { nested: { amount: 1.25 } });
    assert.equal(capabilityInvocationDigest(captured, descriptor), suppliedDigest);
    assert.equal(context?.fleetOperation?.operationId, "original");
    assert.ok(Object.isFrozen(captured.args["nested"]));
    assert.ok(Object.isFrozen(context?.fleetOperation));
    return { ok: true };
  } });
  const pending = hub.invoke(inv, { confirm: true, fleetPermit: permit });
  args.nested.amount = 999;
  permit.operationId = "changed";
  inv.operation = "db.drop";
  resume();
  assert.equal((await pending).ok, true);
  assert.equal(entries, 1);
  const request = spine.currentEvents().find(event => event.payload["phase"] === "request")!;
  assert.deepEqual(request.payload["args"], { nested: { amount: 1.25 } });
});

test("claim failure preserves uncertainty without entering an adapter", async () => {
  for (const throws of [false, true]) {
    const hub = new CapabilityHub(newSpine()); let calls = 0;
    hub.installFleetDispatchClaimer(async () => { if (throws) throw Error("unknown claim"); return false; });
    hub.register({ descriptor: { id: "sink", kind: "connector", name: "sink", credentialId: "fixture", trust: "verified" }, invoke: async () => { calls++; return { ok: true }; } });
    const result = await hub.invoke({ capabilityId: "sink", operation: "email.send", args: {} }, { confirm: true,
      fleetPermit: { tenant: "keep.n1.default", agent: "owner", operationId: "one", admissionDigest: "a".repeat(64), effectDigest: "b".repeat(64) } });
    assert.equal(result.ok, false); assert.equal(result.held, false);
    assert.deepEqual(result.output, { indeterminate: true }); assert.equal(calls, 0);
  }
});

test("hub owns non-dispatch knowledge, including audit failure and forged adapter holds", async () => {
  for (const mode of ["missing", "untrusted", "gate", "request-audit", "response-audit", "throw-before-effect", "throw-after-effect", "forged-hold", "ack"] as const) {
    const spine = newSpine(), hub = new CapabilityHub(spine);
    let calls = 0, effects = 0;
    if (mode !== "missing") hub.register({
      descriptor: { id: "probe", kind: "connector", name: "probe", credentialId: "test", trust: mode === "untrusted" ? "untrusted" : "verified" },
      invoke: async () => {
        calls++;
        if (mode === "throw-before-effect") throw null;
        effects++;
        if (mode === "throw-after-effect") throw "lost acknowledgment";
        return mode === "forged-hold" ? { ok: false, held: true } : { ok: true };
      },
    });
    const stage = spine.stage.bind(spine);
    spine.stage = event => {
      if (event.payload["phase"] === (mode === "request-audit" ? "request" : mode === "response-audit" ? "response" : "never")) throw Error("audit unavailable");
      return stage(event);
    };
    const result = await hub.invoke({ capabilityId: "probe", operation: "email.send", args: {} }, { confirm: mode !== "gate", requireVerified: true });
    const started = ["response-audit", "throw-before-effect", "throw-after-effect", "forged-hold", "ack"].includes(mode);
    assert.equal(calls, started ? 1 : 0, mode);
    assert.equal(result.held, !started, mode);
    assert.equal(result.ok, mode === "ack", mode);
    assert.equal(effects, started && mode !== "throw-before-effect" ? 1 : 0, mode);
  }
});

/** An adapter that RECORDS whether it was ever invoked — so a HOLD (adapter never reached) is observable. */
function spyAdapter(id: string): { adapter: CapabilityAdapter; invoked: () => boolean } {
  let invoked = false;
  const adapter: CapabilityAdapter = {
    descriptor: { id, kind: "mcp-server", name: id, credentialId: `cred-${id}`, trust: "verified" },
    invoke: async (): Promise<CapabilityResult> => {
      invoked = true;
      return { ok: true, output: "reached-the-world" };
    },
  };
  return { adapter, invoked: () => invoked };
}

// ── (a) external effect is mediated/HELD — the adapter is never invoked ─────────────────────────────────────────
test("(a) an EXTERNAL capability is HELD at the wrapper — the adapter is never invoked", async () => {
  const hub = new CapabilityHub(newSpine());
  const { adapter, invoked } = spyAdapter("mailer");
  hub.register(adapter);
  // "email.send" resolves to the EXTERNAL class (8.44B). Unconfirmed → HELD → the adapter must never be reached.
  const r = await hub.invoke({ capabilityId: "mailer", operation: "email.send", args: { to: "x@y.z" } });
  assert.equal(r.held, true, "an external capability must be HELD");
  assert.equal(r.ok, false);
  assert.equal(invoked(), false, "a HELD external effect must NOT reach the adapter (never sent to the world)");
  // A DESTRUCTIVE capability is likewise held.
  const { adapter: da, invoked: dInvoked } = spyAdapter("dropper");
  hub.register(da);
  const dr = await hub.invoke({ capabilityId: "dropper", operation: "db.drop", args: {} });
  assert.equal(dr.held, true);
  assert.equal(dInvoked(), false);
  // But an OPERATOR-CONFIRMED external effect is allowed through (confirmation is not a class flag — the class is
  // still resolved from identity; confirm only authorizes a KNOWN external/destructive effect to proceed).
  const { adapter: ca, invoked: cInvoked } = spyAdapter("mailer2");
  hub.register(ca);
  const cr = await hub.invoke({ capabilityId: "mailer2", operation: "email.send", args: {} }, { confirm: true });
  assert.equal(cr.ok, true, "an operator-confirmed external effect proceeds");
  assert.equal(cInvoked(), true);
});

// ── (b) unknown/unclassified capability is HELD at the wrapper (fail-closed) ─────────────────────────────────────
test("(b) an UNKNOWN capability is HELD at the wrapper (fail-closed), never invoked", async () => {
  const hub = new CapabilityHub(newSpine());
  const { adapter, invoked } = spyAdapter("mystery");
  hub.register(adapter);
  // "totally.unenumerated" is NOT in the 8.44B allowlist → unknown → HELD, deny-by-default.
  const r = await hub.invoke({ capabilityId: "mystery", operation: "totally.unenumerated", args: {} });
  assert.equal(r.held, true, "an unknown capability must be HELD");
  assert.equal(invoked(), false, "an unclassified capability must NOT reach the adapter");
  // A confirmation CANNOT wave an unknown capability through — confirm only authorizes a KNOWN effect class.
  const { adapter: a2, invoked: i2 } = spyAdapter("mystery2");
  hub.register(a2);
  const r2 = await hub.invoke({ capabilityId: "mystery2", operation: "totally.unenumerated", args: {} }, { confirm: true });
  assert.equal(r2.held, true, "confirmation cannot certify a class the allowlist never classified");
  assert.equal(i2(), false);
});

// ── (c) complete-mediation INVENTORY + CI check: no effectful entry bypasses the wrapper ─────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", ".."); // dist/test → dist → repo root (src/ lives here)

test("(c) no effectful entry point BYPASSES the wrapper — a synthetic un-gated entry is DETECTED", () => {
  // SYNTHETIC BYPASS: an effectful entry point whose source reaches the world WITHOUT consulting the gate.
  const synthetic: EffectfulEntryPoint[] = [
    { id: "EvilPort.invoke", file: "src/evil/port.ts", reaches: "transport.callTool (ungated)" },
  ];
  const ungatedSource = new Map<string, string>([
    ["src/evil/port.ts", "async invoke(inv){ return this.transport.callTool(inv.op, inv.args); }"],
  ]);
  const scan = scanForBypasses(synthetic, ungatedSource);
  assert.equal(scan.complete, false, "an un-gated effectful entry must be reported as a bypass");
  assert.equal(scan.bypasses.length, 1);
  assert.match(scan.bypasses[0]!.reason, new RegExp(GATE_MARKER), "the bypass names the missing gate marker");

  // A GATED entry (source consults the gate) is NOT a bypass.
  const gatedSource = new Map<string, string>([
    ["src/evil/port.ts", `async invoke(inv){ const d = ${GATE_MARKER}(inv.op); if(d.route==='hold') return held; return this.transport.callTool(inv.op); }`],
  ]);
  assert.equal(scanForBypasses(synthetic, gatedSource).complete, true);

  // MEASURED over the REAL tree: the enumerated effectful surface consults the gate today (complete mediation).
  const real = verifyCompleteMediation(REPO_ROOT);
  assert.equal(real.complete, true, `real effectful surface must be completely mediated; bypasses: ${JSON.stringify(real.bypasses)}`);
  assert.ok(real.checked.includes(EFFECTFUL_ENTRY_POINTS[0]!.file), "the real capability_port.ts was actually read + scanned");
});

// ── (d) CONTROL — a known-recoverable capability routes through the wrapper and is ALLOWED (not everything held) ──
test("(d) CONTROL — a known-recoverable capability routes through the wrapper and is ALLOWED", async () => {
  const hub = new CapabilityHub(newSpine());
  const { adapter, invoked } = spyAdapter("reader");
  hub.register(adapter);
  // "fs.read" resolves recoverable (8.44B) → ALLOWED → the adapter IS invoked. Proves the wrapper does not just deny all.
  const r = await hub.invoke({ capabilityId: "reader", operation: "fs.read", args: {} });
  assert.equal(r.ok, true, "a recoverable capability is allowed through");
  assert.notEqual(r.held, true);
  assert.equal(invoked(), true, "a recoverable effect reaches the adapter");
});
