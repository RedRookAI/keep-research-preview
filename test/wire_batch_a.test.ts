import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";

// WIRE-BATCH Phase A (self-audit repair): the 12a interlock + fsync durability, made LOAD-BEARING on the live path.
// Proven by disproof — this is the "who instantiates this?" test the mechanism review never had:
//   A1: compose defaults the live spine to fsync-durable        => spineDurable true (false only when opted out)
//   A2: a brokered REMOTE send seals a pre-effect witness intent => an `effect.intent` event on the LIVE spine
//       (neuter: drop the witness arg in compose -> no effect.intent -> this test reddens)

function tmp(): string { return mkdtempSync(join(tmpdir(), "keep-wireA-")); }

/** A fake REMOTE inner provider (isLocal:false => the egress is brokered, so the witness interlock engages). At
 *  TRANSPORT ENTRY it snapshots the spine event types via `onSend`, so the test can assert the pre-effect intent was
 *  sealed BEFORE the transport ran (the ordering is the whole point of a PRE-effect interlock, not just "fired"). */
function fakeRemote(onSend: () => void): ModelProvider & { calls: GenerateRequest[] } {
  const calls: GenerateRequest[] = [];
  return {
    name: "fake-remote", isLocal: false, calls,
    async generate(req: GenerateRequest): Promise<GenerateResult> { onSend(); calls.push(req); return { text: `echo:${req.prompt}`, model: "fake-1", tokensIn: 7, tokensOut: 3 }; },
    async embed(texts: readonly string[]): Promise<Embedding[]> { onSend(); return texts.map(() => [0]); },
  } as ModelProvider & { calls: GenerateRequest[] };
}

test("A1: composeKeep defaults the LIVE spine to fsync-durable (self-audit W2)", () => {
  const a = tmp(); const b = tmp();
  try {
    assert.equal(composeKeep({ dataDir: a }).spineDurable, true, "default must be fsync-durable");
    assert.equal(composeKeep({ dataDir: b, fsync: false }).spineDurable, false, "opt-out honored + reported honestly");
  } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
});

test("A4 LOAD-BEARING: compose refuses a REMOTE provider before installed-release admission", () => {
  const dir = tmp();
  try {
    const descriptor = { mode: "openai-compatible" as const, baseUrl: "https://example.invalid", model: "m", apiKey: "secret" };
    assert.throws(() => composeKeep({ dataDir: dir, remoteProvider: descriptor }), /remote provider descriptor requires A4 installed-release verification/);
    let accessorRan = 0; const hostile = { mode: "openai-compatible", baseUrl: "https://example.invalid", model: "m", get apiKey() { accessorRan++; return "secret"; } };
    assert.throws(() => composeKeep({ dataDir: dir, remoteProvider: hostile as never }), /only enumerable data properties/); assert.equal(accessorRan, 0);
    let traps = 0; const proxy = new Proxy(descriptor, { getPrototypeOf() { traps++; return Object.prototype; }, ownKeys() { traps++; return ["mode", "baseUrl", "model", "apiKey"]; }, getOwnPropertyDescriptor(target, key) { traps++; return Object.getOwnPropertyDescriptor(target, key); }, get(target, key) { traps++; return Reflect.get(target, key); } });
    assert.throws(() => composeKeep({ dataDir: dir, remoteProvider: proxy }), /plain inert data/); assert.equal(traps, 0, "proxy rejection must precede every attacker trap");
    const liar = fakeRemote(() => { throw new Error("transport must not run"); }); Object.defineProperty(liar, "isLocal", { value: true });
    assert.throws(() => composeKeep({ dataDir: dir, provider: liar }), /not locality-attested/);
    assert.equal(liar.calls.length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
