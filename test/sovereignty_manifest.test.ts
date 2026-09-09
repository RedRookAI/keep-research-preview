import { test } from "node:test";
import assert from "node:assert/strict";
import { buildManifest, assertSovereign, findSovereigntyViolations, KEEP_CAPABILITIES, type SovereigntyManifest } from "../src/sovereignty/manifest.js";
import { composeKeep } from "../src/compose.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("INVARIANT: the shipped default manifest is SOVEREIGN (every capability has an in-box fallback, no telemetry)", () => {
  const m = buildManifest();
  assert.doesNotThrow(() => assertSovereign(m));
  assert.equal(findSovereigntyViolations(m).length, 0);
});

test("INVARIANT: EVERY capability has an in-box offline fallback (no hard external dependency)", () => {
  for (const c of KEEP_CAPABILITIES) {
    assert.ok(c.offlineFallback !== null || c.tier === "in-box", `${c.capability} must have an in-box fallback`);
  }
});

test("INVARIANT: a hard external dependency (null fallback, not in-box) is DETECTED and rejected", () => {
  const bad: SovereigntyManifest = {
    asOf: "2026-08-05",
    capabilities: [{ capability: "rented-thing", port: "X", tier: "opt-in-egress", offlineFallback: null, egress: null, externalActive: true }],
  };
  assert.throws(() => assertSovereign(bad), /hard external dependency/i);
});

test("INVARIANT: telemetry egress is DETECTED and rejected (weakest-link leak)", () => {
  const leaky: SovereigntyManifest = {
    asOf: "2026-08-05",
    capabilities: [{ capability: "leaky", port: "X", tier: "opt-in-egress", offlineFallback: "local", egress: { what: "stuff", privacyPreserving: false, telemetry: true }, externalActive: true }],
  };
  assert.throws(() => assertSovereign(leaky), /telemetry/);
});

test("INVARIANT: research-verification egress is privacy-preserving (minimal terms, no telemetry)", () => {
  const m = buildManifest();
  const research = m.capabilities.find((c) => c.capability === "research-verification")!;
  assert.equal(research.egress!.privacyPreserving, true);
  assert.equal(research.egress!.telemetry, false);
});

test("buildManifest reflects REAL config (external active flags)", () => {
  const m = buildManifest({ brain: true, researchVerification: false });
  assert.equal(m.capabilities.find((c) => c.capability === "brain")!.externalActive, true);
  assert.equal(m.capabilities.find((c) => c.capability === "research-verification")!.externalActive, false);
});

test("composeKeep records the manifest to the spine + is sovereign by default", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-sov-")) });
  assert.ok(app.manifest, "app exposes the manifest");
  assert.doesNotThrow(() => assertSovereign(app.manifest));
  await app.spine.seal();
  const events = app.spine.replay();
  assert.ok(events.some((e: { payload?: { event?: string } }) => e.payload?.event === "sovereignty_manifest"), "manifest recorded to spine");
});

test("in-box audit-spine never egresses", () => {
  const m = buildManifest();
  const spine = m.capabilities.find((c) => c.capability === "audit-spine")!;
  assert.equal(spine.tier, "in-box");
  assert.equal(spine.egress, null);
});
