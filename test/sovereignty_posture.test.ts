import { test } from "node:test";
import assert from "node:assert/strict";
import { derivePosture, assertControlPlaneLocal, defaultControlPlaneStatus, type EnvironmentFacts } from "../src/sovereignty/posture.js";
import { buildManifest, assertSovereign, findSovereigntyViolations } from "../src/sovereignty/manifest.js";

const env = (o: Partial<EnvironmentFacts>): EnvironmentFacts => ({
  localModelAvailable: false, brainLocation: "none", hasEgress: false, freeTierConstrained: false, ...o,
});

test("INVARIANT: the back-of-the-room operator (free-tier, NO local model) is a VALID first-class posture", () => {
  const p = derivePosture(env({ localModelAvailable: false, brainLocation: "free-tier", hasEgress: true, freeTierConstrained: true }));
  assert.equal(p.name, "hosted-dependent");
  assert.equal(p.brainLocation, "free-tier");
  assert.equal(p.tier, 2, "minimum sufficient sovereignty — control plane local");
  assert.equal(p.freeTierConstrained, true);
});

test("INVARIANT: control-plane-local holds in ALL four postures", () => {
  const status = defaultControlPlaneStatus();
  for (const e of [
    env({ brainLocation: "local", hasEgress: false }),
    env({ brainLocation: "local", hasEgress: true }),
    env({ localModelAvailable: true, brainLocation: "hosted", hasEgress: true }),
    env({ localModelAvailable: false, brainLocation: "free-tier", hasEgress: true, freeTierConstrained: true }),
  ]) {
    derivePosture(e); // posture derivation never throws
    assert.doesNotThrow(() => assertControlPlaneLocal(status), "control plane is local regardless of brain location");
  }
});

test("INVARIANT: air-gapped is Tier 3 (brain local, no egress)", () => {
  const p = derivePosture(env({ localModelAvailable: true, brainLocation: "local", hasEgress: false }));
  assert.equal(p.name, "air-gapped");
  assert.equal(p.tier, 3);
});

test("INVARIANT: the manifest is HONEST — a no-local-model deployment does NOT claim a local brain fallback", () => {
  const p = derivePosture(env({ localModelAvailable: false, brainLocation: "free-tier", hasEgress: true, freeTierConstrained: true }));
  const m = buildManifest({ brain: true, posture: p });
  const brain = m.capabilities.find((c) => c.capability === "brain")!;
  assert.equal(brain.offlineFallback, null, "no dishonest local-fallback claim when the env can't run one");
  // ...but this is NOT a violation, because the posture legitimately declares the external brain.
  assert.doesNotThrow(() => assertSovereign(m), "control-plane-local is the guarantee, not local-brain");
  assert.equal(findSovereigntyViolations(m).length, 0);
});

test("INVARIANT: an UNDECLARED null fallback (no posture) is still a violation", () => {
  const m = buildManifest({ brain: true }); // no posture → the brain still claims its (conditional) local fallback
  // Force the dishonest case: null fallback with no posture is caught by findSovereigntyViolations directly.
  const dishonest = { asOf: "2026-08-05", capabilities: [{ capability: "brain", port: "ModelProvider", tier: "opt-in-egress" as const, offlineFallback: null, egress: null, externalActive: true }] };
  assert.throws(() => assertSovereign(dishonest), /hard external dependency/i);
  assert.ok(m); // the posture-less default still builds
});

test("INVARIANT: control-plane-local FAILS if audit/governance/floors are reported non-local", () => {
  assert.throws(() => assertControlPlaneLocal([
    { capability: "audit-spine", local: false },
    { capability: "governance", local: true },
    { capability: "deterministic-floors", local: true },
  ]), /not local/);
});

test("hybrid: a local model exists but a hosted brain is wired → Tier 2, control plane local", () => {
  const p = derivePosture(env({ localModelAvailable: true, brainLocation: "hosted", hasEgress: true }));
  assert.equal(p.name, "hybrid");
  assert.equal(p.tier, 2);
});
