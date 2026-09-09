import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveReferenceEnforcementProfile, satisfiesIsolation } from "../src/platform/enforcement_profile.js";
import type { CapabilityReport } from "../src/platform/capability_probe.js";

const report = (status: "present" | "absent"): CapabilityReport => ({
  capabilities: Object.freeze(Object.fromEntries(["landlock", "namespaces", "seccomp", "kvm"].map((name) => [name, { name, status, evidence: "fixture" }]))),
  tier: status === "present" ? 1 : 0, tierReason: "fixture", profileDigest: status.repeat(64).slice(0, 64),
});
const facts = { deploymentIdentity: "deploy-a", bootIdentity: "boot-a", measuredAtMs: 10n, expiresAtMs: 20n, spineDurable: true, witnessOutOfWriteSet: true };

test("available host mechanisms never masquerade as active enforcement", () => {
  const p = resolveReferenceEnforcementProfile(report("present"), facts);
  assert.equal(p.fields.processContainment.status, "unavailable");
  assert.equal(p.fields.filesystemScope.status, "unavailable");
  assert.match(p.fields.processContainment.evidence.join(" "), /namespaces:present/);
  assert.equal(satisfiesIsolation(p, ["processContainment"]), false);
});

test("same-principal role authentication and brokering are detection-only, never containment", () => {
  const p = resolveReferenceEnforcementProfile(report("absent"), facts);
  assert.equal(p.fields.brokerPeerAuthentication.status, "detected-only");
  assert.equal(p.fields.networkMediation.status, "detected-only");
  assert.equal(p.fields.workloadPrincipalSeparation.status, "unavailable");
  assert.equal(satisfiesIsolation(p, ["brokerPeerAuthentication", "networkMediation"]), false);
});

test("out-of-write-set evidence is not overclaimed as an independent principal", () => {
  const p = resolveReferenceEnforcementProfile(report("present"), facts);
  assert.equal(p.fields.auditChainIndependence.status, "detected-only");
  assert.equal(p.fields.witnessIndependence.status, "unavailable");
  assert.match(p.digest, /^[0-9a-f]{64}$/);
});

