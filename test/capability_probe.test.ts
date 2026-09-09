import { test } from "node:test";
import assert from "node:assert/strict";
import { probeCapabilities, selectTier, profileDigestOf, type Capability } from "../src/platform/capability_probe.js";

// HOST CAPABILITY PROBE (register H-8). The mechanical basis for "PROBE BEFORE YOU SEAM": tier selection and every
// seam declaration must be MEASURED, not assumed. Structural + pure-logic assertions (host-value-independent so CI on
// any host passes), plus the one universal truth — asymmetric signing is present on any modern Node, which is exactly
// why C-1/C-2/C-3 (non-repudiable signing) were mis-seam'd to "TEE" when they need only a keypair.

const C = (status: Capability["status"]): Capability => ({ name: "x", status, evidence: "synthetic" });

test("selectTier is PURE and MEASURED: kernel isolation => Tier 1; hardware RoT => Tier 2; else Tier 0", () => {
  assert.equal(selectTier({}).tier, 0, "no measured capabilities => Tier 0 floor");
  assert.equal(selectTier({ namespaces: C("present"), seccomp: C("present") }).tier, 1, "namespaces+seccomp => Tier 1");
  assert.equal(selectTier({ namespaces: C("present"), seccomp: C("present"), kvm: C("present") }).tier, 1);
  assert.match(selectTier({ namespaces: C("present"), seccomp: C("present"), kvm: C("present") }).tierReason, /KVM/);
  assert.equal(selectTier({ tpm: C("present") }).tier, 2, "TPM => Tier 2");
  assert.equal(selectTier({ tee: C("present"), namespaces: C("present"), seccomp: C("present") }).tier, 2, "TEE => Tier 2");
});

test("selectTier degrades conservatively: 'unknown'/'absent' NEVER lift the tier (no silent over-claim)", () => {
  assert.equal(selectTier({ namespaces: C("present"), seccomp: C("unknown") }).tier, 0, "unmeasured seccomp must NOT reach Tier 1");
  assert.equal(selectTier({ namespaces: C("absent"), seccomp: C("present") }).tier, 0);
  assert.equal(selectTier({ tpm: C("unknown"), namespaces: C("present"), seccomp: C("present") }).tier, 1, "unknown TPM => Tier 1 not 2");
});

test("profileDigestOf is stable and host-path-INDEPENDENT (evidence prose excluded)", () => {
  const a: Record<string, Capability> = { kvm: { name: "kvm", status: "present", evidence: "/dev/kvm on host-A" } };
  const b: Record<string, Capability> = { kvm: { name: "kvm", status: "present", evidence: "TOTALLY different prose on host-B" } };
  assert.equal(profileDigestOf(a), profileDigestOf(b), "same {name:status} => same digest regardless of evidence text");
  const c: Record<string, Capability> = { kvm: { name: "kvm", status: "absent", evidence: "x" } };
  assert.notEqual(profileDigestOf(a), profileDigestOf(c), "a status change MUST change the digest");
});

test("probeCapabilities MEASURES this host: every named capability has a valid status, tier is consistent", () => {
  const r = probeCapabilities();
  const names = ["asymmetric-signing", "kvm", "cpu-virt", "seccomp", "landlock", "namespaces", "cgroups-v2", "container-runtime", "hypervisor", "tpm", "tee", "gpu", "package-install"];
  for (const n of names) {
    const c = r.capabilities[n];
    assert.ok(c, `capability ${n} must be probed`);
    assert.ok(["present", "absent", "unknown"].includes(c!.status), `${n} status valid`);
    assert.ok(typeof c!.evidence === "string" && c!.evidence.length > 0, `${n} carries evidence`);
  }
  assert.ok([0, 1, 2].includes(r.tier));
  // the reported tier must equal the PURE selection over the same capabilities (probe and selection can't drift).
  assert.equal(r.tier, selectTier(r.capabilities).tier);
  assert.equal(r.profileDigest, probeCapabilities().profileDigest, "the profile digest is stable across probes on the same host");
});

test("asymmetric signing is PRESENT on any modern Node — the proof C-1/C-2/C-3 were mis-seam'd (need a keypair, not silicon)", () => {
  const r = probeCapabilities();
  assert.equal(r.capabilities["asymmetric-signing"]!.status, "present", "ed25519 sign/verify works with zero deps — non-repudiable signing is Tier-0, every host");
});
