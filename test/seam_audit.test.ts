import { test } from "node:test";
import assert from "node:assert/strict";
import { probeCapabilities } from "../src/platform/capability_probe.js";
import { SEAMS, auditSeams, type SeamDecl } from "../src/platform/seam_registry.js";

// THE ANTI-UNDERBUILD GUARD. A seam is only legitimate for a capability this host genuinely LACKS. This test makes
// "seam'd something the box can do" mechanically un-mergeable: it audits the registry against the LIVE probe and fails
// if any host-hardware seam names a capability the host actually has. (Twin of the pre-push green-gate — that blocks
// disabled safety; this blocks scope reduction.)

test("every registered host-hardware seam names a capability GENUINELY ABSENT on this host (no mis-seam)", () => {
  const audit = auditSeams(probeCapabilities());
  assert.equal(audit.ok, true, `MIS-SEAMED (buildable here, must build not seam): ${audit.misSeamed.join(", ")}\n${audit.rows.filter((r) => !r.ok).map((r) => "  " + r.id + ": " + r.verdict).join("\n")}`);
});

test("the guard BITES: declaring a seam for a PRESENT capability fails the audit", () => {
  const report = probeCapabilities();
  // asymmetric-signing is present on any modern Node — pretend someone tried to seam it (as C-1/2/3 effectively did).
  const bogus: SeamDecl = { id: "S-bogus", title: "pretend signing needs hardware", category: "host-hardware", requiresAbsentCapability: "asymmetric-signing", extendsMechanism: "x", rationale: "x" };
  const audit = auditSeams(report, [bogus]);
  assert.equal(audit.ok, false, "a seam over a present capability must be rejected");
  assert.deepEqual(audit.misSeamed, ["S-bogus"]);
  assert.match(audit.rows[0]!.verdict, /MIS-SEAM/);
});

test("the registry does NOT list buildable-here capabilities as seams (the mis-seam'd set is reopened, not seam'd)", () => {
  // These were wrongly deferred; the probe shows them present/installable, so they must NOT appear as seams.
  const seamedCaps = new Set(SEAMS.filter((s) => s.category === "host-hardware").map((s) => s.requiresAbsentCapability));
  for (const c of ["kvm", "seccomp", "landlock", "namespaces", "cgroups-v2", "container-runtime", "asymmetric-signing", "hypervisor"]) {
    assert.ok(!seamedCaps.has(c), `"${c}" is buildable/installable here — it must be Tier-1 backlog, not a seam`);
  }
  // and the genuine hardware seams ARE present.
  for (const id of ["S-tee", "S-tpm", "S-gpu"]) assert.ok(SEAMS.some((s) => s.id === id), `genuine seam ${id} must be registered`);
});
