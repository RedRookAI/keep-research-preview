#!/usr/bin/env node
/**
 * seam_audit.mjs — PROBE BEFORE YOU SEAM (human/CI view). [netguard-allow]
 *
 * Runs the live host capability probe and audits the machine-readable seam registry against it: a host-hardware seam is
 * only legitimate for a capability this host genuinely LACKS. Prints the measured tier + capabilities + the seam
 * verdicts, and exits non-zero if anything is MIS-SEAMED (buildable here — build it, don't seam it). The same check runs
 * inside `npm test` (test/seam_audit.test.ts), so this is the operator-facing surface of a gate that already blocks merges.
 * Requires `npm run build` first (imports from dist/).
 */
const { probeCapabilities } = await import(new URL("../dist/src/platform/capability_probe.js", import.meta.url));
const { auditSeams, SEAMS } = await import(new URL("../dist/src/platform/seam_registry.js", import.meta.url));

const report = probeCapabilities();
console.log(`\n[seam-audit] measured ENFORCEMENT TIER ${report.tier} — ${report.tierReason}`);
console.log(`[seam-audit] capability profile ${report.profileDigest.slice(0, 16)}`);
for (const c of Object.values(report.capabilities)) console.log(`   ${c.status.padEnd(8)} ${c.name.padEnd(20)} · ${c.evidence}`);

const audit = auditSeams(report);
console.log(`\n[seam-audit] ${SEAMS.length} declared seams:`);
for (const r of audit.rows) console.log(`   ${r.ok ? "OK  " : "FAIL"} ${r.id.padEnd(16)} · ${r.verdict}`);

if (!audit.ok) {
  console.error(`\n[seam-audit] REFUSED: ${audit.misSeamed.length} MIS-SEAM(S) — a capability this host HAS was declared a seam. Build it, do not seam it: ${audit.misSeamed.join(", ")}`);
  process.exit(1);
}
console.log(`\n[seam-audit] OK — every host-hardware seam names a genuinely-absent capability; nothing buildable-here is seam'd.`);
process.exit(0);
