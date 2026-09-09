/**
 * MACHINE-CHECKABLE SEAM REGISTRY + audit (the hardwired anti-underbuild guard).
 *
 * A "seam" is a guarantee Keep legitimately cannot provide HERE. The failure this guard exists to prevent: declaring a
 * seam for something the host can actually do (scope reduction dressed as honesty). So every HOST-HARDWARE seam names
 * the exact capability that must be ABSENT for it to be legitimate, and `auditSeams` cross-references the LIVE probe:
 * if a seam's required capability is PRESENT (or installable), the seam is INVALID — it is buildable-here work, not a
 * seam. A test asserts this over the real host, so "seam'd something this box can do" is mechanically impossible to
 * merge (the twin of the pre-push green-gate, for underbuild instead of broken safety).
 *
 * Non-capability seams (another ORGANIZATION's quorum witnesses; a different OS; a real third-party CREDENTIAL/endpoint)
 * are genuinely external and not probe-checkable — they are declared with a category + rationale, never as a stand-in
 * for unbuilt local work. See [[keep-environment-and-seams]] for the corrected tier model + the reopened Tier-1 backlog.
 */

import type { CapabilityReport } from "./capability_probe.js";

export type SeamCategory =
  | "host-hardware"        // needs specific silicon this host lacks (probe-checkable): TPM/TEE/GPU
  | "external-population"  // needs INDEPENDENT third parties we cannot create (quorum witnesses, public transparency log)
  | "other-platform"       // needs a different OS/runtime we are not on (Windows, iOS/Android)
  | "deployment-credential"; // needs a real third-party credential/endpoint (API key, forge token, IdP, tracker)

export interface SeamDecl {
  readonly id: string;
  readonly title: string;
  readonly category: SeamCategory;
  /** For `host-hardware` seams ONLY: the capability (capability_probe name) that MUST be absent for this to be a seam. */
  readonly requiresAbsentCapability?: string;
  readonly extendsMechanism: string; // the stronger mechanism a capable host/deployment adds
  readonly rationale: string;         // WHY this is genuinely external, not merely unbuilt
}

/**
 * THE genuine seams — re-grounded against the live probe (2026-08-18). Only what is truly external/absent-hardware is
 * here; everything the probe shows present-or-installable (KVM, seccomp, Landlock, namespaces, containers, ed25519
 * signing, an installable hypervisor) is NOT a seam — it is the reopened Tier-1 build backlog.
 */
export const SEAMS: readonly SeamDecl[] = Object.freeze([
  { id: "S-tee", title: "Hardware-sealed key custody + confidential-VM remote attestation", category: "host-hardware", requiresAbsentCapability: "tee",
    extendsMechanism: "run on an SEV-SNP / TDX host; seal signing keys to the TEE and attest the measured VM", rationale: "no SEV-SNP/TDX guest device or CPU flag on this host — cannot be manufactured in software (swtpm/attestation-verify path is still wired + integration-tested)" },
  { id: "S-tpm", title: "Hardware measured boot + TPM-sealed keys", category: "host-hardware", requiresAbsentCapability: "tpm",
    extendsMechanism: "bind keys to a TPM PCR policy; extend measured-boot into the boundary descriptor", rationale: "no /dev/tpm* on this host (swtpm gives an integration test, not a hardware root of trust)" },
  { id: "S-gpu", title: "On-host LoRA training / model synthesis", category: "host-hardware", requiresAbsentCapability: "gpu",
    extendsMechanism: "run the built training loop on a GPU host behind the existing training port", rationale: "no NVIDIA device on this host; the gating/orchestration is built, the compute is hardware" },
  { id: "S-quorum", title: "M-of-N witness quorum / public transparency log", category: "external-population",
    extendsMechanism: "witnesses operated by mutually-distrusting parties cosign each checkpoint (defeats split-view)", rationale: "we can wire the cosigning protocol + a multi-process quorum, but INDEPENDENT organizations to run the nodes cannot be created by us" },
  { id: "S-windows", title: "Windows isolation backend", category: "other-platform",
    extendsMechanism: "Job Object + taskkill /T + WSL2 fallback behind the isolation port", rationale: "this host is Linux; the Windows enforcement path cannot be exercised here" },
  { id: "S-mobile", title: "Signed iOS/Android store binary", category: "other-platform",
    extendsMechanism: "signed native build + store submission; thin client to the gateway", rationale: "requires platform signing + app-store submission, out of this environment" },
  { id: "S-provider-cred", title: "Live third-party provider/forge/IdP/tracker run", category: "deployment-credential",
    extendsMechanism: "supply a real API key / forge token / IdP jwks_uri / tracker webhook (egress itself is available here)", rationale: "network egress WORKS on this host — the blocker is credentials/endpoints, which are the operator's to provide; wired + testable against local fakes" },
]);

export interface SeamAuditRow { readonly id: string; readonly ok: boolean; readonly verdict: string; }
export interface SeamAuditResult { readonly ok: boolean; readonly rows: readonly SeamAuditRow[]; readonly misSeamed: readonly string[]; }

/**
 * Audit the registry against a MEASURED capability report. A host-hardware seam is VALID only if its required capability
 * is genuinely ABSENT; if the probe reports it PRESENT, the seam is a MIS-SEAM (buildable here — build it, don't seam
 * it). "unknown" is flagged (must be re-probed, not silently trusted). Non-host-hardware seams are structurally checked
 * (a category that needs no probe) and pass — they are external by nature.
 */
export function auditSeams(report: CapabilityReport, seams: readonly SeamDecl[] = SEAMS): SeamAuditResult {
  const rows: SeamAuditRow[] = [];
  const misSeamed: string[] = [];
  for (const s of seams) {
    if (s.category !== "host-hardware") { rows.push({ id: s.id, ok: true, verdict: `external (${s.category}) — not host-capability-checkable` }); continue; }
    if (s.requiresAbsentCapability === undefined) { rows.push({ id: s.id, ok: false, verdict: "host-hardware seam MUST name requiresAbsentCapability" }); misSeamed.push(s.id); continue; }
    const c = report.capabilities[s.requiresAbsentCapability];
    if (c === undefined) { rows.push({ id: s.id, ok: false, verdict: `requires capability "${s.requiresAbsentCapability}" which the probe does not measure` }); misSeamed.push(s.id); continue; }
    if (c.status === "present") { rows.push({ id: s.id, ok: false, verdict: `MIS-SEAM: "${s.requiresAbsentCapability}" is PRESENT on this host — build it, do not seam it (${c.evidence})` }); misSeamed.push(s.id); continue; }
    if (c.installable === true) { rows.push({ id: s.id, ok: false, verdict: `MIS-SEAM: "${s.requiresAbsentCapability}" is absent but INSTALLABLE — provision + wire it, do not seam it (${c.evidence})` }); misSeamed.push(s.id); continue; }
    rows.push({ id: s.id, ok: true, verdict: c.status === "absent" ? `genuine: "${s.requiresAbsentCapability}" absent & not installable (${c.evidence})` : `UNKNOWN: "${s.requiresAbsentCapability}" unmeasured — re-probe before trusting this seam` });
  }
  return { ok: misSeamed.length === 0, rows, misSeamed };
}
