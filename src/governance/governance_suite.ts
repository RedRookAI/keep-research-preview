/**
 * Governance-suite composition — the enterprise compliance surface, assembled into one reachable capability.
 *
 *  - ComplianceExporter: build + HMAC-sign a regime-versioned, honesty-labeled evidence pack from the governance trail
 *    (EU AI Act articles crosswalked to NIST AI RMF + ISO 42001). Tamper-evident, verifiable offline with only the key.
 *  - IncidentReporter: capture an incident and compute its multi-clock regulatory deadlines (NIS2 24h, GDPR 72h, and the
 *    AI Act Art. 73 severity ladder: 2 days widespread/critical-infra, 10 days if a death may be involved, else 15 days).
 *  - ResidencyEnforcer: deny-by-default data-residency + egress policy (air-gap forces egress denial).
 *
 * SOTA basis (2026-08-07): after an AI incident an org often reports on THREE clocks to THREE authorities — 24h NIS2,
 * 72h GDPR, 15d AI Act — and the AI Act Art. 73 timeline tightens to 10 days (death) or 2 days (widespread / serious
 * critical-infrastructure disruption). Art. 73 has applied since 2 Aug 2026. The single-entry-point consolidation comes
 * from the Digital Omnibus, which is NOT yet concluded (Council vote postponed 29 Jun 2026), so the reporting target is
 * honesty-labeled as anticipated. What would change it: once the Omnibus concludes, the single entry point becomes final.
 */

import { ComplianceExporter, type EvidencePack, type SignedEvidencePack, type ControlCoverage } from "./evidence_pack.js";
import { IncidentReporter } from "./incident.js";
import { ResidencyEnforcer, type ResidencyPolicy } from "./residency.js";
import type { GovernanceLedger } from "./decision_record.js";
import type { Spine } from "../spine/spine.js";
import { randomBytes } from "node:crypto";

export interface GovernanceSuiteConfig {
  readonly spine: Spine;
  /** The governance decision trail the evidence pack is built from. Absent → packs cover an empty trail. */
  readonly ledger?: GovernanceLedger;
  /** Compliance regime version string (e.g. "EU-AI-Act@2026-08-02"). */
  readonly regimeVersion?: string;
  readonly legalBasis?: string;
  /** HMAC signing key for evidence packs. Absent → a per-process ephemeral key (packs still verify within the session). */
  readonly signingKey?: Buffer;
  /** Data-residency + egress policy. Absent → deny-by-default (air-gapped: no regions, no egress). */
  readonly residency?: ResidencyPolicy;
}

export interface GovernanceSuite {
  readonly exporter: ComplianceExporter;
  readonly incidents: IncidentReporter;
  readonly residency: ResidencyEnforcer;
  /** Build a signed evidence pack from the current governance trail (on-demand, for an auditor). */
  buildSignedPack(controls?: readonly ControlCoverage[]): SignedEvidencePack;
  /** Build an unsigned pack (for inspection). */
  buildPack(controls?: readonly ControlCoverage[]): EvidencePack;
}

export function buildGovernanceSuite(cfg: GovernanceSuiteConfig): GovernanceSuite {
  // Deny-by-default residency: no config → air-gapped with no permitted regions (sovereign floor).
  const residencyPolicy: ResidencyPolicy = cfg.residency ?? { allowedRegions: [], egressAllowlist: [], airGapped: true };
  const residency = new ResidencyEnforcer(residencyPolicy);
  const incidents = new IncidentReporter(cfg.spine);
  // Ephemeral key if none supplied — packs still sign+verify within the session; a real deploy supplies a keystore key.
  const signingKey = cfg.signingKey ?? randomBytes(32);
  const exporter = new ComplianceExporter(cfg.regimeVersion ?? "EU-AI-Act@2026-08-02", cfg.legalBasis ?? "Reg (EU) 2024/1689 as amended", signingKey);

  const trail = () => (cfg.ledger ? cfg.ledger.readTrail() : []);
  return {
    exporter,
    incidents,
    residency,
    buildPack: (controls) => exporter.buildPack(trail(), controls),
    buildSignedPack: (controls) => exporter.sign(exporter.buildPack(trail(), controls)),
  };
}
