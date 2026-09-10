import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import type { CapabilityReport } from "./capability_probe.js";

export const ENFORCEMENT_STATUSES = ["enforced", "detected-only", "unavailable", "unknown"] as const;
export type EnforcementStatus = typeof ENFORCEMENT_STATUSES[number];

export const ENFORCEMENT_FIELDS = [
  "workloadPrincipalSeparation", "brokerPeerAuthentication", "credentialNonExposure", "filesystemScope",
  "processContainment", "networkMediation", "durableAdmission", "independentRecovery", "auditChainIndependence",
  "outcomeReaderIndependence", "witnessIndependence", "verifierExecutionContainment", "resultChannelIntegrity",
  "grantAttenuation",
] as const;
export type EnforcementField = typeof ENFORCEMENT_FIELDS[number];

export interface EnforcementEvidence {
  readonly status: EnforcementStatus;
  readonly evidence: readonly string[];
}

export interface EnforcementProfile {
  readonly deploymentIdentity: string;
  readonly bootIdentity: string;
  readonly measuredAtMs: bigint;
  readonly expiresAtMs: bigint;
  readonly fields: Readonly<Record<EnforcementField, EnforcementEvidence>>;
  readonly digest: string;
}

export interface ReferenceProfileFacts {
  readonly deploymentIdentity: string;
  readonly bootIdentity: string;
  readonly measuredAtMs: bigint;
  readonly expiresAtMs: bigint;
  readonly spineDurable: boolean;
  readonly witnessOutOfWriteSet: boolean;
}

const row = (status: EnforcementStatus, ...evidence: string[]): EnforcementEvidence =>
  Object.freeze({ status, evidence: Object.freeze(evidence) });

/**
 * Resolve the CURRENT single-process deployment honestly. Capability availability is evidence about what could be
 * provisioned, never proof that it is active; therefore a present namespace/Landlock/KVM capability does not upgrade
 * any row. The reference channel and broker are detection/load-bearing mechanisms in one OS principal. Native launch
 * profiles replace these rows only from signed active-mechanism observations.
 */
export function resolveReferenceEnforcementProfile(capabilities: CapabilityReport, facts: ReferenceProfileFacts): EnforcementProfile {
  const available = (name: string): string => `${name}:${capabilities.capabilities[name]?.status ?? "unmeasured"}`;
  const fields: Record<EnforcementField, EnforcementEvidence> = {
    workloadPrincipalSeparation: row("unavailable", "runtime:single-os-principal"),
    brokerPeerAuthentication: row("detected-only", "runtime:role-channel-role+instance+boot+secret", "boundary:same-process"),
    credentialNonExposure: row("detected-only", "runtime:ecmascript-private-fields", "boundary:same-os-principal"),
    filesystemScope: row("unavailable", "runtime:no-active-filesystem-sandbox", available("landlock"), available("namespaces")),
    processContainment: row("unavailable", "runtime:no-active-process-container", available("namespaces"), available("seccomp"), available("kvm")),
    networkMediation: row("detected-only", "runtime:net-broker-live", "boundary:same-os-principal"),
    durableAdmission: facts.spineDurable
      ? row("detected-only", "runtime:spine-fsync", "authority-admission-store:not-yet-authoritative")
      : row("unavailable", "runtime:spine-not-fsync-durable"),
    independentRecovery: row("unavailable", "runtime:no-independent-recovery-principal"),
    auditChainIndependence: facts.witnessOutOfWriteSet
      ? row("detected-only", "runtime:witness-out-of-write-set", "independent-principal:not-established")
      : row("unavailable", "runtime:witness-same-write-set-or-unattested"),
    outcomeReaderIndependence: row("unavailable", "runtime:no-independent-outcome-reader"),
    witnessIndependence: row("unavailable", "runtime:no-distinct-witness-principal"),
    verifierExecutionContainment: row("unavailable", "runtime:no-distinct-verifier-principal"),
    resultChannelIntegrity: row("detected-only", "runtime:canonical-broker-result", "boundary:same-process"),
    grantAttenuation: row("detected-only", "runtime:signed-caveated-single-use-permit", "key-custody:same-principal"),
  };
  const content: CanonicalValue = {
    deploymentIdentity: facts.deploymentIdentity, bootIdentity: facts.bootIdentity,
    measuredAtMs: facts.measuredAtMs, expiresAtMs: facts.expiresAtMs,
    fields: ENFORCEMENT_FIELDS.map((field) => ({ field, status: fields[field].status, evidence: [...fields[field].evidence] })),
  };
  return Object.freeze({ ...facts, fields: Object.freeze(fields), digest: eirDigest("keep.enforcement-profile/reference/v1", content) });
}

export function satisfiesIsolation(profile: EnforcementProfile, required: readonly EnforcementField[]): boolean {
  return required.every((field) => profile.fields[field].status === "enforced");
}
