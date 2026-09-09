/**
 * Autonomous merge executor (Increment AM2) — the governed path that actually LANDS an autonomous-merge change,
 * with a human-on-the-loop safety net. It is the ONLY component that can merge, and by construction it refuses to
 * merge anything the merge-authority decision (AM1) did not clear as `autonomous-merge`. Everything consequential
 * (irreversible / high-blast / sensitive) was already routed to `human-merge` by AM1 and can never reach here.
 *
 * SOTA basis (2026-08-06): autonomous merge for strictly-defined low-risk changes is a recognized level ("L2 —
 * auto-merge low risk … clearly localized fixes in an allowlisted path, all checks must pass"; debugg.ai/zylos). The
 * safety is the lane, not the click: "AI can act only inside pre-approved, observable, REVERSIBLE lanes — if you
 * cannot describe the blast radius and the rollback path in one paragraph, the lane isn't ready" (firstaimovers).
 * The contract is detect → fix-or-rollback → log (arvoai); post-merge regression triggers automatic revert within
 * seconds (harness); a kill switch can pause the whole automated path (firstaimovers). Auto-merge is NOT auto-deploy
 * — this lands the change in the repo and reverts on regression; deployment stays downstream and separately gated.
 *
 * What would change it: L3 (canary-gated) would add a post-merge canary + metric-driven rollback before full
 * inclusion; here the post-merge oracle is the project's own test suite re-run against the merged base.
 */

import type { Spine } from "../spine/spine.js";
import type { MergeAuthorityDecision } from "./merge_authority.js";
import { consumeVerifiedExecutionSubjectAuthority, type VerifiedExecutionSubjectAuthority } from "../isolation/isolation_attestation.js";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalize, type StagedEvent } from "../spine/event.js";
import { types } from "node:util";

export interface MergeSpec {
  readonly issueId: string;
  /** Stable repository identity consumed by the test runner during both ordinary and recovered verification. */
  readonly repoRef: string;
  readonly branch: string;
  readonly baseBranch: string;
  /** Exact commit produced by the publisher from the already-tested staged subject. */
  readonly expectedCandidateCommit: string;
  /** Verifier-owned project manifest from the completed pre-publication Firecracker run. */
  readonly expectedCandidateProjectManifestDigest: string;
  /** Exact guest command/argv/boundary-policy identity used for both candidate and post-merge checks. */
  readonly expectedGuestExecutionRequestDigest: string;
  /** Exact filesystem root measured by both pre- and post-publication Firecracker runs. */
  readonly projectDir: string;
  /** Explicit non-Git execution inputs (for example an installed dependency tree). Every byte remains
   * measured by Firecracker; ignored bytes outside these canonical roots refuse publication. */
  readonly executionAuxiliaryRoots?: readonly string[];
}

export interface MergePreflightIdentity {
  readonly candidateCommit: string;
  readonly candidateTree: string;
  readonly candidateProjectManifestDigest: string;
  readonly baseCommit: string;
  readonly baseTree: string;
  readonly expectedMergedTree: string;
}

export interface PublishedMergeIdentity extends MergePreflightIdentity {
  readonly mergedCommit: string;
  readonly mergedTree: string;
  readonly publishedCommit: string;
  readonly publishedTree: string;
  readonly publishedProjectManifestDigest: string;
  readonly publicationTarget: string;
}

export interface PublicationAttemptV1 {
  readonly schema: "keep.publication-attempt/v1";
  readonly operationId: string;
  readonly spec: MergeSpec;
  readonly identity: PublishedMergeIdentity;
  readonly attemptedCommit: string;
  readonly priorPublishedCommit: string;
  readonly publicationTarget: string;
}

export interface PublicationObservation {
  readonly status: "effect-occurred" | "effect-absent" | "conflict" | "unavailable";
  readonly observedCommit?: string;
  readonly reason: string;
}

export interface PublicationRecoveryResult extends AutonomousMergeResult {
  readonly operationId: string;
  readonly attemptDigest: string;
}

export interface PublicationOperatorTrust {
  readonly keyId: string;
  readonly publicKeyPem: string;
  /** Retained verification keys keep already-sealed adjudications valid across deliberate key rotation. */
  readonly historicalKeys?: readonly { readonly keyId: string; readonly publicKeyPem: string }[];
  /** A rotated key may remain attributable without remaining authoritative. Revoked keys never verify new reliance. */
  readonly revokedKeyIds?: readonly string[];
}

export interface PublicationOperatorAdjudicationV1 {
  readonly schema: "keep.publication-operator-adjudication/v1";
  readonly attemptDigest: string;
  readonly operationId: string;
  readonly adjudicatedDisposition: "effect-occurred" | "effect-absent";
  readonly observedCommit: string;
  readonly operatorEvidenceDigest: string;
  readonly reason: string;
  readonly keyId: string;
  readonly signatureBase64: string;
}

export interface PublicationQuarantineAcknowledgementV1 {
  readonly schema: "keep.publication-quarantine-acknowledgement/v1";
  readonly quarantineDigest: string;
  readonly operatorEvidenceDigest: string;
  readonly reason: string;
  readonly keyId: string;
  readonly signatureBase64: string;
}

const PUBLICATION_TERMINAL_DISPOSITIONS = Object.freeze([
  "effect-occurred-verified", "reconciled-effect-occurred", "reconciled-effect-absent",
  "reverted", "failed", "reconciled-reverted", "reconciled-failed",
] as const);
export type PublicationTerminalDisposition = typeof PUBLICATION_TERMINAL_DISPOSITIONS[number];

/** Stage the one canonical terminal shape shared by every publication orchestrator. */
export function stagePublicationTerminal(
  spine: Spine,
  attemptValue: PublicationAttemptV1,
  disposition: PublicationTerminalDisposition,
  reason: string,
): void {
  const attempt = parsePublicationAttempt(attemptValue);
  if (!(PUBLICATION_TERMINAL_DISPOSITIONS as readonly string[]).includes(disposition)) throw new Error("publication terminal disposition is unknown");
  if (typeof reason !== "string" || reason.length === 0) throw new Error("publication terminal reason is required");
  spine.stage({ type: "effect.terminal", actor: "auto-merge", payload: {
    kind: "auto_merge.publication_terminal", attemptDigest: publicationAttemptDigest(attempt),
    operationId: attempt.operationId, disposition, reason: reason.slice(0, 512),
  } });
}

function publicationQuarantineDigest(event: unknown): string {
  return sha256("keep.publication-quarantine/v1\0", event);
}

function publicationDuplicateConflictDigest(kind: "terminal" | "adjudication", left: unknown, right: unknown): string {
  const rows = [canonicalize(left), canonicalize(right)].sort();
  return sha256(`keep.publication-duplicate-${kind}-conflict/v1\0`, rows);
}

function parsePublicationTerminal(value: unknown): { readonly attemptDigest: string; readonly operationId: string; readonly disposition: string; readonly reason: string } {
  const row = exactObject(value, ["kind", "attemptDigest", "operationId", "disposition", "reason"], "publication terminal");
  const disposition = textField(row, "disposition", 64);
  if (!(PUBLICATION_TERMINAL_DISPOSITIONS as readonly string[]).includes(disposition)) throw new Error("publication terminal disposition is unknown");
  return Object.freeze({ attemptDigest: digestField(row, "attemptDigest"), operationId: digestField(row, "operationId"), disposition, reason: textField(row, "reason", 512) });
}

interface DerivedPublicationRecoveryState {
  readonly attempts: ReadonlyMap<string, PublicationAttemptV1>;
  readonly terminals: ReadonlyMap<string, { readonly row: ReturnType<typeof parsePublicationTerminal>; readonly carrierDigest: string }>;
  readonly adjudications: ReadonlyMap<string, { readonly row: PublicationOperatorAdjudicationV1; readonly carrierDigest: string }>;
  readonly verifiedFacts: ReadonlySet<string>;
  readonly blockedAttempts: ReadonlySet<string>;
  readonly holds: readonly PublicationRecoveryResult[];
}

/** One replay/classification predicate shared by actuator and actuator-free recovery. */
function derivePublicationRecoveryState(replay: readonly StagedEvent[], publicationOperatorTrust?: PublicationOperatorTrust): DerivedPublicationRecoveryState {
  const attempts = new Map<string, PublicationAttemptV1>();
  const terminals = new Map<string, { row: ReturnType<typeof parsePublicationTerminal>; carrierDigest: string }>();
  const adjudications = new Map<string, { row: PublicationOperatorAdjudicationV1; carrierDigest: string }>();
  const verifiedFacts = new Set<string>();
  const verifiedRows = new Map<string, string>();
  const blockedAttempts = new Set<string>();
  const holds: PublicationRecoveryResult[] = [];
  const fallback = (event: StagedEvent) => sha256("keep.malformed-publication-operation/v1\0", event.id);
  const acknowledgementState = replayPublicationQuarantineAcknowledgements(replay, publicationOperatorTrust);
  holds.push(...acknowledgementState.holds);
  for (const event of replay) {
    const payload = event.payload as Record<string, unknown>;
    if (event.type === "effect.terminal" && payload.kind === "auto_merge.publication_quarantine_acknowledged") continue;
    const carrierDigest = publicationQuarantineDigest(event);
    if (acknowledgementState.acknowledged.has(carrierDigest)) continue;
    if (event.type === "effect.intent" && payload.kind === "auto_merge.publication_prepared") {
      try {
        const attempt = parsePublicationAttempt(payload.attempt); const digest = publicationAttemptDigest(attempt);
        if (!attempts.has(digest)) attempts.set(digest, attempt);
        if (payload.attemptDigest !== digest) holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt.attemptedCommit, reason: "prepared attempt digest does not recompute", operationId: attempt.operationId, attemptDigest: carrierDigest });
      } catch (error) { holds.push({ status: "uncertain", needsHuman: true, mergeId: "", reason: `malformed publication preparation quarantined: ${(error as Error).message}`.slice(0, 260), operationId: fallback(event), attemptDigest: carrierDigest }); }
      continue;
    }
    if (event.type === "effect.terminal" && payload.kind === "auto_merge.publication_terminal") {
      try {
        const row = parsePublicationTerminal(payload); const attempt = attempts.get(row.attemptDigest);
        if (!attempt || attempt.operationId !== row.operationId) holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt?.attemptedCommit ?? "", reason: "publication terminal has no exact prior prepared attempt", operationId: row.operationId, attemptDigest: carrierDigest });
        else {
          const prior = terminals.get(row.attemptDigest);
          if (!prior) terminals.set(row.attemptDigest, { row, carrierDigest });
          else if (canonicalize(prior.row) !== canonicalize(row)) {
            blockedAttempts.add(row.attemptDigest);
            holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt.attemptedCommit, reason: "publication terminal contradicts an earlier terminal", operationId: row.operationId, attemptDigest: publicationDuplicateConflictDigest("terminal", prior.row, row) });
          }
        }
      } catch (error) { holds.push({ status: "uncertain", needsHuman: true, mergeId: "", reason: `malformed publication terminal quarantined: ${(error as Error).message}`.slice(0, 260), operationId: fallback(event), attemptDigest: carrierDigest }); }
      continue;
    }
    if (event.type === "effect.terminal" && payload.kind === "auto_merge.publication_adjudicated") {
      try {
        if (!publicationOperatorTrust) throw new Error("no operator trust root is configured");
        const wrapper = exactObject(payload, ["kind", "adjudication"], "publication adjudication terminal");
        const candidate = parseOperatorAdjudication(wrapper.adjudication, publicationOperatorTrust, true); const attempt = attempts.get(candidate.attemptDigest);
        if (!attempt) throw new Error("publication adjudication has no exact prepared effect");
        const adjudication = parseAdjudicationForPrepared(payload, publicationOperatorTrust, attempt, true);
        const prior = adjudications.get(adjudication.attemptDigest);
        if (!prior) adjudications.set(adjudication.attemptDigest, { row: adjudication, carrierDigest });
        else if (canonicalize(prior.row) !== canonicalize(adjudication)) {
          blockedAttempts.add(adjudication.attemptDigest);
          holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt.attemptedCommit, reason: "publication adjudication contradicts an earlier adjudication", operationId: adjudication.operationId, attemptDigest: publicationDuplicateConflictDigest("adjudication", prior.row, adjudication) });
        }
      } catch (error) { holds.push({ status: "uncertain", needsHuman: true, mergeId: "", reason: `publication adjudication observation cannot be verified: ${(error as Error).message}`.slice(0, 260), operationId: fallback(event), attemptDigest: carrierDigest }); }
      continue;
    }
    if (event.type === "effect.receipt" && payload.kind === "auto_merge.publication_verified") {
      try {
        const attemptDigest = digestField(exactObject(payload, ["kind", "attemptDigest", "operationId", "publishedCommit", "publishedTree", "verifiedProjectManifestDigest", "verifiedGuestExecutionRequestDigest"], "publication verified receipt"), "attemptDigest"); const attempt = attempts.get(attemptDigest);
        if (!attempt) throw new Error("publication verified receipt is orphaned, substituted, or duplicated");
        parseVerifiedPublicationReceiptForPrepared(payload, attempt);
        const canonicalReceipt = canonicalize(payload);
        const priorReceipt = verifiedRows.get(attemptDigest);
        if (priorReceipt !== undefined && priorReceipt !== canonicalReceipt) throw new Error("publication verified receipt is orphaned, substituted, or duplicated");
        verifiedRows.set(attemptDigest, canonicalReceipt);
        verifiedFacts.add(attemptDigest);
      } catch (error) {
        try { const digest = digestField(exactObject(payload, ["kind", "attemptDigest", "operationId", "publishedCommit", "publishedTree", "verifiedProjectManifestDigest", "verifiedGuestExecutionRequestDigest"], "publication verified receipt"), "attemptDigest"); if (attempts.has(digest)) blockedAttempts.add(digest); } catch { /* malformed identity has no attempt to block */ }
        holds.push({ status: "uncertain", needsHuman: true, mergeId: "", reason: `publication verified receipt is orphaned, substituted, or duplicated: ${(error as Error).message}`.slice(0, 260), operationId: fallback(event), attemptDigest: carrierDigest });
      }
    }
  }
  const incompatible = new Set(["reconciled-effect-absent", "reverted", "failed", "reconciled-reverted", "reconciled-failed"]);
  for (const [attemptDigest, terminal] of terminals) if (verifiedFacts.has(attemptDigest) && incompatible.has(terminal.row.disposition)) {
    const attempt = attempts.get(attemptDigest);
    blockedAttempts.add(attemptDigest);
    holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt?.attemptedCommit ?? "", reason: "publication terminal contradicts a durable verified publication receipt", operationId: terminal.row.operationId, attemptDigest: terminal.carrierDigest });
  }
  for (const [attemptDigest, adjudication] of adjudications) if (verifiedFacts.has(attemptDigest) && adjudication.row.adjudicatedDisposition === "effect-absent") {
    const attempt = attempts.get(attemptDigest); blockedAttempts.add(attemptDigest);
    holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt?.attemptedCommit ?? "", reason: "effect-absent adjudication contradicts a durable verified publication receipt", operationId: adjudication.row.operationId, attemptDigest: adjudication.carrierDigest });
  }
  const absentTerminalDispositions = new Set(["reconciled-effect-absent", "reverted", "failed", "reconciled-reverted", "reconciled-failed"]);
  for (const [attemptDigest, adjudication] of adjudications) {
    const terminal = terminals.get(attemptDigest); const attempt = attempts.get(attemptDigest);
    if (!terminal) continue;
    const contradiction = adjudication.row.adjudicatedDisposition === "effect-absent"
      ? !absentTerminalDispositions.has(terminal.row.disposition)
      : absentTerminalDispositions.has(terminal.row.disposition);
    if (!contradiction) continue;
    const conflictDigest = sha256("keep.publication-terminal-adjudication-conflict/v1\0", canonicalize({ terminal: terminal.row, adjudication: adjudication.row }));
    blockedAttempts.add(attemptDigest);
    holds.push({ status: "uncertain", needsHuman: true, mergeId: attempt?.attemptedCommit ?? "", reason: "publication terminal contradicts operator adjudication", operationId: terminal.row.operationId, attemptDigest: conflictDigest });
  }
  return Object.freeze({ attempts, terminals, adjudications, verifiedFacts, blockedAttempts, holds: Object.freeze(holds) });
}

/**
 * Read-only appraisal used before constructing a publication actuator. A disappeared configuration must not
 * turn a durable prepared attempt into "nothing to recover". Malformed/orphan recovery evidence is deliberately
 * treated as outstanding so the caller fails closed instead of silently admitting new work.
 */
export function missingPublicationActuatorRecoveryHold(spine: Spine, publicationOperatorTrust?: PublicationOperatorTrust): PublicationRecoveryResult | undefined {
  const replay = spine.replay();
  const fallbackIdentity = sha256("keep.publication-recovery-unavailable/v1\0", replay);
  if (!spine.verify().ok) return {
    status: "uncertain", reason: "publication Spine is not verifiable and no configured publication actuator is available",
    needsHuman: true, operationId: fallbackIdentity, attemptDigest: fallbackIdentity,
  };
  const derived = derivePublicationRecoveryState(replay, publicationOperatorTrust);
  if (derived.holds.length > 0) return derived.holds[0];
  for (const [digest, attempt] of derived.attempts) if (!derived.terminals.has(digest)) return {
    status: "uncertain", reason: "durable publication recovery evidence exists but no configured publication actuator is available",
    needsHuman: true, operationId: attempt.operationId, attemptDigest: digest,
  };
  return undefined;
}

/**
 * Opaque, one-shot proof that the exact publication attempt was appended to and verified from an
 * fsync-durable Spine before the actuator was allowed to publish. Structural lookalikes carry no
 * authority: the verifier-owned WeakMap below is the sole runtime source of truth.
 */
export interface PreparedPublicationAuthority {
  readonly kind: "keep.prepared-publication-authority/v1";
}

const preparedPublicationAuthorities = new WeakMap<object, { readonly attemptDigest: string; readonly spine: Spine }>();

export async function sealPreparedPublication(
  spine: Spine,
  attemptValue: PublicationAttemptV1,
): Promise<PreparedPublicationAuthority> {
  if (!spine.durableStorage()) throw new Error("publication preparation requires an fsync-durable Spine");
  const attempt = parsePublicationAttempt(attemptValue);
  const attemptDigest = publicationAttemptDigest(attempt);
  spine.stage({ type: "effect.intent", actor: "auto-merge", payload: { kind: "auto_merge.publication_prepared", attemptDigest, attempt } });
  await spine.seal();
  const verified = spine.verify();
  if (!verified.ok) throw new Error(`publication prepare could not be durably verified: ${verified.reason ?? "sealed chain verification failed"}`);
  const authority = Object.freeze({ kind: "keep.prepared-publication-authority/v1" as const });
  preparedPublicationAuthorities.set(authority, { attemptDigest, spine });
  return authority;
}

export function consumePreparedPublicationAuthority(
  authority: PreparedPublicationAuthority | undefined,
  attemptValue: PublicationAttemptV1,
  expectedSpine: Spine | undefined,
): boolean {
  if (!authority || typeof authority !== "object" || types.isProxy(authority)) return false;
  const prepared = preparedPublicationAuthorities.get(authority);
  if (prepared === undefined || expectedSpine === undefined || prepared.spine !== expectedSpine ||
      prepared.attemptDigest !== publicationAttemptDigest(attemptValue) || !prepared.spine.verify().ok) return false;
  preparedPublicationAuthorities.delete(authority);
  return true;
}

const HEX40_OR_64 = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const HEX64 = /^[0-9a-f]{64}$/;

function sha256(domain: string, value: unknown): string {
  return createHash("sha256").update(domain).update(canonicalize(value)).digest("hex");
}

function operatorAdjudicationMessage(row: Omit<PublicationOperatorAdjudicationV1, "signatureBase64">): Buffer {
  return Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(row)}`, "utf8");
}

function trustedPublicationKey(trust: PublicationOperatorTrust, keyId: string, allowRevokedHistorical = false) {
  const trustedRows = [{ keyId: trust.keyId, publicKeyPem: trust.publicKeyPem }, ...(trust.historicalKeys ?? [])];
  if (trustedRows.length > 32 || new Set(trustedRows.map((row) => row.keyId)).size !== trustedRows.length) throw new Error("publication operator trust key set is malformed");
  const revoked = trust.revokedKeyIds ?? [];
  if (revoked.length > 32 || new Set(revoked).size !== revoked.length || revoked.some((id) => typeof id !== "string" || id.length === 0 || id.length > 128)) throw new Error("publication operator revoked key set is malformed");
  if (!allowRevokedHistorical && revoked.includes(keyId)) throw new Error("publication operator key is revoked");
  const trusted = trustedRows.find((row) => row.keyId === keyId);
  if (!trusted) throw new Error("publication operator key is not trusted");
  const key = createPublicKey(trusted.publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("publication operator key is not Ed25519");
  return key;
}

function parseOperatorAdjudication(value: unknown, trust: PublicationOperatorTrust, allowRevokedHistorical = false): PublicationOperatorAdjudicationV1 {
  const row = exactObject(value, ["schema", "attemptDigest", "operationId", "adjudicatedDisposition", "observedCommit", "operatorEvidenceDigest", "reason", "keyId", "signatureBase64"], "publication operator adjudication");
  if (row.schema !== "keep.publication-operator-adjudication/v1") throw new Error("publication operator adjudication schema is unknown");
  const adjudicatedDisposition = textField(row, "adjudicatedDisposition", 32);
  if (adjudicatedDisposition !== "effect-occurred" && adjudicatedDisposition !== "effect-absent") throw new Error("publication operator adjudication disposition is unknown");
  const keyId = textField(row, "keyId", 128);
  const signatureBase64 = textField(row, "signatureBase64", 512);
  if (!/^[A-Za-z0-9+/]{86}==$/.test(signatureBase64)) throw new Error("publication operator adjudication signature is malformed");
  const parsed = Object.freeze({
    schema: "keep.publication-operator-adjudication/v1" as const,
    attemptDigest: digestField(row, "attemptDigest"),
    operationId: digestField(row, "operationId"),
    adjudicatedDisposition,
    observedCommit: oidField(row, "observedCommit"),
    operatorEvidenceDigest: digestField(row, "operatorEvidenceDigest"),
    reason: textField(row, "reason", 512),
    keyId,
    signatureBase64,
  });
  const { signatureBase64: _signature, ...unsigned } = parsed;
  const key = trustedPublicationKey(trust, keyId, allowRevokedHistorical);
  if (!verifySignature(null, operatorAdjudicationMessage(unsigned), key, Buffer.from(signatureBase64, "base64"))) {
    throw new Error("publication operator adjudication signature is invalid");
  }
  return parsed;
}

function quarantineAcknowledgementMessage(row: Omit<PublicationQuarantineAcknowledgementV1, "signatureBase64">): Buffer {
  return Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(row)}`, "utf8");
}

function parseQuarantineAcknowledgement(value: unknown, trust: PublicationOperatorTrust): PublicationQuarantineAcknowledgementV1 {
  const row = exactObject(value, ["schema", "quarantineDigest", "operatorEvidenceDigest", "reason", "keyId", "signatureBase64"], "publication quarantine acknowledgement");
  if (row.schema !== "keep.publication-quarantine-acknowledgement/v1") throw new Error("publication quarantine acknowledgement schema is unknown");
  const keyId = textField(row, "keyId", 128);
  const signatureBase64 = textField(row, "signatureBase64", 512);
  if (!/^[A-Za-z0-9+/]{86}==$/.test(signatureBase64)) throw new Error("publication quarantine acknowledgement signature is malformed");
  const parsed = Object.freeze({ schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest: digestField(row, "quarantineDigest"), operatorEvidenceDigest: digestField(row, "operatorEvidenceDigest"), reason: textField(row, "reason", 512), keyId, signatureBase64 });
  const { signatureBase64: _signature, ...unsigned } = parsed;
  if (!verifySignature(null, quarantineAcknowledgementMessage(unsigned), trustedPublicationKey(trust, keyId), Buffer.from(signatureBase64, "base64"))) throw new Error("publication quarantine acknowledgement signature is invalid");
  return parsed;
}

function replayPublicationQuarantineAcknowledgements(
  replay: readonly { readonly id: string; readonly type: string; readonly payload: unknown }[],
  trust: PublicationOperatorTrust | undefined,
): { readonly acknowledged: ReadonlySet<string>; readonly holds: readonly PublicationRecoveryResult[] } {
  const acknowledged = new Set<string>();
  const invalid: { event: unknown; reason: string }[] = [];
  for (const event of replay) {
    const payload = event.payload as Record<string, unknown>;
    if (event.type !== "effect.terminal" || payload.kind !== "auto_merge.publication_quarantine_acknowledged") continue;
    try {
      if (!trust) throw new Error("no operator trust root is configured");
      const row = exactObject(payload, ["kind", "acknowledgement"], "publication quarantine acknowledgment");
      acknowledged.add(parseQuarantineAcknowledgement(row.acknowledgement, trust).quarantineDigest);
    } catch (error) { invalid.push({ event, reason: (error as Error).message }); }
  }
  const holds: PublicationRecoveryResult[] = [];
  for (const { event, reason } of invalid) {
    const quarantineDigest = publicationQuarantineDigest(event);
    if (acknowledged.has(quarantineDigest)) continue;
    holds.push({
      status: "uncertain" as const, needsHuman: true, mergeId: "",
      reason: `malformed publication quarantine acknowledgment: ${reason}`.slice(0, 260),
      operationId: sha256("keep.malformed-publication-operation/v1\0", (event as { id: string }).id), attemptDigest: quarantineDigest,
    });
  }
  return { acknowledged, holds: Object.freeze(holds) };
}

function parseAdjudicationForPrepared(value: unknown, trust: PublicationOperatorTrust, prepared: PublicationAttemptV1, allowRevokedHistorical = false): PublicationOperatorAdjudicationV1 {
  const row = exactObject(value, ["kind", "adjudication"], "publication adjudication observation");
  const adjudication = parseOperatorAdjudication(row.adjudication, trust, allowRevokedHistorical);
  const expectedObserved = adjudication.adjudicatedDisposition === "effect-occurred" ? prepared.attemptedCommit : prepared.priorPublishedCommit;
  if (adjudication.attemptDigest !== publicationAttemptDigest(prepared) || adjudication.operationId !== prepared.operationId || adjudication.observedCommit !== expectedObserved) throw new Error("publication adjudication is not bound to the exact prepared effect");
  return adjudication;
}

function parseVerifiedPublicationReceiptForPrepared(value: unknown, prepared: PublicationAttemptV1): string {
  const row = exactObject(value, ["kind", "attemptDigest", "operationId", "publishedCommit", "publishedTree", "verifiedProjectManifestDigest", "verifiedGuestExecutionRequestDigest"], "publication verified receipt");
  if (row.kind !== "auto_merge.publication_verified") throw new Error("publication verified receipt kind is unknown");
  const attemptDigest = digestField(row, "attemptDigest");
  if (attemptDigest !== publicationAttemptDigest(prepared) || digestField(row, "operationId") !== prepared.operationId || oidField(row, "publishedCommit") !== prepared.identity.publishedCommit || oidField(row, "publishedTree") !== prepared.identity.publishedTree || digestField(row, "verifiedProjectManifestDigest") !== prepared.identity.publishedProjectManifestDigest || digestField(row, "verifiedGuestExecutionRequestDigest") !== prepared.spec.expectedGuestExecutionRequestDigest) throw new Error("publication verified receipt is not bound to the exact prepared effect");
  return attemptDigest;
}

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length !== 0) throw new Error(`${label} must be one inert plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Object.keys(descriptors).sort();
  const expected = [...keys].sort();
  if (canonicalize(actual) !== canonicalize(expected)) throw new Error(`${label} has missing or unknown fields`);
  const snapshot: Record<string, unknown> = {};
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error(`${label}.${key} must be one enumerable data property`);
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function exactStringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0) throw new Error(`${label} is malformed`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
  const length = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : undefined;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0 || length > 128) throw new Error(`${label}.length is malformed`);
  const expected = ["length", ...Array.from({ length }, (_, index) => String(index))].sort();
  if (canonicalize(Object.keys(descriptors).sort()) !== canonicalize(expected)) throw new Error(`${label} must be one exact dense array`);
  const out: string[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = descriptors[String(index)];
    const entry = descriptor && "value" in descriptor ? descriptor.value : undefined;
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true || typeof entry !== "string" || entry.length === 0 || entry.length > 4096 || entry.includes("\0")) throw new Error(`${label}[${index}] is malformed`);
    out.push(entry);
  }
  return Object.freeze(out);
}

function textField(row: Record<string, unknown>, key: string, max = 4096): string {
  const value = row[key];
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.includes("\0")) throw new Error(`${key} is malformed`);
  return value;
}

function digestField(row: Record<string, unknown>, key: string): string {
  const value = textField(row, key, 64);
  if (!HEX64.test(value)) throw new Error(`${key} is not one sha256 digest`);
  return value;
}

function oidField(row: Record<string, unknown>, key: string): string {
  const value = textField(row, key, 64);
  if (!HEX40_OR_64.test(value)) throw new Error(`${key} is not one full Git object id`);
  return value;
}

function capturePublishedIdentity(value: unknown): PublishedMergeIdentity {
  const row = exactObject(value, ["candidateCommit", "candidateTree", "candidateProjectManifestDigest", "baseCommit", "baseTree", "expectedMergedTree", "mergedCommit", "mergedTree", "publishedCommit", "publishedTree", "publishedProjectManifestDigest", "publicationTarget"], "publication attempt identity");
  return Object.freeze({
    candidateCommit: oidField(row, "candidateCommit"), candidateTree: oidField(row, "candidateTree"), candidateProjectManifestDigest: digestField(row, "candidateProjectManifestDigest"),
    baseCommit: oidField(row, "baseCommit"), baseTree: oidField(row, "baseTree"), expectedMergedTree: oidField(row, "expectedMergedTree"),
    mergedCommit: oidField(row, "mergedCommit"), mergedTree: oidField(row, "mergedTree"), publishedCommit: oidField(row, "publishedCommit"),
    publishedTree: oidField(row, "publishedTree"), publishedProjectManifestDigest: digestField(row, "publishedProjectManifestDigest"), publicationTarget: textField(row, "publicationTarget", 512),
  });
}

/** Exact inert parser for the durable recovery carrier. Recovery never trusts a structural cast from the Spine. */
export function parsePublicationAttempt(value: unknown): PublicationAttemptV1 {
  const row = exactObject(value, ["schema", "operationId", "spec", "identity", "attemptedCommit", "priorPublishedCommit", "publicationTarget"], "publication attempt");
  if (row.schema !== "keep.publication-attempt/v1") throw new Error("publication attempt schema is unknown");
  const specRow = exactObject(row.spec, ["issueId", "repoRef", "branch", "baseBranch", "expectedCandidateCommit", "expectedCandidateProjectManifestDigest", "expectedGuestExecutionRequestDigest", "projectDir", "executionAuxiliaryRoots"], "publication attempt spec");
  const executionAuxiliaryRoots = exactStringArray(specRow.executionAuxiliaryRoots, "executionAuxiliaryRoots");
  const spec: MergeSpec = Object.freeze({
    issueId: textField(specRow, "issueId", 256), repoRef: textField(specRow, "repoRef", 2048), branch: textField(specRow, "branch", 256), baseBranch: textField(specRow, "baseBranch", 256),
    expectedCandidateCommit: oidField(specRow, "expectedCandidateCommit"), expectedCandidateProjectManifestDigest: digestField(specRow, "expectedCandidateProjectManifestDigest"),
    expectedGuestExecutionRequestDigest: digestField(specRow, "expectedGuestExecutionRequestDigest"), projectDir: textField(specRow, "projectDir", 4096),
    executionAuxiliaryRoots,
  });
  const identity = capturePublishedIdentity(row.identity);
  const attempt: PublicationAttemptV1 = Object.freeze({
    schema: "keep.publication-attempt/v1", operationId: digestField(row, "operationId"), spec, identity,
    attemptedCommit: oidField(row, "attemptedCommit"), priorPublishedCommit: oidField(row, "priorPublishedCommit"), publicationTarget: textField(row, "publicationTarget", 512),
  });
  const semantic = { spec, preflight: {
    candidateCommit: identity.candidateCommit, candidateTree: identity.candidateTree, candidateProjectManifestDigest: identity.candidateProjectManifestDigest,
    baseCommit: identity.baseCommit, baseTree: identity.baseTree, expectedMergedTree: identity.expectedMergedTree,
  }, publicationTarget: attempt.publicationTarget };
  if (attempt.operationId !== sha256("keep.publication-operation/v1\0", semantic)) throw new Error("publication operationId does not recompute");
  if (attempt.attemptedCommit !== identity.mergedCommit || identity.publishedCommit !== identity.mergedCommit || identity.publishedTree !== identity.mergedTree ||
      identity.expectedMergedTree !== identity.mergedTree || attempt.priorPublishedCommit !== identity.baseCommit || attempt.publicationTarget !== identity.publicationTarget) {
    throw new Error("publication attempt identities are inconsistent");
  }
  return attempt;
}

export function publicationAttemptDigest(attempt: PublicationAttemptV1): string {
  return sha256("keep.publication-attempt/v1\0", parsePublicationAttempt(attempt));
}

export function makePublicationAttempt(spec: MergeSpec, identity: PublishedMergeIdentity): PublicationAttemptV1 {
  if (spec === null || typeof spec !== "object" || types.isProxy(spec)) throw new Error("merge spec must be one inert plain object");
  const hasAuxiliaryRoots = Object.getOwnPropertyDescriptors(spec).executionAuxiliaryRoots !== undefined;
  const source = exactObject(spec, hasAuxiliaryRoots
    ? ["issueId", "repoRef", "branch", "baseBranch", "expectedCandidateCommit", "expectedCandidateProjectManifestDigest", "expectedGuestExecutionRequestDigest", "projectDir", "executionAuxiliaryRoots"]
    : ["issueId", "repoRef", "branch", "baseBranch", "expectedCandidateCommit", "expectedCandidateProjectManifestDigest", "expectedGuestExecutionRequestDigest", "projectDir"], "merge spec");
  const safeSpec = {
    issueId: textField(source, "issueId", 256), repoRef: textField(source, "repoRef", 2048), branch: textField(source, "branch", 256), baseBranch: textField(source, "baseBranch", 256),
    expectedCandidateCommit: oidField(source, "expectedCandidateCommit"), expectedCandidateProjectManifestDigest: digestField(source, "expectedCandidateProjectManifestDigest"),
    expectedGuestExecutionRequestDigest: digestField(source, "expectedGuestExecutionRequestDigest"), projectDir: textField(source, "projectDir", 4096),
    executionAuxiliaryRoots: hasAuxiliaryRoots ? exactStringArray(source.executionAuxiliaryRoots, "executionAuxiliaryRoots") : Object.freeze([] as string[]),
  };
  const safeIdentity = capturePublishedIdentity(identity);
  const canonicalSpec = parsePublicationAttempt({
    schema: "keep.publication-attempt/v1",
    operationId: sha256("keep.publication-operation/v1\0", { spec: safeSpec, preflight: {
      candidateCommit: safeIdentity.candidateCommit, candidateTree: safeIdentity.candidateTree, candidateProjectManifestDigest: safeIdentity.candidateProjectManifestDigest,
      baseCommit: safeIdentity.baseCommit, baseTree: safeIdentity.baseTree, expectedMergedTree: safeIdentity.expectedMergedTree,
    }, publicationTarget: safeIdentity.publicationTarget }),
    spec: safeSpec, identity: safeIdentity,
    attemptedCommit: safeIdentity.mergedCommit, priorPublishedCommit: safeIdentity.baseCommit, publicationTarget: safeIdentity.publicationTarget,
  });
  return canonicalSpec;
}

export interface MergeOutcome {
  readonly merged: boolean;
  /** Idempotent rollback handle (e.g. the pre-merge base commit / the merge commit). */
  readonly mergeId: string;
  readonly identity?: PublishedMergeIdentity;
  /** The publication effect may have happened, but its authoritative ref could not be reconciled. Never retry blindly. */
  readonly uncertainPublication?: {
    readonly attemptedCommit: string;
    readonly priorPublishedCommit: string;
    readonly publicationTarget: string;
    readonly reason: string;
  };
  /** The exact prepared effect was proven absent and its local merge was compensated. */
  readonly compensatedPublicationAbsent?: true;
  readonly reason?: string;
  /** A local merge exists but its compensating revert failed. The residue must be surfaced, never hidden. */
  readonly rollbackFailed?: boolean;
}

export interface RevertOutcome {
  readonly reverted: boolean;
  /** Exact history-preserving compensation commit when the port can observe one. */
  readonly revertCommit?: string;
  readonly reason?: string;
}

/** The merge capability — swappable. Real impl drives git; the in-memory impl proves the executor's logic. */
export interface MergePort {
  /** Exact authority target named before mutation and carried into recovery evidence. */
  publicationTarget(spec: MergeSpec): string;
  /** Would this branch merge cleanly into the CURRENT base? (base may have moved since the solve). */
  dryRun(spec: MergeSpec): Promise<{ clean: boolean; identity?: MergePreflightIdentity; reason?: string }>;
  /** Merge only the identity returned by dryRun. Implementations must refuse any intervening movement. */
  merge(spec: MergeSpec, preflight: MergePreflightIdentity, preparePublication: (attempt: PublicationAttemptV1) => Promise<PreparedPublicationAuthority>): Promise<MergeOutcome>;
  /** Read-only authoritative observation. It must never retry or otherwise reproduce the publication effect. */
  observePublication(attempt: PublicationAttemptV1): Promise<PublicationObservation>;
  /** Reconcile local unpublished residue after authoritative observation proves the effect absent. */
  reconcileAbsentPublication(attempt: PublicationAttemptV1): Promise<{ reconciled: boolean; reason: string }>;
  /** Re-observe the authoritative publication target after verification, before success is recorded. */
  confirmPublished(identity: PublishedMergeIdentity, spec: MergeSpec): Promise<{ current: boolean; reason?: string }>;
  /** Must be replay-safe: re-observe and reconcile the exact prior compensation before issuing another effect. */
  revert(mergeId: string, spec: MergeSpec, expectedPublicationTarget?: string): Promise<RevertOutcome>;
}

export type AutonomousMergeStatus =
  | "merged"        // merged + post-merge verified clean
  | "reverted"      // merged, regressed, auto-reverted (a human is notified — rare + loud)
  | "abstained"     // base moved / would not apply cleanly — did not merge (re-solve)
  | "refused"       // not an autonomous-merge verdict, or the kill switch is engaged
  | "uncertain"     // publication may have happened; preserve and reconcile, never blindly retry
  | "failed";       // the merge itself failed

export interface AutonomousMergeResult {
  readonly status: AutonomousMergeStatus;
  readonly mergeId?: string;
  readonly reason: string;
  /** True when an auto-merged change regressed and was reverted — the one case that surfaces to a human. */
  readonly needsHuman: boolean;
}

export interface MergeExecutorDeps {
  readonly port: MergePort;
  readonly spine: Spine;
  /** Re-run the oracle (project tests) against the MERGED base; regressed=true → auto-revert. */
  readonly postMergeVerify: (spec: MergeSpec, identity: PublishedMergeIdentity) => Promise<{ regressed: boolean; detail?: string; verifiedProjectManifestDigest?: string; verifiedGuestExecutionRequestDigest?: string; executionSubjectAuthority?: VerifiedExecutionSubjectAuthority }>;
  /** The kill switch — if engaged, the entire autonomous path pauses (deny-by-default). */
  readonly killSwitchEngaged?: () => boolean;
  /** Separately-held public key for exceptional, exact-attempt publication adjudication. */
  readonly publicationOperatorTrust?: PublicationOperatorTrust;
}

export function classifyPostMergeExecutionSubject(
  spec: Pick<MergeSpec, "expectedGuestExecutionRequestDigest">,
  identity: Pick<PublishedMergeIdentity, "publishedProjectManifestDigest">,
  check: { readonly verifiedProjectManifestDigest?: string; readonly verifiedGuestExecutionRequestDigest?: string },
  executionSubjectAuthorityVerified: boolean,
): { readonly mismatch: boolean; readonly requestMismatch: boolean; readonly authorityMissing: boolean } {
  const requestMismatch = check.verifiedGuestExecutionRequestDigest !== spec.expectedGuestExecutionRequestDigest;
  const authorityMissing = !executionSubjectAuthorityVerified;
  return {
    requestMismatch,
    authorityMissing,
    mismatch: check.verifiedProjectManifestDigest !== identity.publishedProjectManifestDigest || authorityMissing || requestMismatch,
  };
}

export class AutonomousMergeExecutor {
  constructor(private readonly deps: MergeExecutorDeps) {}

  private audit(event: string, spec: MergeSpec, extra: Record<string, unknown> = {}): void {
    this.deps.spine.stage({ type: "identity.action", actor: "auto-merge", payload: { event, issueId: spec.issueId, branch: spec.branch, ts: Date.now(), ...extra } });
  }

  private async sealCurrent(label: string): Promise<void> {
    await this.deps.spine.seal();
    const verified = this.deps.spine.verify();
    if (!verified.ok) throw new Error(`${label}: ${verified.reason ?? "sealed chain verification failed"}`);
  }

  private async preparePublication(attemptValue: PublicationAttemptV1): Promise<PreparedPublicationAuthority> {
    return sealPreparedPublication(this.deps.spine, attemptValue);
  }

  private async terminal(attempt: PublicationAttemptV1, disposition: string, reason: string): Promise<void> {
    stagePublicationTerminal(this.deps.spine, attempt, disposition as PublicationTerminalDisposition, reason);
    await this.sealCurrent("publication terminal could not be durably sealed");
  }

  private async finalizePublished(attempt: PublicationAttemptV1, recovering = false): Promise<AutonomousMergeResult> {
    const { spec, identity } = attempt;
    const mergeId = identity.mergedCommit;
    this.audit("auto_merge.merged", spec, {
      mergeId, candidateCommit: identity.candidateCommit, candidateTree: identity.candidateTree,
      mergedTree: identity.mergedTree, publishedCommit: identity.publishedCommit, publishedTree: identity.publishedTree,
      publishedProjectManifestDigest: identity.publishedProjectManifestDigest, publicationTarget: identity.publicationTarget,
    });

    let check: { regressed: boolean; detail?: string; verifiedProjectManifestDigest?: string; verifiedGuestExecutionRequestDigest?: string; executionSubjectAuthority?: VerifiedExecutionSubjectAuthority };
    try {
      check = await this.deps.postMergeVerify(spec, identity);
    } catch (e) {
      if (recovering) return {
        status: "uncertain", mergeId,
        reason: `published effect exists but recovery verification is unavailable: ${(e as Error).message}`,
        needsHuman: true,
      };
      check = { regressed: true, detail: `post-merge verify threw — fail-safe revert: ${(e as Error).message}` };
    }
    const postMergeAuthorityVerified = consumeVerifiedExecutionSubjectAuthority(check.executionSubjectAuthority, spec.projectDir, identity.publishedProjectManifestDigest);
    const classification = classifyPostMergeExecutionSubject(spec, identity, check, postMergeAuthorityVerified);
    const { requestMismatch, authorityMissing: postMergeAuthorityMissing, mismatch: manifestMismatch } = classification;
    if (recovering && !check.regressed && manifestMismatch) return {
      status: "uncertain", mergeId,
      reason: `published effect exists but recovery verification produced no current matching Firecracker authority (authority=${postMergeAuthorityMissing ? "missing" : "present"}, manifest=${manifestMismatch ? "mismatch-or-absent" : "matched"}, request=${requestMismatch ? "mismatch-or-absent" : "matched"})`,
      needsHuman: true,
    };
    let publication: { current: boolean; reason?: string } = { current: false, reason: "post-merge verification did not complete" };
    if (!check.regressed && !manifestMismatch) {
      try { publication = await this.deps.port.confirmPublished(identity, spec); }
      catch (e) { publication = { current: false, reason: `publication confirmation threw: ${(e as Error).message}` }; }
    }
    if (check.regressed || manifestMismatch || !publication.current) {
      const detail = check.regressed
        ? check.detail ?? "post-merge verification regressed"
        : manifestMismatch
          ? `post-merge Firecracker authority/manifest/request mismatch: authority=${postMergeAuthorityMissing ? "absent-replayed-or-substituted" : "verified"} verified=${check.verifiedProjectManifestDigest ?? "absent"} published=${identity.publishedProjectManifestDigest} request=${requestMismatch ? "changed-or-absent" : "verified"}`
          : publication.reason ?? "published ref/tree moved during verification";
      this.audit("auto_merge.regression", spec, { mergeId, detail });
      const rev = await this.deps.port.revert(mergeId, spec, identity.publicationTarget);
      this.audit("auto_merge.reverted", spec, { mergeId, reverted: rev.reverted, reason: rev.reason ?? "" });
      if (!rev.reverted) return { status: "failed", mergeId, reason: `auto-merged change failed published-tree verification and compensating revert FAILED: ${detail}; ${rev.reason ?? "unknown revert failure"}`, needsHuman: true };
      return { status: "reverted", mergeId, reason: `auto-merged change failed published-tree verification and was auto-reverted: ${detail}`, needsHuman: true };
    }

    this.audit("auto_merge.verified", spec, {
      mergeId, candidateCommit: identity.candidateCommit, candidateProjectManifestDigest: identity.candidateProjectManifestDigest,
      mergedCommit: identity.mergedCommit, mergedTree: identity.mergedTree, publishedCommit: identity.publishedCommit,
      publishedTree: identity.publishedTree, verifiedProjectManifestDigest: check.verifiedProjectManifestDigest, publicationTarget: identity.publicationTarget,
    });
    this.deps.spine.stage({ type: "effect.receipt", actor: "auto-merge", payload: {
      kind: "auto_merge.publication_verified", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId,
      publishedCommit: identity.publishedCommit, publishedTree: identity.publishedTree,
      verifiedProjectManifestDigest: check.verifiedProjectManifestDigest,
      verifiedGuestExecutionRequestDigest: check.verifiedGuestExecutionRequestDigest,
    } });
    try { await this.sealCurrent("post-publication verification fact could not be durably sealed"); }
    catch (error) { return { status: "uncertain", mergeId, reason: (error as Error).message, needsHuman: true }; }
    return { status: "merged", mergeId, reason: "merged and post-merge verified clean", needsHuman: false };
  }

  private async finalizePreviouslyVerified(attempt: PublicationAttemptV1): Promise<AutonomousMergeResult> {
    try {
      const current = await this.deps.port.confirmPublished(attempt.identity, attempt.spec);
      if (!current.current) return {
        status: "uncertain", mergeId: attempt.attemptedCommit,
        reason: `durably verified publication could not be reconfirmed: ${current.reason ?? "publication identity moved"}`,
        needsHuman: true,
      };
      return { status: "merged", mergeId: attempt.attemptedCommit, reason: "durably verified publication was reconfirmed", needsHuman: false };
    } catch (error) {
      return { status: "uncertain", mergeId: attempt.attemptedCommit, reason: `durably verified publication reconfirmation is unavailable: ${(error as Error).message}`, needsHuman: true };
    }
  }

  /**
   * Fresh-process recovery for publication attempts whose exact pre-effect carrier was sealed but no terminal was.
   * This method performs read-only observation first and never calls merge/push. An observed delivery is subjected to
   * the same post-publication verifier as the uninterrupted path before it can become `merged`.
   */
  async reconcileOutstandingPublications(): Promise<readonly PublicationRecoveryResult[]> {
    return this.deps.spine.withCoordinationLock("publication.coordinator", () => this.reconcileOutstandingPublicationsLocked());
  }

  /** Signed, content-addressed disposition for structurally invalid non-intent history; bytes remain in the Spine. */
  async acknowledgePublicationQuarantine(input: PublicationQuarantineAcknowledgementV1): Promise<void> {
    const trust = this.deps.publicationOperatorTrust;
    if (!trust) throw new Error("publication quarantine acknowledgement trust is not configured");
    const acknowledgement = parseQuarantineAcknowledgement(input, trust);
    await this.deps.spine.withCoordinationLock("publication.coordinator", async () => {
      if (!this.deps.spine.verify().ok || !this.deps.spine.durableStorage()) throw new Error("publication quarantine acknowledgement requires a verifiable durable Spine");
      const target = this.deps.spine.replay().find((event) => publicationQuarantineDigest(event) === acknowledgement.quarantineDigest);
      if (!target) throw new Error("publication quarantine acknowledgement has no exact carrier");
      const targetPayload = target.payload as Record<string, unknown>;
      const preparedByDigest = new Map<string, PublicationAttemptV1>();
      for (const event of this.deps.spine.replay()) {
        const payload = event.payload as Record<string, unknown>;
        if (event.type !== "effect.intent" || payload.kind !== "auto_merge.publication_prepared") continue;
        try { const prepared = parsePublicationAttempt(payload.attempt); preparedByDigest.set(publicationAttemptDigest(prepared), prepared); } catch { /* malformed preparations carry no authority */ }
      }
      if (target.type === "effect.intent" && targetPayload.kind === "auto_merge.publication_prepared") {
        try {
          const candidate = parsePublicationAttempt(targetPayload.attempt);
          const candidateDigest = publicationAttemptDigest(candidate);
          if (targetPayload.attemptDigest === candidateDigest) throw new Error("a valid prepared publication effect cannot be quarantined without determining its outcome");
          const replay = this.deps.spine.replay();
          const independentlyCarried = replay.some((event) => {
            if (event.id === target.id) return false;
            const payload = event.payload as Record<string, unknown>;
            if (event.type === "effect.intent" && payload.kind === "auto_merge.publication_prepared") {
              try { return publicationAttemptDigest(parsePublicationAttempt(payload.attempt)) === candidateDigest; } catch { return false; }
            }
            if (event.type === "effect.terminal" && (payload.kind === "auto_merge.publication_terminal" || payload.kind === "auto_merge.publication_adjudicated")) {
              try {
                return payload.kind === "auto_merge.publication_terminal"
                  ? (() => { const terminal = parsePublicationTerminal(payload); return terminal.attemptDigest === candidateDigest && terminal.operationId === candidate.operationId; })()
                  : (() => { const adjudication = parseOperatorAdjudication(exactObject(payload, ["kind", "adjudication"], "publication adjudication observation").adjudication, trust, true); return adjudication.attemptDigest === candidateDigest && adjudication.operationId === candidate.operationId; })();
              } catch { return false; }
            }
            return false;
          });
          if (!independentlyCarried) throw new Error("a parseable unterminated prepared publication effect cannot be quarantined while it is the sole carrier");
        } catch (error) {
          if (/prepared publication effect cannot be quarantined/.test((error as Error).message)) throw error;
          // A structurally invalid historical carrier has no reconstructable effect identity.
          // It may be dispositioned only by this separately signed, content-addressed path.
        }
      } else if (target.type === "effect.terminal" && targetPayload.kind === "auto_merge.publication_terminal") {
        try {
          const terminal = parsePublicationTerminal(targetPayload); const prepared = preparedByDigest.get(terminal.attemptDigest);
          if (prepared && terminal.operationId === prepared.operationId) throw new Error("a valid publication terminal cannot be quarantined");
        } catch (error) { if ((error as Error).message === "a valid publication terminal cannot be quarantined") throw error; }
      } else if (target.type === "effect.terminal" && targetPayload.kind === "auto_merge.publication_adjudicated") {
        try {
          const candidate = parseOperatorAdjudication(exactObject(targetPayload, ["kind", "adjudication"], "publication adjudication observation").adjudication, trust, true); const prepared = preparedByDigest.get(candidate.attemptDigest);
          if (prepared) { parseAdjudicationForPrepared(targetPayload, trust, prepared, true); throw new Error("a valid publication adjudication cannot be quarantined"); }
        } catch (error) { if ((error as Error).message === "a valid publication adjudication cannot be quarantined") throw error; }
      } else if (target.type === "effect.receipt" && targetPayload.kind === "auto_merge.publication_verified") {
        try {
          const attemptDigest = digestField(exactObject(targetPayload, ["kind", "attemptDigest", "operationId", "publishedCommit", "publishedTree", "verifiedProjectManifestDigest", "verifiedGuestExecutionRequestDigest"], "publication verified receipt"), "attemptDigest"); const prepared = preparedByDigest.get(attemptDigest);
          if (prepared) { parseVerifiedPublicationReceiptForPrepared(targetPayload, prepared); throw new Error("a valid publication verified receipt cannot be quarantined"); }
        } catch (error) { if ((error as Error).message === "a valid publication verified receipt cannot be quarantined") throw error; }
      }
      this.deps.spine.stage({ type: "effect.terminal", actor: `auto-merge-operator:${acknowledgement.keyId}`, payload: { kind: "auto_merge.publication_quarantine_acknowledged", acknowledgement } });
      await this.sealCurrent("publication quarantine acknowledgment could not be durably sealed");
    });
  }

  /**
   * Resolve a genuinely in-doubt historical publication only with an externally signed, exact-attempt decision.
   * This does not erase the prepared effect or infer absence from configuration drift; it appends a terminal fact.
   */
  async adjudicatePublication(input: PublicationOperatorAdjudicationV1): Promise<void> {
    const trust = this.deps.publicationOperatorTrust;
    if (!trust) throw new Error("publication operator adjudication trust is not configured");
    const adjudication = parseOperatorAdjudication(input, trust);
    await this.deps.spine.withCoordinationLock("publication.coordinator", async () => {
      if (!this.deps.spine.verify().ok || !this.deps.spine.durableStorage()) throw new Error("publication operator adjudication requires a verifiable durable Spine");
      // Consume the same order-independent, acknowledgement-aware predicate as
      // both recovery readers.  A third bespoke replay walk previously revived
      // event-order and loose-receipt bugs that the shared derivation had closed.
      const derived = derivePublicationRecoveryState(this.deps.spine.replay(), trust);
      const prepared = derived.attempts.get(adjudication.attemptDigest);
      if (!prepared || prepared.operationId !== adjudication.operationId) throw new Error("publication operator adjudication has no exact prepared attempt");
      if (derived.terminals.has(adjudication.attemptDigest) || derived.adjudications.has(adjudication.attemptDigest)) throw new Error("publication operator adjudication cannot replace an existing terminal");
      if (derived.verifiedFacts.has(adjudication.attemptDigest) && adjudication.adjudicatedDisposition === "effect-absent") throw new Error("effect-absent adjudication contradicts a durable verified publication receipt");
      const expectedObserved = adjudication.adjudicatedDisposition === "effect-occurred" ? prepared.attemptedCommit : prepared.priorPublishedCommit;
      if (adjudication.observedCommit !== expectedObserved) throw new Error("publication operator adjudication observed commit contradicts its disposition");
      this.deps.spine.stage({ type: "effect.terminal", actor: `auto-merge-operator:${adjudication.keyId}`, payload: { kind: "auto_merge.publication_adjudicated", adjudication } });
      await this.sealCurrent("publication operator adjudication could not be durably sealed");
      const reconciled = await this.reconcileOutstandingPublicationsLocked();
      const row = reconciled.find((candidate) => candidate.attemptDigest === adjudication.attemptDigest);
      if (row?.needsHuman || row?.status === "uncertain" || row?.status === "failed" || row?.status === "refused") {
        throw new Error(`publication adjudication was preserved but recovery remains held: ${row.reason}`);
      }
    });
  }

  private async reconcileOutstandingPublicationsLocked(): Promise<readonly PublicationRecoveryResult[]> {
    const verified = this.deps.spine.verify();
    if (!verified.ok) throw new Error(`publication recovery refused an unverifiable Spine: ${verified.reason ?? "unknown chain failure"}`);
    const replay = this.deps.spine.replay();
    const derived = derivePublicationRecoveryState(replay, this.deps.publicationOperatorTrust);
    const { attempts, terminals, adjudications, verifiedFacts, blockedAttempts } = derived;
    if (attempts.size === 0) return derived.holds;
    if (!this.deps.spine.durableStorage()) throw new Error("publication recovery requires an fsync-durable Spine when publication intents exist");
    const results: PublicationRecoveryResult[] = [...derived.holds];
    for (const [attemptDigest, attempt] of attempts) {
      if (terminals.has(attemptDigest) || blockedAttempts.has(attemptDigest)) continue;
      if (this.deps.killSwitchEngaged?.()) {
        results.push({ status: "refused", mergeId: attempt.attemptedCommit, reason: "kill switch engaged — publication recovery paused before observation or compensation", needsHuman: false, operationId: attempt.operationId, attemptDigest });
        continue;
      }
      const adjudication = adjudications.get(attemptDigest)?.row;
      const observation: PublicationObservation = adjudication
        ? { status: adjudication.adjudicatedDisposition, observedCommit: adjudication.observedCommit, reason: `signed operator observation: ${adjudication.reason}` }
        : await this.deps.port.observePublication(attempt);
      let result: AutonomousMergeResult;
      if (observation.status === "effect-occurred") {
        result = verifiedFacts.has(attemptDigest)
          ? await this.finalizePreviouslyVerified(attempt)
          : await this.finalizePublished(attempt, true);
        if (result.status !== "uncertain") await this.terminal(attempt, result.status === "merged" ? "reconciled-effect-occurred" : `reconciled-${result.status}`, result.reason);
      } else if (observation.status === "effect-absent") {
        const local = await this.deps.port.reconcileAbsentPublication(attempt);
        if (!local.reconciled) {
          result = { status: "uncertain", mergeId: attempt.attemptedCommit, reason: `remote publication is absent but local residue remains held: ${local.reason}`, needsHuman: true };
        } else {
          result = { status: "abstained", mergeId: attempt.attemptedCommit, reason: `publication was durably reconciled absent; no retry performed: ${observation.reason}; ${local.reason}`, needsHuman: false };
          await this.terminal(attempt, "reconciled-effect-absent", result.reason);
        }
      } else {
        result = { status: "uncertain", mergeId: attempt.attemptedCommit, reason: `publication remains held (${observation.status}): ${observation.reason}`, needsHuman: true };
      }
      results.push({ ...result, operationId: attempt.operationId, attemptDigest });
    }
    return Object.freeze(results);
  }

  async execute(decision: MergeAuthorityDecision, spec: MergeSpec, executionSubjectAuthority?: VerifiedExecutionSubjectAuthority): Promise<AutonomousMergeResult> {
    return this.deps.spine.withCoordinationLock("publication.coordinator", () => this.executeLocked(decision, spec, executionSubjectAuthority));
  }

  private async executeLocked(decision: MergeAuthorityDecision, spec: MergeSpec, executionSubjectAuthority?: VerifiedExecutionSubjectAuthority): Promise<AutonomousMergeResult> {
    // GATE 1 (structural): only an autonomous-merge verdict may ever merge. Everything else is refused here —
    // a human-merge / abandon-retry / block change can never be merged by this executor.
    if (decision.verdict !== "autonomous-merge") {
      this.audit("auto_merge.refused", spec, { verdict: decision.verdict });
      return { status: "refused", reason: `verdict is "${decision.verdict}", not autonomous-merge`, needsHuman: false };
    }
    // GATE 2: the kill switch pauses the whole automated path (deny-by-default).
    if (this.deps.killSwitchEngaged?.()) {
      this.audit("auto_merge.refused", spec, { reason: "kill-switch" });
      return { status: "refused", reason: "kill switch engaged — autonomous merge paused", needsHuman: false };
    }

    // Authority is consumed before even preflight: a caller-supplied "dryRun" is not assumed pure.
    if (!consumeVerifiedExecutionSubjectAuthority(
      executionSubjectAuthority, spec.projectDir, spec.expectedCandidateProjectManifestDigest,
    )) {
      this.audit("auto_merge.refused", spec, { reason: "missing-replayed-or-substituted-execution-subject-authority" });
      return { status: "refused", reason: "autonomous publication requires a fresh verifier-owned Firecracker execution-subject authority", needsHuman: false };
    }

    // PRE-MERGE re-validation against the live base (the base may have moved since the solve).
    const dry = await this.deps.port.dryRun(spec);
    if (!dry.clean || !dry.identity) {
      this.audit("auto_merge.abstained", spec, { reason: dry.reason ?? "would not apply cleanly" });
      return { status: "abstained", reason: dry.reason ?? "base moved — would not apply cleanly; re-solve", needsHuman: false };
    }

    // MERGE.
    this.audit("auto_merge.attempt", spec, {
      operationId: `auto-merge:${spec.issueId}:${dry.identity.candidateCommit}:${dry.identity.baseCommit}`,
      priorPublishedCommit: dry.identity.baseCommit,
      publicationTarget: this.deps.port.publicationTarget(spec),
      expectedMergedTree: dry.identity.expectedMergedTree,
      candidateCommit: dry.identity.candidateCommit,
      candidateProjectManifestDigest: dry.identity.candidateProjectManifestDigest,
    });
    if (!this.deps.spine.durableStorage()) {
      this.audit("auto_merge.refused", spec, { reason: "nondurable-pre-effect-journal" });
      return { status: "refused", reason: "autonomous merge requires an fsync-durable pre-effect journal", needsHuman: false };
    }
    try {
      await this.deps.spine.seal();
      const verified = this.deps.spine.verify();
      if (!verified.ok) throw new Error(verified.reason ?? "sealed chain verification failed");
    } catch (error) {
      return { status: "refused", reason: `pre-effect intent could not be durably sealed: ${(error as Error).message}`, needsHuman: false };
    }
    let outcome: MergeOutcome;
    let preparedAttempt: PublicationAttemptV1 | undefined;
    try {
      outcome = await this.deps.port.merge(spec, dry.identity, async (attempt) => {
        preparedAttempt = parsePublicationAttempt(attempt);
        return this.preparePublication(preparedAttempt);
      });
    } catch (e) {
      this.audit("auto_merge.failed", spec, { reason: (e as Error).message });
      return { status: "failed", reason: `merge threw: ${(e as Error).message}`, needsHuman: false };
    }
    if (outcome.uncertainPublication) {
      this.audit("auto_merge.publication_uncertain", spec, outcome.uncertainPublication);
      return {
        status: "uncertain",
        mergeId: outcome.mergeId || outcome.uncertainPublication.attemptedCommit,
        reason: `remote publication outcome is uncertain and must be reconciled without retry: ${outcome.uncertainPublication.reason}`,
        needsHuman: true,
      };
    }
    if (!outcome.merged || !outcome.identity) {
      if (outcome.compensatedPublicationAbsent && preparedAttempt) {
        try { await this.terminal(preparedAttempt, "reconciled-effect-absent", outcome.reason ?? "prepared publication was proven absent and locally compensated"); }
        catch (error) { return { status: "uncertain", mergeId: outcome.mergeId, reason: `publication was proven absent and compensated but its terminal could not be durably sealed: ${(error as Error).message}`, needsHuman: true }; }
      }
      this.audit("auto_merge.failed", spec, { mergeId: outcome.mergeId, rollbackFailed: outcome.rollbackFailed ?? false, reason: outcome.reason ?? "merge failed" });
      return {
        status: "failed",
        ...(outcome.mergeId ? { mergeId: outcome.mergeId } : {}),
        reason: outcome.reason ?? "merge failed",
        needsHuman: outcome.rollbackFailed === true,
      };
    }
    const attempt = makePublicationAttempt(spec, outcome.identity);
    const result = await this.finalizePublished(attempt);
    if (result.status === "uncertain") return result;
    try { await this.terminal(attempt, result.status === "merged" ? "effect-occurred-verified" : result.status, result.reason); }
    catch (error) { return { status: "uncertain", mergeId: outcome.mergeId, reason: `publication completed but its terminal could not be durably sealed: ${(error as Error).message}`, needsHuman: true }; }
    return result;
  }
}
