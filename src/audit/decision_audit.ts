/**
 * Derive local audit records and OTLP log records from existing gate decisions.
 * The audit copies the route, barrier results and reasons without recomputing the gate. A local sink
 * receives the record first; optional synchronous export failures are reported through exportDropped.
 * The injected sink and exporter control their own latency, and a local sink error propagates.
 *
 * OTLP severity follows the OpenTelemetry log model: INFO=9 for proceeding and WARN=13 for a hold.
 * Provenance records, content hashes and witness helpers below retain the reported evidence and
 * its trust limits. Independent storage and signing-key custody require separate configuration.
 */

import type { GateInputs, GateRoute } from "../gate/composed_gate.js";
import type { StableResolutionVerdict } from "../eval/swebench_task.js";
import type { CrossFamilyVerdict } from "../review/heterogeneous.js";
import type { VerificationConfidence } from "../routing/verification_confidence.js";
import { createHash } from "node:crypto";
import { canonicalize } from "../spine/event.js";
import { ZERO_HASH } from "../spine/hashchain.js";
import { stubSign, type Signature, type Signer } from "../bom/bom_signing.js";
import type { Spine } from "../spine/spine.js";
import type { WitnessSink } from "../spine/witness_sink.js";
import type { ConsequenceClass } from "../routing/uncertainty_router.js";

/** The structured audit record — a faithful, derived copy of the decision. */
export interface DecisionAuditRecord {
  readonly timestamp: number;
  readonly route: "auto-proceed" | "human-hold";
  readonly reasons: readonly string[];
  /** The eight barrier verdicts exactly as observed at the gate. */
  readonly barriers: {
    readonly floor?: string | undefined;
    readonly budget?: string | undefined;
    readonly actionTier?: string | undefined;
    readonly ownerPresent?: boolean | undefined;
    readonly provenance?: string | undefined;
    readonly twin?: string | undefined;
    readonly bomVerified?: boolean | undefined;
    readonly identityLive?: boolean | undefined;
  };
}

/** The OTLP LogRecord shape (subset of the OTel log data model). */
export interface OtlpLogRecord {
  readonly timeUnixNano: number;
  readonly severityNumber: number;
  readonly severityText: "INFO" | "WARN";
  readonly eventName: string;
  readonly body: string;
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
  readonly traceId: string;
  readonly spanId: string;
}

/** A local-first append-only audit sink. */
export interface AuditSink {
  write(record: DecisionAuditRecord, otlp: OtlpLogRecord): void;
}

/** In-memory sink (default; local-first, works offline). */
export class InMemoryAuditSink implements AuditSink {
  readonly records: Array<{ record: DecisionAuditRecord; otlp: OtlpLogRecord }> = [];
  write(record: DecisionAuditRecord, otlp: OtlpLogRecord): void {
    this.records.push({ record, otlp });
  }
}

/** Optional synchronous OTLP exporter; the caller records export failures. */
export interface OtlpExporter {
  export(otlp: OtlpLogRecord): void; // may throw / be unavailable — caller must not let that block
}

/** Copy the observed route, reasons and barrier inputs into an audit record. */
export function auditDecision(inputs: GateInputs, decision: GateRoute, now = Date.now()): DecisionAuditRecord {
  return {
    timestamp: now,
    route: decision.route, // the route that was decided — reflected, not recomputed
    reasons: [...decision.reasons],
    barriers: {
      floor: inputs.floor,
      budget: inputs.budget,
      actionTier: inputs.actionTier,
      ownerPresent: inputs.ownerPresent,
      provenance: inputs.provenance,
      twin: inputs.twin,
      bomVerified: inputs.bomVerified,
      identityLive: inputs.identityLive,
    },
  };
}

const SEV_INFO = 9;
const SEV_WARN = 13;

function hex(n: number): string {
  // deterministic id from timestamp + route (in-env; a real tracer supplies W3C ids).
  return Math.abs(Math.floor(n)).toString(16).padStart(16, "0").slice(0, 16);
}

/** Shape the record as an OTLP LogRecord. A human-hold is WARN; auto-proceed is INFO. */
export function toOtlp(record: DecisionAuditRecord, ids?: { traceId?: string; spanId?: string }): OtlpLogRecord {
  const hold = record.route === "human-hold";
  const attributes: Record<string, string | number | boolean> = {
    "keep.gate.route": record.route,
    "keep.gate.reasons": record.reasons.join(","),
    "keep.gate.reason_count": record.reasons.length,
  };
  for (const [k, v] of Object.entries(record.barriers)) {
    if (v !== undefined) attributes[`keep.barrier.${k}`] = v;
  }
  return {
    timeUnixNano: record.timestamp * 1_000_000,
    severityNumber: hold ? SEV_WARN : SEV_INFO,
    severityText: hold ? "WARN" : "INFO",
    eventName: "keep.gate.decision",
    body: hold ? `gate HELD: ${record.reasons.join(", ")}` : "gate auto-proceed",
    attributes,
    traceId: ids?.traceId ?? hex(record.timestamp).repeat(2).slice(0, 32),
    spanId: ids?.spanId ?? hex(record.timestamp + 1),
  };
}

export interface AuditOutcome {
  readonly record: DecisionAuditRecord;
  readonly otlp: OtlpLogRecord;
  /** True if a best-effort export was attempted and failed/absent (recorded, never blocks). */
  readonly exportDropped: boolean;
}

/**
 * Write a derived record to the local sink, then attempt optional export.
 * Exporter errors set exportDropped; local sink errors propagate. The decision itself is unchanged.
 */
export function emitDecisionAudit(
  inputs: GateInputs,
  decision: GateRoute,
  sink: AuditSink,
  exporter?: OtlpExporter,
  now = Date.now(),
): AuditOutcome {
  const record = auditDecision(inputs, decision, now);
  const otlp = toOtlp(record);
  sink.write(record, otlp); // local-first: always written
  let exportDropped = false;
  if (exporter) {
    try {
      exporter.export(otlp);
    } catch {
      exportDropped = true; // the gap is recorded; the decision is NOT blocked
    }
  } else {
    exportDropped = true; // The local record is retained when no exporter is configured.
  }
  return { record, otlp, exportDropped };
}

/**
 * Combine existing verification verdicts into a serializable record. Uncomputed signals remain
 * not-assessed. The overall result follows the explicit precedence for missing deterministic checks,
 * failure, human hold and flagged evidence. This function reports those inputs without changing gates.
 */

export interface VerificationProvenanceInput {
  readonly subjectId: string;
  /** Deterministic oracle result; undefined means not assessed. */
  readonly deterministicPass?: boolean;
  readonly stable?: StableResolutionVerdict;
  readonly crossFamily?: CrossFamilyVerdict;
  readonly confidence?: VerificationConfidence;
  readonly gate?: GateRoute;
}

export type ProvenanceOverall = "clean" | "flagged" | "held" | "failed" | "incomplete";

export interface VerificationProvenance {
  readonly subjectId: string;
  readonly deterministic: "pass" | "fail" | "not-assessed";
  readonly stability: { readonly assessed: boolean; readonly stable?: boolean; readonly flaky?: boolean; readonly flakyTests?: readonly string[]; readonly runs?: number };
  readonly crossFamily: { readonly assessed: boolean; readonly accepted?: boolean; readonly independent?: boolean; readonly authorFamily?: string; readonly verifierFamily?: string; readonly agreement?: boolean };
  readonly confidence: { readonly assessed: boolean; readonly score?: number; readonly band?: string; readonly contributions?: readonly string[] };
  readonly gate: { readonly assessed: boolean; readonly route?: string; readonly reasons?: readonly string[] };
  readonly overall: ProvenanceOverall;
  readonly summary: string;
}

/** Combine supplied verdicts without mutating the inputs or changing their decisions. */
export function verificationProvenance(input: VerificationProvenanceInput): VerificationProvenance {
  const deterministic: "pass" | "fail" | "not-assessed" =
    input.deterministicPass === undefined ? "not-assessed" : input.deterministicPass ? "pass" : "fail";

  const stability: VerificationProvenance["stability"] = input.stable === undefined
    ? { assessed: false }
    : { assessed: true, stable: !input.stable.flaky && input.stable.resolved, flaky: input.stable.flaky, flakyTests: input.stable.flakyTests, runs: input.stable.runs };

  const crossFamily: VerificationProvenance["crossFamily"] = input.crossFamily === undefined
    ? { assessed: false }
    : { assessed: true, accepted: input.crossFamily.accepted, independent: input.crossFamily.independent, authorFamily: input.crossFamily.authorFamily,
        ...(input.crossFamily.verifierFamily !== undefined ? { verifierFamily: input.crossFamily.verifierFamily } : {}),
        ...(input.crossFamily.agreement !== undefined ? { agreement: input.crossFamily.agreement } : {}) };

  const confidence: VerificationProvenance["confidence"] = input.confidence === undefined
    ? { assessed: false }
    : { assessed: true, score: input.confidence.score, band: input.confidence.band, contributions: input.confidence.reasons };

  const gate: VerificationProvenance["gate"] = input.gate === undefined
    ? { assessed: false }
    : { assessed: true, route: input.gate.route, reasons: input.gate.reasons };

  // Precedence: unassessed deterministic check, failure, human hold, flagged evidence, then clean.
  let overall: ProvenanceOverall;
  if (deterministic === "not-assessed") overall = "incomplete";
  else if (deterministic === "fail") overall = "failed";
  else if (gate.assessed && gate.route === "human-hold") overall = "held";
  else if ((stability.assessed && stability.flaky === true) || (confidence.assessed && confidence.band === "low") || (crossFamily.assessed && crossFamily.accepted === false)) overall = "flagged";
  else overall = "clean";

  const parts: string[] = [`deterministic ${deterministic}`];
  if (stability.assessed) parts.push(stability.flaky ? `FLAKY [${(stability.flakyTests ?? []).join(", ")}]` : `stable/${stability.runs}`);
  if (crossFamily.assessed) parts.push(crossFamily.independent ? `cross-family ${crossFamily.authorFamily}⟷${crossFamily.verifierFamily ?? "?"} ${crossFamily.accepted ? "agreed" : "declined"}` : `verifier not-independent`);
  if (confidence.assessed) parts.push(`confidence ${confidence.band}(${(confidence.score ?? 0).toFixed(2)})`);
  if (gate.assessed) parts.push(`gate ${gate.route}`);
  const summary = `verification provenance for ${input.subjectId} — ${overall.toUpperCase()}: ${parts.join("; ")}`;

  return { subjectId: input.subjectId, deterministic, stability, crossFamily, confidence, gate, overall, summary };
}

/**
 * Hash a provenance record's canonical form with an optional link to the preceding seal.
 * Verification detects content or chain changes relative to the retained hashes. A producer able
 * to replace the records and hashes can construct another valid chain. Authentication and independent
 * history checks require the separate signing and witness mechanisms.
 */

/**
 * Reported identity of the runtime that produced a record. It contains an identifier, optional
 * version and liveness state, with no secret token. Binding this claim into a hash detects changes
 * relative to that hash; authenticated attribution requires separate evidence.
 */
export interface AttestingIdentity {
  readonly agentId: string;
  readonly version?: string;
  readonly liveness: "live" | "killed" | "unknown";
}

/** Derive an attester from the identity layer — reuses the registry's kill/revoke state. No registry ⇒ "unknown" (never assumed live). Never includes the secret token. */
export function attesterFrom(agentId: string, registry: { isKilled(id: string): boolean } | undefined, version?: string): AttestingIdentity {
  const liveness: AttestingIdentity["liveness"] = registry === undefined ? "unknown" : registry.isKilled(agentId) ? "killed" : "live";
  return { agentId, liveness, ...(version !== undefined ? { version } : {}) };
}

export interface SealedProvenance {
  readonly record: VerificationProvenance;
  /** Reported agent identity bound into the hash; omitted when unattributed. */
  readonly attester?: AttestingIdentity;
  /** Prior seal's hash (ZERO_HASH at genesis) — the chain link. */
  readonly prevHash: string;
  /** SHA-256 over canonicalize({ record, [attester], prevHash }) — the attester is covered when present. */
  readonly hash: string;
  /** Content-integrity classification; signer identity is checked separately. */
  readonly integrity: "tamper-evident";
  /** The base seal is unsigned; signSeal adds a separate signature record. */
  readonly signed: false;
  /** The base seal retains the producer's reported identity as a self-asserted claim. */
  readonly attribution: "self-asserted";
}

function sealHash(record: VerificationProvenance, prevHash: string, attester?: AttestingIdentity): string {
  const body = attester === undefined ? { record, prevHash } : { record, attester, prevHash };
  return createHash("sha256").update(canonicalize(body), "utf8").digest("hex");
}

/** Seal a provenance record: content hash over its canonical form + a chain link to the prior seal (ZERO_HASH genesis). */
export function sealProvenance(record: VerificationProvenance, prevHash: string = ZERO_HASH, attester?: AttestingIdentity): SealedProvenance {
  return { record, ...(attester !== undefined ? { attester } : {}), prevHash, hash: sealHash(record, prevHash, attester), integrity: "tamper-evident", signed: false, attribution: "self-asserted" };
}

export type SealVerdict = { readonly valid: true } | { readonly valid: false; readonly reason: string };

/** Total verification: recompute the hash; a mismatch or malformed seal reports tampered/invalid — never silently valid. */
export function verifyProvenanceSeal(sealed: SealedProvenance | null | undefined): SealVerdict {
  if (!sealed || typeof sealed !== "object") return { valid: false, reason: "missing or malformed seal" };
  if (typeof sealed.hash !== "string" || sealed.hash.length !== 64) return { valid: false, reason: "malformed hash" };
  if (typeof sealed.prevHash !== "string") return { valid: false, reason: "malformed prevHash" };
  if (sealed.record === null || typeof sealed.record !== "object") return { valid: false, reason: "malformed record" };
  // A present attester must be well-formed (total verification — an attributed seal cannot be silently unattributed/invalid).
  if (sealed.attester !== undefined) {
    const a = sealed.attester as AttestingIdentity;
    if (a === null || typeof a !== "object" || typeof a.agentId !== "string" || (a.liveness !== "live" && a.liveness !== "killed" && a.liveness !== "unknown")) {
      return { valid: false, reason: "malformed attester" };
    }
  }
  const recomputed = sealHash(sealed.record, sealed.prevHash, sealed.attester);
  if (recomputed !== sealed.hash) return { valid: false, reason: "hash mismatch — record altered after sealing (TAMPERED)" };
  return { valid: true };
}

/** Chain a sequence: each record sealed with the prior seal's hash (genesis = ZERO_HASH). Append-only + tamper-evident. */
export function chainProvenance(records: readonly VerificationProvenance[]): SealedProvenance[] {
  const out: SealedProvenance[] = [];
  let prev = ZERO_HASH;
  for (const r of records) { const s = sealProvenance(r, prev); out.push(s); prev = s.hash; }
  return out;
}

export type ChainVerdict = { readonly valid: true } | { readonly valid: false; readonly reason: string; readonly index: number };

/** Verify a chain: every seal valid AND each prevHash links to the prior hash. Detects any edit, break, or reorder. */
export function verifyProvenanceChain(chain: readonly SealedProvenance[]): ChainVerdict {
  let prev = ZERO_HASH;
  for (let i = 0; i < chain.length; i++) {
    const s = chain[i]!;
    const v = verifyProvenanceSeal(s);
    if (!v.valid) return { valid: false, reason: v.reason, index: i };
    if (s.prevHash !== prev) return { valid: false, reason: "chain break: prevHash does not link to the prior block", index: i };
    prev = s.hash;
  }
  return { valid: true };
}

/**
 * Attach a signature to a sealed content hash, leaving the base seal unchanged.
 * The reference signer and verifier use the BOM keyed-hash primitive and share a secret. The
 * returned guarantee field carries the provider's declaration; verification does not establish
 * asymmetric key separation or key custody. Those require a matching production implementation.
 */

export type SealGuarantee = "keyed-integrity" | "non-repudiation";

/** Injected signer and its declared guarantee level. */
export interface SealSigner {
  readonly signer: Signer;
  readonly guarantee: SealGuarantee;
}

/** Shared-secret reference signer reporting keyed-integrity. */
export function keyedSealSigner(privateKey: string, keyid: string): SealSigner {
  return { signer: { sign: (digest: string): Signature => stubSign(privateKey, keyid, digest) }, guarantee: "keyed-integrity" };
}

export interface SignedSeal {
  readonly seal: SealedProvenance;
  /** Detached signature over `seal.hash` (reuses BOM `Signature` = { keyid, sig }). */
  readonly signature: Signature;
  /** Provider-declared guarantee; the reference signer reports keyed-integrity. */
  readonly guarantee: SealGuarantee;
}

/** Sign a seal: a DETACHED signature over its content hash. The seal itself is unchanged (stays `signed:false`). */
export function signSeal(seal: SealedProvenance, signer: SealSigner): SignedSeal {
  return { seal, signature: signer.signer.sign(seal.hash), guarantee: signer.guarantee };
}

export type SealSignatureVerdict =
  | { readonly valid: true; readonly guarantee: SealGuarantee; readonly keyid: string }
  | { readonly valid: false; readonly reason: string };

/**
 * Check the content seal, then compare its signature with the configured trusted-key result.
 * The reference verification uses stubSign; a valid result retains the supplied guarantee label.
 */
export function verifySignedSeal(signed: SignedSeal | null | undefined, trustedKeys: ReadonlyMap<string, string>): SealSignatureVerdict {
  if (!signed || typeof signed !== "object") return { valid: false, reason: "missing signed seal" };
  const sv = verifyProvenanceSeal(signed.seal);
  if (!sv.valid) return { valid: false, reason: `seal invalid: ${sv.reason}` };
  const sig = signed.signature;
  if (!sig || typeof sig !== "object" || typeof sig.sig !== "string" || typeof sig.keyid !== "string") return { valid: false, reason: "malformed signature" };
  const key = trustedKeys.get(sig.keyid);
  if (key === undefined) return { valid: false, reason: "untrusted key — signature does not chain to a trusted signer" };
  const expected = stubSign(key, sig.keyid, signed.seal.hash).sig;
  if (sig.sig !== expected) return { valid: false, reason: "signature does not verify over the seal hash (TAMPERED or wrong key)" };
  return { valid: true, guarantee: signed.guarantee, keyid: sig.keyid };
}

/**
 * Record a seal hash and optional key identifier in the local spine chain. Once sealed, the event
 * supplies local ordering and a recorded timestamp. Its integrity depends on the retained chain and
 * trusted operator; independent observers are needed to detect conflicting views. Signature
 * verification remains the responsibility of verifySignedSeal.
 */

export interface SealWitness {
  readonly sealHash: string;
  readonly keyid?: string;
  readonly eventId: string;
  /** Ordering and timestamp recorded by the local spine. */
  readonly scope: "local-spine";
}

/** Stage a witness event for a sealed (or signed) record into the spine. Commit it by sealing the spine (leader seal). */
export function anchorSeal(spine: Spine, sealed: SealedProvenance | SignedSeal, actor = "keep-audit"): SealWitness {
  const seal = "seal" in sealed ? sealed.seal : sealed;
  const keyid = "signature" in sealed ? sealed.signature.keyid : undefined;
  const eventId = spine.stage({
    type: "identity.action",
    actor,
    payload: { event: "seal_witness", sealHash: seal.hash, ...(keyid !== undefined ? { keyid } : {}) },
  });
  return { sealHash: seal.hash, ...(keyid !== undefined ? { keyid } : {}), eventId, scope: "local-spine" };
}

export type InclusionVerdict =
  | { readonly witnessed: true; readonly witnessedAt: number; readonly eventId: string; readonly chainIntact: boolean }
  | { readonly witnessed: false; readonly reason: string };

/**
 * Find a committed witness event and report whether the current spine chain verifies.
 * Pending events do not count as committed witnesses.
 */
export function checkSealInclusion(spine: Spine, sealHash: string): InclusionVerdict {
  const committed = spine.replay();
  const hit = committed.find((e) => e.payload["event"] === "seal_witness" && e.payload["sealHash"] === sealHash);
  if (hit === undefined) return { witnessed: false, reason: "seal hash not found in the committed spine chain — un-witnessed" };
  const chainIntact = spine.verify().ok; // a later edit/re-date to the chain is detectable here
  return { witnessed: true, witnessedAt: hit.ts, eventId: hit.id, chainIntact };
}

/**
 * Compare the local chain with the external sink's previously retained root before advancing it.
 * Divergence preserves the prior reference and is reported to the caller. The result depends on
 * independent custody of that reference. A single observer does not supply a witness quorum or
 * resolve conflicting views across observers.
 */

export interface SealReconcileResult {
  /** true iff the local chain agrees with (or is an authorized restore of) the external record. */
  readonly reconciled: boolean;
  readonly status: "agreed" | "authorized-restore" | "diverged" | "unreconciled" | "unreadable";
  /** One external observer; quorum agreement is outside this result. */
  readonly witnessScope: "single-external";
  readonly reason: string;
}

/**
 * Reconcile + advance. Compares the current local chain to the sink's PRIOR published witness; on agreement (or an
 * authorized restore) it advances the sink; on divergence it does NOT advance (preserving the good record). With no
 * prior external record it bootstraps and reports `unreconciled` — never assumed to agree.
 */
export function reconcileSealWitness(spine: Spine, sink: WitnessSink, opts: { readOnly?: boolean } = {}): SealReconcileResult {
  // Read-only boot reconciliation leaves publication to seal()/checkpoint(), avoiding a new
  // record on each boot. A null or undefined prior value means no retained witness.
  const emit = (): void => { if (!opts.readOnly) spine.emitWitness(sink); };
  const prior = sink.latest();
  if (prior == null) {
    emit(); // bootstrap: publish the first head to the external sink (skipped in readOnly)
    return { reconciled: false, status: "unreconciled", witnessScope: "single-external", reason: "no prior external witness — un-reconciled (never assumed to agree)" };
  }
  const v = spine.reconcileAgainst(sink);
  switch (v.status) {
    case "consistent":
      emit(); // agreed → advance the external record (skipped in readOnly)
      return { reconciled: true, status: "agreed", witnessScope: "single-external", reason: "local chain agrees with the external witness (forward-consistent)" };
    case "authorized-restore":
      emit();
      return { reconciled: true, status: "authorized-restore", witnessScope: "single-external", reason: `authorized restore attested (restoredToSeq ${v.attestation.restoredToSeq})` };
    case "tamper":
      return { reconciled: false, status: "diverged", witnessScope: "single-external", reason: `TAMPER: local chain diverged from the external witness (${v.kind}: ${v.reason})` };
  }
}

/**
 * Report the supplied verification, seal, identity, signature and witness evidence.
 * The level stops at the first missing layer. These labels describe evidence coverage; the function
 * does not validate the supplied booleans or change an execution gate. Shared-key signatures and
 * single-observer reconciliation retain their narrower trust limits.
 */

export interface TrustEvidence {
  readonly deterministicPass?: boolean;
  readonly sealValid?: boolean;
  /** attester present AND liveness "live". */
  readonly attesterLive?: boolean;
  readonly signatureValid?: boolean;
  readonly signatureGuarantee?: SealGuarantee;
  /** spine inclusion confirmed AND chain intact. */
  readonly witnessed?: boolean;
  /** external reconcile agreed. */
  readonly reconciled?: boolean;
  readonly reconcileScope?: "single-external";
}

export type AssuranceLevel =
  | "L0-unverified" | "L1-verified" | "L2-tamper-evident" | "L3-attributed"
  | "L4-signed" | "L5-witnessed" | "L6-externally-anchored";

export interface TrustReport {
  readonly level: AssuranceLevel;
  readonly levelIndex: number; // 0..6
  readonly layers: readonly { readonly name: string; readonly present: boolean; readonly note: string }[];
  /** First missing or failed layer that limits the reported level. */
  readonly gaps: readonly string[];
  /** Additional capabilities beyond the reported evidence. */
  readonly seams: readonly string[];
  readonly summary: string;
}

const LEVELS: readonly AssuranceLevel[] = [
  "L0-unverified", "L1-verified", "L2-tamper-evident", "L3-attributed", "L4-signed", "L5-witnessed", "L6-externally-anchored",
];

export function trustReport(e: TrustEvidence): TrustReport {
  const rungs: readonly { readonly name: string; readonly ok: boolean; readonly gap: string }[] = [
    { name: "deterministic verification", ok: e.deterministicPass === true, gap: "deterministic oracle not passed" },
    { name: "tamper-evident seal", ok: e.sealValid === true, gap: "no verified tamper-evident seal" },
    { name: "attributed identity", ok: e.attesterLive === true, gap: "no live attesting identity" },
    { name: "verified signature", ok: e.signatureValid === true, gap: "no verified signature" },
    { name: "spine timestamp witness", ok: e.witnessed === true, gap: "not witnessed in the tamper-evident log" },
    { name: "external reconcile", ok: e.reconciled === true, gap: "not reconciled against an external witness" },
  ];

  // Stop the reported level at the first missing layer.
  let idx = 0;
  for (const r of rungs) { if (r.ok) idx++; else break; }
  const level = LEVELS[idx]!;

  const layers = rungs.map((r) => ({ name: r.name, present: r.ok, note: r.ok ? "present + verified" : "absent / not verified" }));
  const gaps = idx < rungs.length ? [`${rungs[idx]!.name}: ${rungs[idx]!.gap} (caps assurance at ${level})`] : [];

  // Retain the limits of shared-key signatures and single-observer reconciliation.
  const seams: string[] = [];
  if (e.signatureValid === true && e.signatureGuarantee === "keyed-integrity") {
    seams.push("signature is keyed-integrity (shared secret) — asymmetric/keyless (Sigstore) signing would provide true non-repudiation");
  }
  if (e.reconciled === true && (e.reconcileScope ?? "single-external") === "single-external") {
    seams.push("single external witness — an M-of-N witness quorum would provide split-view resistance");
  }
  // Protected key custody and public mirroring are outside the reference implementation.
  seams.push("hardware key custody (TEE/HSM) for signing", "a public transparency-log mirror (Rekor-style)");

  const summary = `assurance ${level} (${idx}/6 layers)${gaps.length ? ` — capped by: ${gaps[0]}` : " — full chain present"}; ${seams.length} upgrade seam(s) named`;
  return { level, levelIndex: idx, layers, gaps, seams, summary };
}

/**
 * Render the reported evidence level, its first gap and the supplied gate route on one line.
 * This presentation helper leaves both the report and the gate decision unchanged.
 */
export function assuranceHeadline(report: TrustReport, gateRoute?: "auto-proceed" | "human-hold"): string {
  const gate = gateRoute === "human-hold" ? " · HELD for review" : gateRoute === "auto-proceed" ? " · proceeding" : "";
  // the single capping gap is the "why" of the level; a complete chain says so plainly.
  const cap = report.gaps.length > 0 ? report.gaps[0]! : "full chain present";
  return `assurance ${report.level} (${report.levelIndex}/6)${gate} — ${cap}`;
}

/**
 * Compare current and projected evidence levels with the supplied marginal escalation cost.
 * Irreversible consequences always produce an escalation advisory. Other cases report whether
 * the projected step adds a level or resolves the current limiting gap. This advice measures
 * reported assurance rather than answer correctness and cannot override the execution gate.
 */

export interface AssuranceBudgetInput {
  /** Assurance at the current (cheaper) step. */
  readonly current: TrustReport;
  /** Projected assurance after the proposed escalation. */
  readonly ifEscalated: TrustReport;
  /** The marginal cost of escalating (USD per task; from the existing cost router). */
  readonly escalationCost: number;
  /** Reversibility/consequence of the action (reused from the router). */
  readonly consequence: ConsequenceClass;
}

export type BudgetAdvice = "escalate-worthwhile" | "escalate-low-value" | "escalate-required-by-consequence";

export interface AssuranceBudgetAdvisory {
  readonly advice: BudgetAdvice;
  /** Difference between projected and current reported levels. */
  readonly assuranceGain: number;
  readonly resolvesCappingGap: boolean;
  readonly escalationCost: number;
  /** Advisory only; execution gates retain authority. */
  readonly overridesGate: false;
  /** The advisory compares evidence levels rather than answer correctness. */
  readonly basis: "assurance-not-correctness";
  readonly reason: string;
}

export function assuranceBudgetAdvice(input: AssuranceBudgetInput): AssuranceBudgetAdvisory {
  const assuranceGain = input.ifEscalated.levelIndex - input.current.levelIndex;
  const resolvesCappingGap = input.current.gaps.length > 0 && input.ifEscalated.levelIndex > input.current.levelIndex;

  let advice: BudgetAdvice;
  let reason: string;
  // Irreversible consequences require escalation regardless of cost or projected gain.
  if (input.consequence === "irreversible") {
    advice = "escalate-required-by-consequence";
    reason = "irreversible consequence — escalation required regardless of cost or assurance gain; cost never suppresses it";
  } else if (assuranceGain > 0 || resolvesCappingGap) {
    advice = "escalate-worthwhile";
    reason = `escalation raises assurance by ${assuranceGain} level(s)${resolvesCappingGap ? " and resolves the capping gap" : ""} — the spend buys real assurance`;
  } else {
    advice = "escalate-low-value";
    reason = `escalation costs ${input.escalationCost} but does not raise assurance (gain ${assuranceGain}) — paying more for the same-or-lower assurance is low-value (assurance, not correctness)`;
  }

  return { advice, assuranceGain, resolvesCappingGap, escalationCost: input.escalationCost, overridesGate: false, basis: "assurance-not-correctness", reason };
}
