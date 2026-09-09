/**
 * Local-audit + OTLP export (Core Addition D) — make every gate decision observable.
 *
 * A pure, total function DERIVES a structured audit record from a gate decision (the eight barrier
 * verdicts + the route + the deciding reasons) and shapes it as an OTLP LogRecord. It is DERIVED, not
 * re-judged: the audit reflects the decision that was made; it never recomputes the gate. It is
 * LOCAL-FIRST: the record is written to a local append-only sink that works with no network; the real
 * OTLP collector/exporter endpoint is a SEAM (export is best-effort, a dropped export is itself
 * recorded, and audit NEVER blocks or alters a decision).
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - OTLP log data model: TimeUnixNano, SeverityNumber (smaller = less severe; INFO=9, WARN=13) +
 *    SeverityText, Body (AnyValue), Attributes (per-occurrence key-values), TraceId + SpanId (correlate
 *    the record to a trace), EventName (a named log record is an Event). OTel defines the data model
 *    locally and EXPORT to a collector is a separate pipeline stage — hence local-first + a collector SEAM.
 *  - Every authorization decision is observable: log allow/deny WITH the deciding reason (the security-
 *    audit rule). A hold is WARN severity and carries its reasons.
 *  - Tamper-evident audit vs observability: the spine is the integrity log (what happened, un-alterable);
 *    the OTLP stream is the telemetry (operator-facing, exportable). You want both — this derives the
 *    telemetry from the same decision and can also anchor a compact line in the spine.
 *
 * WHAT WOULD CHANGE IT: richer OTel semantic-convention attributes, or a resource/scope block, extend
 * the record; a real exporter upgrades best-effort export to delivered telemetry. Neither lets the audit
 * change a route — it observes only.
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

/** An optional best-effort OTLP exporter (the collector wire is the SEAM). */
export interface OtlpExporter {
  export(otlp: OtlpLogRecord): void; // may throw / be unavailable — caller must not let that block
}

/** DERIVE the audit record from the decision. Copies verbatim — does NOT re-run the gate. */
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
 * Emit the decision audit: derive → shape → write locally (always) → best-effort export (optional).
 * Never throws, never blocks, never alters the decision. A dropped export is recorded on the record.
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
    exportDropped = true; // no exporter wired yet (the collector SEAM) — local record stands
  }
  return { record, otlp, exportDropped };
}

/**
 * VERIFY-PROVENANCE — a composed, auditable verification-provenance record: the full trust story of a fix in ONE
 * serializable artifact. This is the software-layer "action evidence package" (arXiv 2608.00801) for a verification —
 * it answers "what verified this change, from which signals, and what did the gate decide?" (Zylos 2026). Like the rest
 * of this module it is DERIVED and REPORT-ONLY: it reflects verdicts already produced and NEVER recomputes, alters, or
 * weakens any gate. HONEST: a signal that was not computed is marked "not-assessed" — NEVER fabricated as a pass; the
 * summary reflects the WORST signal (a flaky / low-confidence / held result is never summarized as clean). Deterministic
 * + JSON-serializable (same inputs → same record) for third-party reconstruction (isimplifyme's four demands:
 * completeness, point-in-time, attribution, integrity). Cryptographic signing / tamper-evidence / hardware attestation
 * are NAMED SEAMS ("software attestation is necessary but not sufficient", arXiv 2608.00801). ZERO-DEP.
 */

export interface VerificationProvenanceInput {
  readonly subjectId: string;
  /** The hard, AUTHORITATIVE deterministic oracle result. undefined ⇒ not assessed (cannot attest). */
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

/** Compose the produced verdicts into ONE report-only provenance record. Pure — never mutates its inputs. */
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

  // OVERALL reflects the WORST signal (precedence: incomplete < failed < held < flagged < clean, worst wins).
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
 * PROVENANCE-SEAL — a tamper-EVIDENT integrity seal + hash-chain over the verification-provenance record (Level 2
 * "hash-chained" integrity; Auditable Agents, arXiv 2604.05485). A content hash over the record's CANONICAL form
 * (sorted keys — reusing spine `canonicalize`) binds its content; an optional `prevHash` chain link makes a sequence
 * append-only, so any edit to a sealed record — or a break/reorder in the chain — is detectable by re-hashing (the goal
 * is to make tampering DETECTABLE, not impossible; c-sharpcorner/VCT 2026).
 *
 * HONEST SCOPE: this is INTEGRITY / tamper-evidence — it detects EDITS. It is NOT authenticity: the hash does not prove
 * WHO wrote the record. Cryptographic SIGNING (an organisational key / Sigstore-grade attestation) and an external
 * tail-hash WITNESS/anchor are NAMED SEAMS ("substitute a signing key without altering the mechanism… not yet
 * implemented", arXiv 2606.26924). The seal never claims authenticity. Reuses the spine hash primitive; ZERO-DEP
 * (node:crypto is a builtin, the same one the spine hash-chain uses). Verification is TOTAL — a missing/malformed seal
 * or a hash mismatch always reports invalid/tampered, never silently valid.
 */

/**
 * The identity ATTESTING a sealed record — the agent/runtime that produced it (SEAL-ATTRIBUTION). Carries the agent id
 * (NEVER the secret token) + optional version + liveness. `liveness` is RECORDED honestly (a killed/unknown attester is
 * recorded as such, NEVER elevated to live). This is ATTRIBUTION, not non-repudiation: without a signature the attester
 * is a SELF-ASSERTED claim — binding it into the hash only prevents it being SILENTLY SWAPPED.
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
  /** The attesting agent identity (id + version + liveness), bound INTO the hash. undefined ⇒ unattributed. */
  readonly attester?: AttestingIdentity;
  /** Prior seal's hash (ZERO_HASH at genesis) — the chain link. */
  readonly prevHash: string;
  /** SHA-256 over canonicalize({ record, [attester], prevHash }) — the attester is covered when present. */
  readonly hash: string;
  /** HONEST label: integrity/tamper-evidence only — NOT authenticity. */
  readonly integrity: "tamper-evident";
  /** Never claims authorship — signing is a named seam. */
  readonly signed: false;
  /** HONEST: the attester is a SELF-ASSERTED claim (no signature) — attribution binding, NOT non-repudiation. */
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
 * SEAL-SIGNING — a pluggable signing PORT over the sealed hash, upgrading self-asserted attribution toward
 * non-repudiation when a key is present. Composes the existing BOM `Signer`/`stubSign` primitive: a DETACHED signature
 * over `seal.hash` (Sigstore/Red Hat 2026: sign the artifact HASH, store the signature detached). The signer is INJECTED,
 * never bundled — the DEFAULT seal stays unsigned/`signed:false`/self-asserted; a signature ADDS a guarantee, it does not
 * replace the deterministic hash.
 *
 * HONEST guarantee ladder (DevSecOps School 2026: "non-repudiation depends on key management"): the reference provider is
 * a KEYED HASH (shared secret) → `keyed-integrity` (a holder of the shared key produced it) — NOT true non-repudiation,
 * because both parties hold the secret. TRUE non-repudiation needs an ASYMMETRIC signer (private-sign / public-verify) or
 * keyless Sigstore/Fulcio-OIDC — those, plus a Rekor-style transparency-log + RFC-3161 timestamp, are NAMED SEAMS. The
 * signed seal records the provider's declared guarantee; it never overclaims. Verification is TOTAL: the seal must be
 * intact FIRST, then the signature must verify over `seal.hash` against a TRUSTED key. ZERO-DEP (node:crypto builtin).
 */

export type SealGuarantee = "keyed-integrity" | "non-repudiation";

/** A signing provider for seals: the underlying signer + its HONEST declared guarantee level. Injected, never bundled. */
export interface SealSigner {
  readonly signer: Signer;
  readonly guarantee: SealGuarantee;
}

/** The reference keyed-hash signer (reuses BOM `stubSign`). HONEST: shared-secret ⇒ `keyed-integrity`, NOT non-repudiation. */
export function keyedSealSigner(privateKey: string, keyid: string): SealSigner {
  return { signer: { sign: (digest: string): Signature => stubSign(privateKey, keyid, digest) }, guarantee: "keyed-integrity" };
}

export interface SignedSeal {
  readonly seal: SealedProvenance;
  /** Detached signature over `seal.hash` (reuses BOM `Signature` = { keyid, sig }). */
  readonly signature: Signature;
  /** The provider's declared guarantee — never overclaimed (keyed reference = "keyed-integrity"). */
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
 * Verify a signed seal. TOTAL + fail-safe: the seal must itself be intact (tamper-evidence) FIRST, THEN the signature
 * must verify over `seal.hash` against a TRUSTED key. A bad/absent/untrusted signature never upgrades trust.
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
 * SEAL-WITNESS — anchor a sealed (optionally signed) provenance record into the spine's existing append-only,
 * hash-chained log. Staging a witness event carrying the seal hash (+ signature keyid, if signed) lets the spine's
 * tamper-evident chain TIMESTAMP + ORDER the seal: an entry attests "this seal existed by this point" (Sigstore 2026:
 * an append-only entry "attests that a piece of data existed prior to a certain time"). An inclusion check confirms the
 * seal is a committed leaf in the chain AND that the chain still verifies (a later re-date breaks the chain).
 *
 * HONEST SCOPE: this is a LOCAL-SPINE ordering/timestamp witness — backdating-resistance WITHIN the local chain. It is
 * NOT a public/trustless transparency log: it requires trusting the local operator and is vulnerable to a split-view
 * without EXTERNAL third-party witnesses (su3.io 2026). An external witness / Rekor-style mirror is the NAMED SEAM —
 * the spine's own `makeWitness`/`verifyAgainstWitness` (published to an independent sink) is that seam's primitive. The
 * witness records EXISTENCE-BY-A-POINT; it does NOT re-prove the signature (that is `verifySignedSeal`). ZERO-DEP.
 */

export interface SealWitness {
  readonly sealHash: string;
  readonly keyid?: string;
  readonly eventId: string;
  /** HONEST: local spine ordering/timestamp — NOT a public transparency log. */
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
 * Check inclusion: the seal hash is a COMMITTED witness leaf in the spine's tamper-evident chain AND the chain verifies.
 * Absent ⇒ un-witnessed (never assumed present). Only committed (sealed) events count — a merely-pending stage is not yet
 * chain-protected.
 */
export function checkSealInclusion(spine: Spine, sealHash: string): InclusionVerdict {
  const committed = spine.replay();
  const hit = committed.find((e) => e.payload["event"] === "seal_witness" && e.payload["sealHash"] === sealHash);
  if (hit === undefined) return { witnessed: false, reason: "seal hash not found in the committed spine chain — un-witnessed" };
  const chainIntact = spine.verify().ok; // a later edit/re-date to the chain is detectable here
  return { witnessed: true, witnessedAt: hit.ts, eventId: hit.id, chainIntact };
}

/**
 * WITNESS-MIRROR — reconcile the local seal-witness chain against an INDEPENDENT external sink, closing (partway) the
 * split-view seam. It reconciles the current local chain against the PRIOR witness the external sink published, then
 * advances the sink only if they agree. A silently-rewritten or truncated local chain diverges from the external record
 * and is reported TAMPER (equivocation detection needs an observer "other than the untrusted server" — arXiv 2011.04551).
 *
 * HONEST SCOPE: this raises the bar from local-only to EXTERNALLY-ANCHORED — a SINGLE external witness proves the log is
 * append-only and catches a rewrite/truncation (transparency.dev 2026). But it is ONE witness: full split-view defense
 * needs an M-of-N witness QUORUM (≥2f+1 cosigning; Jovanovic; Sigstore/ArmoredWitness) — that quorum, and a public
 * transparency network, are NAMED SEAMS. The mirror DETECTS divergence; it does not by itself prove which view is
 * canonical without the quorum. Reuses the spine's emitWitness/reconcileAgainst; no new witness protocol. ZERO-DEP.
 */

export interface SealReconcileResult {
  /** true iff the local chain agrees with (or is an authorized restore of) the external record. */
  readonly reconciled: boolean;
  readonly status: "agreed" | "authorized-restore" | "diverged" | "unreconciled" | "unreadable";
  /** HONEST: a single external observer — NOT an M-of-N public transparency network (the quorum is a named seam). */
  readonly witnessScope: "single-external";
  readonly reason: string;
}

/**
 * Reconcile + advance. Compares the current local chain to the sink's PRIOR published witness; on agreement (or an
 * authorized restore) it advances the sink; on divergence it does NOT advance (preserving the good record). With no
 * prior external record it bootstraps and reports `unreconciled` — never assumed to agree.
 */
export function reconcileSealWitness(spine: Spine, sink: WitnessSink, opts: { readOnly?: boolean } = {}): SealReconcileResult {
  // readOnly (L20a boot reconcile): DETECT only — do NOT advance the sink. Without it, publishing a witness
  // on every clean boot grows the file unboundedly and re-parses it O(n) per boot; the sink is advanced by
  // seal()/checkpoint() (L4) instead. == null also treats a `null` witness line as "no prior witness".
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
 * TRUST-REPORT — a composed, honest end-to-end assurance report over the evidence chain. It walks whatever evidence is
 * actually present for a fix (deterministic verdict → seal → attestation → signature → spine witness → external reconcile)
 * and reports ONE overall ASSURANCE LEVEL bounded by the WEAKEST present layer ("posture is only as good as its weakest
 * dependency" — NeuralTrust 2026; trust is non-compositional — iternal.ai 2026). A missing/failed layer CAPS the level
 * and is listed as a GAP; present-but-weak guarantees (keyed-integrity, single-external) are named as upgrade SEAMS and
 * never overclaimed (evidence-present ≠ guarantee-provided — Help Net 2026). REPORT-ONLY: it composes existing verdicts,
 * changes no gate, and is deterministic. ZERO-DEP.
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
  /** Missing/failed ladder layers that CAP the level (weakest-link). Empty for a complete chain. */
  readonly gaps: readonly string[];
  /** Named upgrade seams beyond what's achieved — the honest horizon (never claimed as satisfied). */
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

  // Weakest-link: the achieved level is the highest UNBROKEN rung from the base.
  let idx = 0;
  for (const r of rungs) { if (r.ok) idx++; else break; }
  const level = LEVELS[idx]!;

  const layers = rungs.map((r) => ({ name: r.name, present: r.ok, note: r.ok ? "present + verified" : "absent / not verified" }));
  const gaps = idx < rungs.length ? [`${rungs[idx]!.name}: ${rungs[idx]!.gap} (caps assurance at ${level})`] : [];

  // Upgrade seams — the honest horizon. Present-but-weak guarantees are named, never counted as stronger.
  const seams: string[] = [];
  if (e.signatureValid === true && e.signatureGuarantee === "keyed-integrity") {
    seams.push("signature is keyed-integrity (shared secret) — asymmetric/keyless (Sigstore) signing would provide true non-repudiation");
  }
  if (e.reconciled === true && (e.reconcileScope ?? "single-external") === "single-external") {
    seams.push("single external witness — an M-of-N witness quorum would provide split-view resistance");
  }
  // top horizons always beyond L6 with zero-dep reference providers
  seams.push("hardware key custody (TEE/HSM) for signing", "a public transparency-log mirror (Rekor-style)");

  const summary = `assurance ${level} (${idx}/6 layers)${gaps.length ? ` — capped by: ${gaps[0]}` : " — full chain present"}; ${seams.length} upgrade seam(s) named`;
  return { level, levelIndex: idx, layers, gaps, seams, summary };
}

/**
 * ASSURANCE-SURFACE — render a trust report into ONE concise, honest operator-facing line for the decision point.
 * "Actionable trust" must be tied to the DECISION, not the raw level (arXiv 2601.04486 2026: "no such thing as
 * actionable trust unless it is linked to the effects of escalation versus closure") — so the line states the assurance
 * level, the single capping gap (the "why"), AND whether the gate is proceeding or holding. It is GLANCEABLE (one line,
 * no jargon dump — OAD 2026) and HONEST: the level is stated as-is, NEVER rounded up or softened into reassurance
 * (miscalibrated signals enhance bias — arXiv 2601.04486). PRESENTATION-ONLY: it renders the existing report + gate
 * route, computes no verdict, mutates nothing, and is deterministic. ZERO-DEP.
 */
export function assuranceHeadline(report: TrustReport, gateRoute?: "auto-proceed" | "human-hold"): string {
  const gate = gateRoute === "human-hold" ? " · HELD for review" : gateRoute === "auto-proceed" ? " · proceeding" : "";
  // the single capping gap is the "why" of the level; a complete chain says so plainly.
  const cap = report.gaps.length > 0 ? report.gaps[0]! : "full chain present";
  return `assurance ${report.level} (${report.levelIndex}/6)${gate} — ${cap}`;
}

/**
 * ASSURANCE-BUDGET — fold the trust report's assurance level into a cost-aware routing advisory. Spending more on the
 * next (costlier) routing/escalation step is worthwhile only when it would RAISE assurance or resolve the capping gap —
 * "knowing which cheap model will succeed is worth more than additional blind budget… the value of a better SIGNAL, not
 * more sampling" (arXiv 2607.08665 2026). Paying more for the same-or-lower assurance is flagged low-value. It composes
 * the existing trustReport (assurance now vs if-escalated) with the existing cost signal (a USD number from the cost
 * router) — NO new router.
 *
 * SAFE — the advisory never suppresses a NEEDED escalation to save cost: an IRREVERSIBLE (high-consequence) action
 * escalates regardless of cost or assurance gain ("never downgrade a model mid-task" — Taskade 2026). REPORT-ONLY: it
 * advises, it does not override the deterministic floor or the consequence gate (`overridesGate: false`). HONEST: it
 * weighs ASSURANCE — a signal that is "weak, gameable" (arXiv 2607.08665) — NOT correctness; a low-value flag never means
 * the cheaper answer is right (`basis: "assurance-not-correctness"`). Only real trustReport signals are used; never
 * fabricated. Deterministic. ZERO-DEP.
 */

export interface AssuranceBudgetInput {
  /** Assurance at the current (cheaper) step. */
  readonly current: TrustReport;
  /** Projected assurance IF the costlier next step is taken. */
  readonly ifEscalated: TrustReport;
  /** The marginal cost of escalating (USD per task; from the existing cost router). */
  readonly escalationCost: number;
  /** Reversibility/consequence of the action (reused from the router). */
  readonly consequence: ConsequenceClass;
}

export type BudgetAdvice = "escalate-worthwhile" | "escalate-low-value" | "escalate-required-by-consequence";

export interface AssuranceBudgetAdvisory {
  readonly advice: BudgetAdvice;
  /** ifEscalated.levelIndex − current.levelIndex — the REAL assurance delta (never fabricated). */
  readonly assuranceGain: number;
  readonly resolvesCappingGap: boolean;
  readonly escalationCost: number;
  /** HONEST: advice-only — never overrides the deterministic floor or the consequence gate. */
  readonly overridesGate: false;
  /** HONEST: weighs ASSURANCE (a signal), NOT correctness. */
  readonly basis: "assurance-not-correctness";
  readonly reason: string;
}

export function assuranceBudgetAdvice(input: AssuranceBudgetInput): AssuranceBudgetAdvisory {
  const assuranceGain = input.ifEscalated.levelIndex - input.current.levelIndex;
  const resolvesCappingGap = input.current.gaps.length > 0 && input.ifEscalated.levelIndex > input.current.levelIndex;

  let advice: BudgetAdvice;
  let reason: string;
  // SAFE — consequence FIRST: an irreversible action escalates regardless of cost or assurance gain. Cost never vetoes it.
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
