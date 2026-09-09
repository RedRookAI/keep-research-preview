import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, renameSync, unlinkSync, writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { StaleWorkAttemptError, type WorkAttemptFenceV1, type WorkAttemptReferenceV1 } from "../spine/work_attempt_authority_v1.js";

export const TICKET_CLOSURE_STEPS_V1 = [
  ["CLEAN_SOURCE", "SOURCE_IDENTITY", "PASS"],
  ["SOURCE_REMOTE", "AUTHENTICATED_GITHUB_READBACK", "REMOTE_SHA_MATCH"],
  ["EXACT_CANDIDATE_TESTS", "TEST_MATRIX", "PASS"],
  ["ONE_RETAINED_TARBALL", "ARTIFACT_BUILD", "PASS"],
  ["CLOSURE_MANIFEST", "PROVENANCE_BINDING", "PASS"],
  ["ARCHIVE_INSPECTION", "ARTIFACT_INSPECTION", "PASS"],
  ["BLANK_INSTALL", "ARTIFACT_ACCEPTANCE", "PASS"],
  ["INSTALLED_TRACKS", "INSTALLED_N1_ENTERPRISE", "PASS"],
  ["ARTIFACT_REMOTE", "AUTHENTICATED_GITHUB_UPLOAD", "REMOTE_IDENTITY_RECORDED"],
  ["REMOTE_MEMBER_READBACK", "AUTHENTICATED_GITHUB_READBACK", "REMOTE_IDENTITIES_MATCH"],
  ["RETRIEVED_ARTIFACT", "RETRIEVAL_ACCEPTANCE", "DIGEST_ARCHIVE_REINSTALL_RESTART_BOUNDED_SMOKE_PASS"],
  ["CLOSURE", "EXACT_IDENTITY_CONJUNCTION", "COMPLETE"],
] as const;

export type TicketClosureTrackV1 = "n1" | "enterprise";
export type TicketClosureStepV1 = typeof TICKET_CLOSURE_STEPS_V1[number];

export interface TicketClosureSubjectV1 {
  readonly project_id: string;
  readonly goal_id: string;
  readonly subgoal_id: string;
  readonly ticket_id: string;
  readonly approved_ticket_body_sha256: string;
  readonly approved_ticket_body_json: string;
  readonly attempt_fence_ticket_body_digest: string;
  readonly product_commit: string;
  readonly closure_profile_sha256: string;
  readonly lockfile_sha256: string;
  readonly build_recipe_sha256: string;
  readonly environment_identity_sha256: string;
  readonly retained_artifact_sha256: string;
  readonly n1_authority_digest: string;
  readonly enterprise_authority_digest: string;
  readonly source_remote: string;
  readonly artifact_remote: string;
  readonly attempts: Readonly<{ n1: WorkAttemptReferenceV1; enterprise: WorkAttemptReferenceV1 }>;
}

export interface TicketClosureTrackEvidenceV1 {
  readonly authority_digest: string;
  readonly artifact_sha256: string;
  readonly evidence_sha256: string;
  readonly direct: true;
  readonly result: "PASS";
}

export interface TicketClosureStepResultV1 {
  readonly result: string;
  readonly facts: Readonly<Record<string, unknown>>;
  readonly tracks?: Readonly<{ n1: TicketClosureTrackEvidenceV1; enterprise: TicketClosureTrackEvidenceV1 }>;
}

export interface TicketClosureRequestV1 {
  readonly completion_index: number;
  readonly step_id: TicketClosureStepV1[0];
  readonly operation_id: string;
  readonly subject_identity: string;
  readonly subject: TicketClosureSubjectV1;
}

export type TicketClosureObservationV1 =
  | { readonly status: "ABSENT" }
  | { readonly status: "UNKNOWN"; readonly reason: string }
  | { readonly status: "MATCH"; readonly operation_id: string; readonly value: TicketClosureStepResultV1 };

export interface TicketClosurePortV1 {
  observe(request: TicketClosureRequestV1): Promise<TicketClosureObservationV1>;
  execute(request: TicketClosureRequestV1): Promise<TicketClosureStepResultV1>;
}

export interface TicketClosureEvidenceV1 {
  readonly completion_index: number;
  readonly step_id: TicketClosureStepV1[0];
  readonly evidence_class: TicketClosureStepV1[1];
  readonly ticket_id: string;
  readonly subject_identity: string;
  readonly operation_id: string;
  readonly result: string;
  readonly facts: Readonly<Record<string, unknown>>;
  readonly tracks?: Readonly<{ n1: TicketClosureTrackEvidenceV1; enterprise: TicketClosureTrackEvidenceV1 }>;
  readonly prior_evidence_digest: string;
  readonly evidence_digest: string;
}

export interface TicketClosureJournalV1 {
  readonly schema: "keep.ticket-closure-journal/v1";
  readonly schema_version: 1;
  readonly track: TicketClosureTrackV1;
  readonly authority_digest: string;
  readonly attempt_reference: WorkAttemptReferenceV1;
  readonly subject: TicketClosureSubjectV1;
  readonly subject_identity: string;
  readonly first_failure: { readonly completion_index: number; readonly reason: string; readonly retryable: boolean; readonly attempts: number } | null;
  readonly active_failure: TicketClosureJournalV1["first_failure"];
  readonly evidence: readonly TicketClosureEvidenceV1[];
}

export interface TicketClosureStatusV1 {
  readonly state: "IN_PROGRESS" | "FAILED" | "EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP" | "COMPLETE";
  readonly completion_percentage: number;
  readonly completed_indices: readonly number[];
  readonly next_index: number | null;
  readonly first_failure: TicketClosureJournalV1["first_failure"];
}

export class InvalidTicketClosureError extends Error { override readonly name = "InvalidTicketClosureError"; }
export class TicketClosureEvidenceMismatchError extends Error { override readonly name = "TicketClosureEvidenceMismatchError"; }
export class TicketClosureEffectOutcomeUnresolvedError extends Error { override readonly name = "TicketClosureEffectOutcomeUnresolvedError"; }
export class TicketClosureFailedError extends Error { override readonly name = "TicketClosureFailedError"; }
export class TicketClosureRetryableError extends Error { override readonly name = "TicketClosureRetryableError"; }

const HEX = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TICKET = /^SG-[0-9]{2}-T[0-9]{3}[A-Z]?$/u;
const MAX_JOURNAL_BYTES = 16 * 1024 * 1024;
const ZERO_DIGEST = "0".repeat(64);

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (!plain(value)) throw new InvalidTicketClosureError("closure evidence contains a non-JSON value");
  const keys = Object.keys(value).sort();
  if (keys.some((key) => key === "__proto__" || key === "prototype" || key === "constructor")) throw new InvalidTicketClosureError("closure evidence contains an unsafe key");
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

const digest = (value: unknown): string => createHash("sha256").update(canonical(value)).digest("hex");
const clone = <T>(value: T): T => JSON.parse(canonical(value)) as T;
const boundedText = (value: unknown): value is string => typeof value === "string" && value.trim() === value && value.length > 0 && Buffer.byteLength(value, "utf8") <= 2048 && !value.includes("\0");

function validateSubject(value: unknown): TicketClosureSubjectV1 {
  const keys = ["approved_ticket_body_json", "approved_ticket_body_sha256", "artifact_remote", "attempt_fence_ticket_body_digest", "attempts", "build_recipe_sha256", "closure_profile_sha256", "enterprise_authority_digest", "environment_identity_sha256", "goal_id", "lockfile_sha256", "n1_authority_digest", "product_commit", "project_id", "retained_artifact_sha256", "source_remote", "subgoal_id", "ticket_id"];
  if (!plain(value) || Object.keys(value).sort().join(",") !== keys.join(",")) throw new InvalidTicketClosureError("closure subject has incomplete or unknown fields");
  const subject = value as unknown as TicketClosureSubjectV1;
  if (![subject.project_id, subject.goal_id, subject.subgoal_id, subject.source_remote, subject.artifact_remote].every(boundedText)
    || !TICKET.test(subject.ticket_id) || !COMMIT.test(subject.product_commit)
    || ![subject.approved_ticket_body_sha256, subject.attempt_fence_ticket_body_digest, subject.closure_profile_sha256, subject.lockfile_sha256, subject.build_recipe_sha256, subject.environment_identity_sha256, subject.retained_artifact_sha256, subject.n1_authority_digest, subject.enterprise_authority_digest].every((entry) => HEX.test(entry))
    || subject.n1_authority_digest === subject.enterprise_authority_digest || subject.source_remote === subject.artifact_remote
    || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+#[A-Za-z0-9_./-]+$/u.test(subject.source_remote)
    || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+#[A-Za-z0-9_./-]+$/u.test(subject.artifact_remote)
    || !plain(subject.attempts) || Object.keys(subject.attempts).sort().join(",") !== "enterprise,n1"
    || subject.attempts.n1.identity_digest === subject.attempts.enterprise.identity_digest) throw new InvalidTicketClosureError("closure subject identity is invalid or substitutes a track");
  if (typeof subject.approved_ticket_body_json !== "string" || Buffer.byteLength(subject.approved_ticket_body_json, "utf8") > 1024 * 1024) throw new InvalidTicketClosureError("approved ticket body bytes are absent or unbounded");
  let ticketBody: unknown; try { ticketBody = JSON.parse(subject.approved_ticket_body_json) as unknown; } catch { throw new InvalidTicketClosureError("approved ticket body bytes are invalid JSON"); }
  if (!plain(ticketBody) || ticketBody.id !== subject.ticket_id || JSON.stringify(ticketBody) !== subject.approved_ticket_body_json || createHash("sha256").update(subject.approved_ticket_body_json).digest("hex") !== subject.approved_ticket_body_sha256 || digest(ticketBody) !== subject.attempt_fence_ticket_body_digest) throw new InvalidTicketClosureError("ticket body dual digests do not derive from identical bytes");
  for (const track of ["n1", "enterprise"] as const) {
    const reference = subject.attempts[track];
    if (!plain(reference) || Object.keys(reference).sort().join(",") !== "attempt_id,generation,identity_digest" || !HEX.test(String(reference.identity_digest)) || !/^[0-9a-f]{32}$/u.test(String(reference.attempt_id)) || !Number.isSafeInteger(reference.generation) || reference.generation < 0) throw new InvalidTicketClosureError(`${track} initial attempt reference is invalid`);
  }
  return clone(subject);
}

function validateTrackEvidence(value: unknown, subject: TicketClosureSubjectV1): asserts value is NonNullable<TicketClosureStepResultV1["tracks"]> {
  if (!plain(value) || Object.keys(value).sort().join(",") !== "enterprise,n1") throw new TicketClosureEvidenceMismatchError("both direct track slots are required");
  for (const track of ["n1", "enterprise"] as const) {
    const row = value[track];
    if (!plain(row) || Object.keys(row).sort().join(",") !== "artifact_sha256,authority_digest,direct,evidence_sha256,result"
      || row.authority_digest !== subject[`${track}_authority_digest`] || row.artifact_sha256 !== subject.retained_artifact_sha256
      || !HEX.test(String(row.evidence_sha256)) || row.direct !== true || row.result !== "PASS") throw new TicketClosureEvidenceMismatchError(`${track} evidence is absent or substituted`);
  }
  const tracks = value as unknown as NonNullable<TicketClosureStepResultV1["tracks"]>;
  if (tracks.n1.evidence_sha256 === tracks.enterprise.evidence_sha256) throw new TicketClosureEvidenceMismatchError("direct track evidence is duplicated");
}

function validateResult(index: number, value: unknown, subject: TicketClosureSubjectV1): TicketClosureStepResultV1 {
  if (!plain(value) || !boundedText(value.result) || !plain(value.facts) || !Object.keys(value).every((key) => ["facts", "result", "tracks"].includes(key))) throw new TicketClosureEvidenceMismatchError("step result is malformed");
  const facts = value.facts;
  const required = TICKET_CLOSURE_STEPS_V1[index];
  if (required === undefined || value.result !== required[2]) throw new TicketClosureEvidenceMismatchError("step result does not match the fixed closure profile");
  if ([6, 7, 10].includes(index)) validateTrackEvidence(value.tracks, subject);
  else if (value.tracks !== undefined) throw new TicketClosureEvidenceMismatchError("track slots are not allowed for this step");
  if (index === 2) {
    const requiredFacts = ["focused_sha256", "portable_sha256", "full_native_sha256"];
    if (Object.keys(facts).sort().join(",") !== requiredFacts.sort().join(",") || !requiredFacts.every((key) => HEX.test(String(facts[key])))) throw new TicketClosureEvidenceMismatchError("test matrix evidence is incomplete");
  }
  const exactKeys = (keys: readonly string[]): void => { if (Object.keys(facts).sort().join(",") !== [...keys].sort().join(",")) throw new TicketClosureEvidenceMismatchError("step facts are incomplete or contain unknown fields"); };
  const shaFact = (key: string, expected?: string): void => { if (!HEX.test(String(facts[key])) || (expected !== undefined && facts[key] !== expected)) throw new TicketClosureEvidenceMismatchError(`${key} does not bind the closure subject`); };
  if (index === 0) { exactKeys(["clean", "source_commit"]); if (facts.clean !== true || facts.source_commit !== subject.product_commit) throw new TicketClosureEvidenceMismatchError("clean source fact does not bind the exact commit"); }
  if (index === 1) { exactKeys(["authenticated", "source_commit", "source_remote"]); if (facts.authenticated !== true || facts.source_commit !== subject.product_commit || facts.source_remote !== subject.source_remote) throw new TicketClosureEvidenceMismatchError("source readback does not bind the declared remote"); }
  if (index === 3) { exactKeys(["artifact_sha256"]); shaFact("artifact_sha256", subject.retained_artifact_sha256); }
  if (index === 4) { exactKeys(["manifest_sha256"]); shaFact("manifest_sha256"); }
  if (index === 5) { exactKeys(["archive_inspection_sha256", "artifact_sha256"]); shaFact("archive_inspection_sha256"); shaFact("artifact_sha256", subject.retained_artifact_sha256); }
  if (index === 6) { exactKeys(["artifact_sha256", "blank_install_sha256"]); shaFact("artifact_sha256", subject.retained_artifact_sha256); shaFact("blank_install_sha256"); }
  if (index === 7) { exactKeys(["artifact_sha256", "installed_tracks_sha256"]); shaFact("artifact_sha256", subject.retained_artifact_sha256); shaFact("installed_tracks_sha256"); }
  if (index === 8) { exactKeys(["artifact_remote", "artifact_sha256", "asset_id", "authenticated", "state"]); if (facts.artifact_remote !== subject.artifact_remote || facts.authenticated !== true || facts.state !== "uploaded" || !boundedText(facts.asset_id)) throw new TicketClosureEvidenceMismatchError("artifact upload identity is absent or unauthenticated"); shaFact("artifact_sha256", subject.retained_artifact_sha256); }
  if (index === 9) { exactKeys(["artifact_sha256", "authenticated_readback_sha256", "source_commit"]); if (facts.source_commit !== subject.product_commit) throw new TicketClosureEvidenceMismatchError("remote readback source commit is substituted"); shaFact("artifact_sha256", subject.retained_artifact_sha256); shaFact("authenticated_readback_sha256"); }
  if (index === 10) { exactKeys(["artifact_sha256", "retrieved_smoke_sha256"]); shaFact("artifact_sha256", subject.retained_artifact_sha256); shaFact("retrieved_smoke_sha256"); }
  if (index === 11) { exactKeys(["conjunction_sha256"]); shaFact("conjunction_sha256"); }
  const encoded = canonical(value);
  if (Buffer.byteLength(encoded, "utf8") > 1024 * 1024) throw new TicketClosureEvidenceMismatchError("step result exceeds size ceiling");
  return clone(value as unknown as TicketClosureStepResultV1);
}

function authorityDigest(fence: WorkAttemptFenceV1): string { return digest(fence.identity.authority); }
function referenceOf(fence: WorkAttemptFenceV1): WorkAttemptReferenceV1 {
  return { identity_digest: fence.reference.identity_digest, attempt_id: fence.reference.attempt_id, generation: fence.reference.generation };
}

export class TicketClosureSupervisorV1 {
  readonly #subject: TicketClosureSubjectV1;
  readonly #subjectIdentity: string;

  constructor(readonly directory: string, subject: TicketClosureSubjectV1) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory); const uid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o077) !== 0) throw new InvalidTicketClosureError("closure directory must be private and owner-controlled");
    this.#subject = validateSubject(subject);
    this.#subjectIdentity = digest(this.#subject);
  }

  load(track: TicketClosureTrackV1): TicketClosureJournalV1 {
    return this.#loadOptional(track) ?? this.#empty(track);
  }

  status(): TicketClosureStatusV1 {
    const n1 = this.load("n1"), enterprise = this.load("enterprise"), journals = [n1, enterprise];
    if (n1.evidence.length === enterprise.evidence.length && canonical(n1.evidence) !== canonical(enterprise.evidence)) throw new InvalidTicketClosureError("track journals contain different evidence");
    const firstFailure = journals.map((journal) => journal.first_failure).find((failure) => failure !== null) ?? null;
    const completed = Math.min(...journals.map((journal) => journal.evidence.length));
    const completedIndices = Array.from({ length: completed }, (_, index) => index);
    const activeFailures = journals.map((journal) => journal.active_failure);
    if (canonical(activeFailures[0]) !== canonical(activeFailures[1])) throw new InvalidTicketClosureError("track journals contain different active failures");
    const activeFailure = activeFailures[0];
    const unresolved = activeFailure?.reason.startsWith("EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP:") === true;
    const state = unresolved ? "EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP" : activeFailure !== null ? "FAILED" : completed === TICKET_CLOSURE_STEPS_V1.length ? "COMPLETE" : "IN_PROGRESS";
    return Object.freeze({ state, completion_percentage: Math.floor(completed * 100 / TICKET_CLOSURE_STEPS_V1.length), completed_indices: completedIndices, next_index: completed === TICKET_CLOSURE_STEPS_V1.length ? null : completed, first_failure: firstFailure });
  }

  async advance(fences: Readonly<{ n1: WorkAttemptFenceV1; enterprise: WorkAttemptFenceV1 }>, port: TicketClosurePortV1): Promise<TicketClosureStatusV1> {
    this.#validateFences(fences);
    const journals = { n1: this.load("n1"), enterprise: this.load("enterprise") };
    for (const track of ["n1", "enterprise"] as const) this.#validateReference(fences[track], journals[track]);
    if (journals.n1.evidence.length !== journals.enterprise.evidence.length) {
      const [shortTrack, longTrack] = journals.n1.evidence.length < journals.enterprise.evidence.length ? ["n1", "enterprise"] as const : ["enterprise", "n1"] as const;
      const shorter = journals[shortTrack], longer = journals[longTrack];
      if (longer.evidence.length !== shorter.evidence.length + 1 || canonical(longer.evidence.slice(0, -1)) !== canonical(shorter.evidence)) throw new InvalidTicketClosureError("track journals disagree on more than one interrupted append");
      await this.#underBothFences(fences, () => this.#write({ ...shorter, evidence: longer.evidence, first_failure: longer.first_failure, active_failure: longer.active_failure }));
      return this.status();
    }
    if (canonical(journals.n1.evidence) !== canonical(journals.enterprise.evidence)) throw new InvalidTicketClosureError("track journals contain different evidence");
    if (canonical(journals.n1.first_failure) !== canonical(journals.enterprise.first_failure)) {
      const retained = journals.n1.first_failure ?? journals.enterprise.first_failure;
      if (retained === null) throw new InvalidTicketClosureError("track failure journals disagree");
      await this.#underBothFences(fences, () => {
        if (journals.n1.first_failure === null) this.#write({ ...journals.n1, first_failure: retained });
        if (journals.enterprise.first_failure === null) this.#write({ ...journals.enterprise, first_failure: retained });
      });
      throw new TicketClosureFailedError("closure retains its first failure");
    }
    if (canonical(journals.n1.active_failure) !== canonical(journals.enterprise.active_failure)) {
      const active = journals.n1.active_failure ?? journals.enterprise.active_failure;
      if (active === null) throw new InvalidTicketClosureError("track active failures disagree");
      await this.#underBothFences(fences, () => {
        if (journals.n1.active_failure === null) this.#write({ ...journals.n1, active_failure: active });
        if (journals.enterprise.active_failure === null) this.#write({ ...journals.enterprise, active_failure: active });
      });
      throw new TicketClosureFailedError("closure retains its active failure");
    }
    const activeFailure = journals.n1.active_failure;
    if (activeFailure?.reason.startsWith("EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP:") === true) throw new TicketClosureFailedError("unresolved external effect cannot be retried");
    if (activeFailure !== null && activeFailure.completion_index !== journals.n1.evidence.length) throw new InvalidTicketClosureError("active failure does not describe the current step");
    if (activeFailure !== null && (!activeFailure.retryable || activeFailure.attempts >= 2)) throw new TicketClosureFailedError("failed closure step has no retry remaining");
    const index = journals.n1.evidence.length;
    if (index === TICKET_CLOSURE_STEPS_V1.length) return this.status();
    const step = TICKET_CLOSURE_STEPS_V1[index]!;
    const operationId = createHash("sha256").update(this.#subject.ticket_id).update("\0").update(this.#subjectIdentity).update("\0").update(String(index)).digest("hex");
    const request: TicketClosureRequestV1 = Object.freeze({ completion_index: index, step_id: step[0], operation_id: operationId, subject_identity: this.#subjectIdentity, subject: clone(this.#subject) });
    let result: TicketClosureStepResultV1;
    try {
      const observed = await port.observe(request);
      if (!plain(observed) || !["ABSENT", "MATCH", "UNKNOWN"].includes(String(observed.status))) throw new TicketClosureEvidenceMismatchError("observation is malformed");
      if (observed.status === "UNKNOWN") {
        if (Object.keys(observed).sort().join(",") !== "reason,status" || !boundedText(observed.reason)) throw new TicketClosureEvidenceMismatchError("unknown observation lacks a bounded reason");
        throw new TicketClosureEffectOutcomeUnresolvedError(observed.reason);
      }
      if (observed.status === "MATCH") {
        if (Object.keys(observed).sort().join(",") !== "operation_id,status,value") throw new TicketClosureEvidenceMismatchError("matching observation contains unknown fields");
        if (observed.operation_id !== operationId) throw new TicketClosureEvidenceMismatchError("observed operation identity is substituted");
        result = validateResult(index, observed.value, this.#subject);
      } else {
        if (Object.keys(observed).join(",") !== "status") throw new TicketClosureEvidenceMismatchError("absent observation contains unknown fields");
        if (index === 1) throw new TicketClosureEvidenceMismatchError("frozen source commit is absent from the declared checkpoint remote");
        const remoteMutation = index === 8;
        const raw = remoteMutation
          ? await fences.n1.withCurrent(async () => await fences.enterprise.withCurrent(async () => await port.execute(request)))
          : await port.execute(request);
        result = validateResult(index, raw, this.#subject);
      }
    } catch (error) {
      const reason = error instanceof TicketClosureEffectOutcomeUnresolvedError ? `EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP:${error.message}` : `${error instanceof Error ? error.name : "Error"}:${error instanceof Error ? error.message : String(error)}`;
      const retained = activeFailure ?? { completion_index: index, reason, retryable: error instanceof TicketClosureRetryableError, attempts: 0 };
      const failure = { ...retained, attempts: retained.attempts + 1 };
      const firstFailure = journals.n1.first_failure ?? failure;
      await this.#underBothFences(fences, () => {
        for (const track of ["n1", "enterprise"] as const) this.#write({ ...journals[track], attempt_reference: referenceOf(fences[track]), first_failure: firstFailure, active_failure: failure });
      });
      throw error;
    }
    await this.#underBothFences(fences, () => {
      for (const track of ["n1", "enterprise"] as const) {
        const prior = journals[track].evidence.at(-1)?.evidence_digest ?? ZERO_DIGEST;
        const unsigned = { completion_index: index, step_id: step[0], evidence_class: step[1], ticket_id: this.#subject.ticket_id, subject_identity: this.#subjectIdentity, operation_id: operationId, result: result.result, facts: result.facts, ...(result.tracks === undefined ? {} : { tracks: result.tracks }), prior_evidence_digest: prior };
        const evidence = { ...unsigned, evidence_digest: digest(unsigned) } as TicketClosureEvidenceV1;
        this.#write({ ...journals[track], attempt_reference: referenceOf(fences[track]), active_failure: null, evidence: [...journals[track].evidence, evidence] });
      }
    });
    return this.status();
  }

  #validateFences(fences: Readonly<{ n1: WorkAttemptFenceV1; enterprise: WorkAttemptFenceV1 }>): void {
    for (const track of ["n1", "enterprise"] as const) {
      const fence = fences[track]; const identity = fence.identity;
      if (identity.track !== track || identity.project_id !== this.#subject.project_id || identity.goal_id !== this.#subject.goal_id || identity.subgoal_id !== this.#subject.subgoal_id || identity.ticket_id !== this.#subject.ticket_id || identity.product_commit !== this.#subject.product_commit || identity.ticket_body_digest !== this.#subject.attempt_fence_ticket_body_digest || canonical(identity.ticket_body) !== canonical(JSON.parse(this.#subject.approved_ticket_body_json)) || authorityDigest(fence) !== this.#subject[`${track}_authority_digest`]) throw new StaleWorkAttemptError("closure fence is stale, cross-track, or substituted");
    }
  }

  #validateReference(fence: WorkAttemptFenceV1, journal: TicketClosureJournalV1): void {
    const previous = journal.attempt_reference, current = fence.reference;
    const same = current.identity_digest === previous.identity_digest && current.attempt_id === previous.attempt_id && current.generation === previous.generation;
    const takeover = current.identity_digest === previous.identity_digest && current.generation > previous.generation && current.attempt_id !== previous.attempt_id;
    if (!same && !takeover) throw new StaleWorkAttemptError("closure attempt lineage is stale or substituted");
  }

  async #underBothFences(fences: Readonly<{ n1: WorkAttemptFenceV1; enterprise: WorkAttemptFenceV1 }>, commit: () => void): Promise<void> {
    await fences.n1.withCurrent(async () => await fences.enterprise.withCurrent(async () => { commit(); }));
  }

  #empty(track: TicketClosureTrackV1): TicketClosureJournalV1 {
    return { schema: "keep.ticket-closure-journal/v1", schema_version: 1, track, authority_digest: this.#subject[`${track}_authority_digest`], attempt_reference: clone(this.#subject.attempts[track]), subject: clone(this.#subject), subject_identity: this.#subjectIdentity, first_failure: null, active_failure: null, evidence: [] };
  }

  #path(track: TicketClosureTrackV1): string { return join(this.directory, `${track}.journal.json`); }

  #loadOptional(track: TicketClosureTrackV1): TicketClosureJournalV1 | undefined {
    let fd: number | undefined; let bytes: Buffer;
    try { fd = openSync(this.#path(track), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); const stat = fstatSync(fd); const uid = typeof process.getuid === "function" ? process.getuid() : stat.uid; if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o077) !== 0) throw new InvalidTicketClosureError("closure journal must be private and owner-controlled"); bytes = readFileSync(fd); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
    finally { if (fd !== undefined) closeSync(fd); }
    if (bytes.byteLength > MAX_JOURNAL_BYTES) throw new InvalidTicketClosureError("closure journal exceeds size ceiling");
    let value: unknown; try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new InvalidTicketClosureError("closure journal is malformed"); }
    return this.#decodeJournal(value, track);
  }

  #decodeJournal(value: unknown, track: TicketClosureTrackV1): TicketClosureJournalV1 {
    if (!plain(value) || Object.keys(value).sort().join(",") !== "active_failure,attempt_reference,authority_digest,evidence,first_failure,schema,schema_version,subject,subject_identity,track" || value.schema !== "keep.ticket-closure-journal/v1" || value.schema_version !== 1 || value.track !== track || value.subject_identity !== this.#subjectIdentity || canonical(value.subject) !== canonical(this.#subject) || value.authority_digest !== this.#subject[`${track}_authority_digest`] || !plain(value.attempt_reference) || !Array.isArray(value.evidence)) throw new InvalidTicketClosureError("closure journal identity is invalid");
    const reference = value.attempt_reference;
    if (Object.keys(reference).sort().join(",") !== "attempt_id,generation,identity_digest" || reference.identity_digest !== this.#subject.attempts[track].identity_digest || !/^[0-9a-f]{32}$/u.test(String(reference.attempt_id)) || !Number.isSafeInteger(reference.generation) || Number(reference.generation) < this.#subject.attempts[track].generation) throw new InvalidTicketClosureError("closure journal attempt lineage is invalid");
    let prior = ZERO_DIGEST;
    const evidence = value.evidence.map((entry, index) => {
      if (!plain(entry) || entry.completion_index !== index || entry.step_id !== TICKET_CLOSURE_STEPS_V1[index]?.[0] || entry.evidence_class !== TICKET_CLOSURE_STEPS_V1[index]?.[1] || entry.ticket_id !== this.#subject.ticket_id || entry.subject_identity !== this.#subjectIdentity || entry.prior_evidence_digest !== prior || !HEX.test(String(entry.operation_id)) || !HEX.test(String(entry.evidence_digest))) throw new InvalidTicketClosureError("closure evidence skips, reorders, or changes subject");
      const { evidence_digest: evidenceDigest, ...unsigned } = entry;
      if (digest(unsigned) !== evidenceDigest) throw new InvalidTicketClosureError("closure evidence digest disagrees");
      validateResult(index, { result: entry.result, facts: entry.facts, ...(entry.tracks === undefined ? {} : { tracks: entry.tracks }) }, this.#subject);
      prior = String(evidenceDigest); return clone(entry) as unknown as TicketClosureEvidenceV1;
    });
    const failure = value.first_failure;
    if (failure !== null && (!plain(failure) || Object.keys(failure).sort().join(",") !== "attempts,completion_index,reason,retryable" || !Number.isSafeInteger(failure.completion_index) || Number(failure.completion_index) < 0 || Number(failure.completion_index) > evidence.length || !boundedText(failure.reason) || typeof failure.retryable !== "boolean" || !Number.isSafeInteger(failure.attempts) || Number(failure.attempts) < 1 || Number(failure.attempts) > 2)) throw new InvalidTicketClosureError("closure first failure is malformed");
    const active = value.active_failure;
    if (active !== null && (!plain(active) || Object.keys(active).sort().join(",") !== "attempts,completion_index,reason,retryable" || active.completion_index !== evidence.length || !boundedText(active.reason) || typeof active.retryable !== "boolean" || !Number.isSafeInteger(active.attempts) || Number(active.attempts) < 1 || Number(active.attempts) > 2)) throw new InvalidTicketClosureError("closure active failure is malformed");
    return clone({ ...value, evidence } as unknown as TicketClosureJournalV1);
  }

  #write(journal: TicketClosureJournalV1): void {
    const bytes = Buffer.from(`${canonical(journal)}\n`, "utf8");
    if (bytes.byteLength > MAX_JOURNAL_BYTES) throw new InvalidTicketClosureError("closure journal exceeds size ceiling");
    const destination = this.#path(journal.track); const temporary = join(this.directory, `.${journal.track}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
    let fd: number | undefined;
    try { fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); writeFileSync(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temporary, destination); const dir = openSync(dirname(destination), constants.O_RDONLY | constants.O_DIRECTORY); try { fsyncSync(dir); } finally { closeSync(dir); } }
    finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temporary); } catch { /* best effort */ } }
  }
}
