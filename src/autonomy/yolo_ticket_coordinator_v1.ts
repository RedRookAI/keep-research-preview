import { createHash } from "node:crypto";

import {
  validateTicketResearchProgressV1,
  type AuthorityPosture,
  type TicketResearchProgressInputV1,
  type TicketResearchProgressV1,
} from "./project_state.js";
import {
  FileWorkAttemptAuthorityV1,
  InvalidWorkAttemptError,
  replayWorkAttemptV1,
  type WorkAttemptReferenceV1,
  type WorkAttemptSnapshotV1,
  type WorkAttemptStageV1,
} from "../spine/work_attempt_authority_v1.js";

export type YoloTicketStopCodeV1 = "POSTURE_NOT_AUTONOMOUS" | "RESEARCH_AUTHORITY_INVALID" | "ATTEMPT_COMPLETE"
  | "PROTECTED_WORKLOAD_IMPACT" | "SCOPE_CONFLICT" | "OWNER_RESERVED_EFFECT" | "THIRD_VET_REQUIRED"
  | "RESOURCE_CEILING" | "AMBIGUOUS_EFFECT" | "ACTION_FAILURE";

export interface YoloTicketBoundaryFactsV1 {
  readonly requested_scope_ids: readonly string[];
  readonly protected_workload_effects: readonly {
    readonly resource: string;
    readonly consequence_order: 1 | 2 | 3;
  }[];
  readonly requested_effects: readonly {
    readonly description: string;
    readonly class: "none" | "pure-local" | "external-reversible" | "public" | "destructive" | "irreversible" | "unknown";
  }[];
  readonly requested_vet_round: 0 | 1 | 2 | 3;
  readonly resources: {
    readonly estimated_ram_mib: number;
    readonly estimated_disk_mib: number;
    readonly estimated_processes: number;
  };
}

export interface YoloTicketActionResultV1 {
  readonly outcome: "ADVANCE" | "FAILURE";
  readonly evidence_digest: string;
}

export interface YoloTicketStatusCapabilityV1 {
  readonly ticket_id: string;
  readonly track: "n1" | "enterprise";
  readonly status: "ACTIVE" | "CLOSED" | "REMAINING";
  readonly summary: string;
}

export interface YoloTicketStatusV1 {
  readonly schema: "keep.yolo-ticket-status/v1";
  readonly schema_version: 1;
  readonly mode: AuthorityPosture;
  readonly project_id: string;
  readonly ticket_id: string;
  readonly ticket_title: string;
  readonly current_work: string;
  readonly value: string;
  readonly next_action: string;
  readonly attempt_generation: number;
  readonly next_stage: WorkAttemptStageV1 | null;
  readonly last_outcome: "ADVANCE" | "FAILURE" | null;
  readonly stop_code: YoloTicketStopCodeV1 | null;
  readonly completed_capabilities: readonly YoloTicketStatusCapabilityV1[];
  readonly remaining_capabilities: readonly YoloTicketStatusCapabilityV1[];
  readonly completion: {
    readonly closed: number;
    readonly approved: number;
    readonly basis_points: number;
    readonly display: string;
  };
  readonly source_receipt_digest: string;
  readonly authoritative: false;
  readonly effects_performed: false;
  readonly projection_digest: string;
}

export interface YoloTicketStatusProjectionSinkV1 {
  publish(status: YoloTicketStatusV1): void | Promise<void>;
}

export interface YoloTicketCoordinatorInputV1 {
  readonly attempt_authority: FileWorkAttemptAuthorityV1;
  readonly attempt: WorkAttemptReferenceV1;
  readonly configured_posture: AuthorityPosture;
  readonly requested_posture?: AuthorityPosture;
  readonly research_progress: TicketResearchProgressInputV1;
  readonly boundary_facts: YoloTicketBoundaryFactsV1;
  readonly action: (stage: WorkAttemptStageV1, attempt: WorkAttemptSnapshotV1) => Promise<YoloTicketActionResultV1>;
  readonly status_sink?: YoloTicketStatusProjectionSinkV1;
}

export type YoloTicketStepResultV1 =
  | { readonly advanced: true; readonly code: "ADVANCED"; readonly attempt: WorkAttemptSnapshotV1; readonly status: YoloTicketStatusV1 }
  | { readonly advanced: false; readonly code: YoloTicketStopCodeV1; readonly attempt: WorkAttemptSnapshotV1; readonly status: YoloTicketStatusV1 };

const HEX = /^[0-9a-f]{64}$/u;
const boundedText = (value: unknown): value is string => typeof value === "string" && value.trim() === value && value.length > 0 && Buffer.byteLength(value, "utf8") <= 4096 && !value.includes("\0");
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const stable = (value: unknown): unknown => Array.isArray(value) ? value.map(stable) : plain(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
const digest = (value: unknown): string => createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
const freeze = <T>(value: T): T => {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
  }
  return value;
};

function effectivePosture(configured: unknown, requested: unknown): AuthorityPosture | null {
  const rank: Readonly<Record<AuthorityPosture, number>> = { autonomous: 0, "policy-calibrated": 1, "approval-required": 2 };
  if (typeof configured !== "string" || !Object.hasOwn(rank, configured)) return null;
  if (requested !== undefined && (typeof requested !== "string" || !Object.hasOwn(rank, requested))) return null;
  if (requested === undefined) return configured as AuthorityPosture;
  return rank[requested as AuthorityPosture] > rank[configured as AuthorityPosture] ? requested as AuthorityPosture : configured as AuthorityPosture;
}

function validBoundaryFacts(value: YoloTicketBoundaryFactsV1): boolean {
  if (!plain(value) || !Array.isArray(value.requested_scope_ids)
    || !Array.isArray(value.protected_workload_effects) || !Array.isArray(value.requested_effects)
    || ![0, 1, 2, 3].includes(value.requested_vet_round) || !plain(value.resources)) return false;
  if (!value.requested_scope_ids.every(boundedText) || new Set(value.requested_scope_ids).size !== value.requested_scope_ids.length) return false;
  if (value.protected_workload_effects.some((effect) => !plain(effect) || !boundedText(effect.resource) || typeof effect.consequence_order !== "number" || ![1, 2, 3].includes(effect.consequence_order))) return false;
  if (value.requested_effects.some((effect) => !plain(effect) || !boundedText(effect.description)
    || typeof effect.class !== "string" || !["none", "pure-local", "external-reversible", "public", "destructive", "irreversible", "unknown"].includes(effect.class))) return false;
  return ["estimated_ram_mib", "estimated_disk_mib", "estimated_processes"]
    .every((key) => Number.isSafeInteger(value.resources[key as keyof typeof value.resources]) && value.resources[key as keyof typeof value.resources] >= 0);
}

function authorityMatches(snapshot: WorkAttemptSnapshotV1, progress: TicketResearchProgressV1): boolean {
  const approved = progress.approved_tickets.find((ticket) => ticket.ticket_id === snapshot.identity.ticket_id);
  return approved?.track === snapshot.identity.track && snapshot.identity.ticket_id === progress.active_ticket_id;
}

function researchAuthorityMatches(snapshot: WorkAttemptSnapshotV1, input: TicketResearchProgressInputV1): boolean {
  const receipt = input.receipt;
  if (snapshot.identity.ticket_id !== receipt.ticket_id || snapshot.identity.track !== receipt.track) return false;
  const work = snapshot.identity.authority;
  const research = receipt.authority;
  if (work.kind !== research.kind) return false;
  if (work.kind === "n1" && research.kind === "n1") return work.owner_id === research.owner_id && work.custody_id === research.custody_id && work.organization_services === research.organization_services;
  if (work.kind === "enterprise" && research.kind === "enterprise") return work.organization_id === research.organization_id && work.actor_id === research.actor_id
    && work.role_id === research.role_id && work.separation_policy_id === research.separation_policy_id
    && work.custody_evidence_digest === research.custody_evidence_digest && work.isolation_evidence_digest === research.isolation_evidence_digest
    && work.local_owner_substitution === false && research.local_owner_substitution === false;
  return false;
}

function ticketControls(snapshot: WorkAttemptSnapshotV1): { readonly scope: Set<string>; readonly ram: number; readonly disk: number; readonly processes: number } | null {
  const ticket = snapshot.identity.ticket_body;
  if (!Array.isArray(ticket.scope_rows) || !ticket.scope_rows.every(boundedText) || new Set(ticket.scope_rows).size !== ticket.scope_rows.length || !plain(ticket.resource_bounds)) return null;
  const resources = ticket.resource_bounds;
  if (!Number.isSafeInteger(resources.peak_ram_mib) || Number(resources.peak_ram_mib) < 0 || !Number.isSafeInteger(resources.peak_disk_mib) || Number(resources.peak_disk_mib) < 0
    || !Number.isSafeInteger(resources.max_parallel_processes) || Number(resources.max_parallel_processes) < 0) return null;
  return { scope: new Set(ticket.scope_rows), ram: Number(resources.peak_ram_mib), disk: Number(resources.peak_disk_mib), processes: Number(resources.max_parallel_processes) };
}

function boundaryStop(snapshot: WorkAttemptSnapshotV1, facts: YoloTicketBoundaryFactsV1): YoloTicketStopCodeV1 | null {
  if (!validBoundaryFacts(facts)) return "AMBIGUOUS_EFFECT";
  const controls = ticketControls(snapshot);
  if (controls === null) return "AMBIGUOUS_EFFECT";
  if (facts.protected_workload_effects.length > 0) return "PROTECTED_WORKLOAD_IMPACT";
  if (facts.requested_scope_ids.length === 0 || facts.requested_scope_ids.some((scope) => !controls.scope.has(scope))) return "SCOPE_CONFLICT";
  if (facts.requested_effects.some((effect) => ["public", "destructive", "irreversible"].includes(effect.class))) return "OWNER_RESERVED_EFFECT";
  if (facts.requested_vet_round === 3) return "THIRD_VET_REQUIRED";
  const resource = facts.resources;
  if (resource.estimated_ram_mib > controls.ram || resource.estimated_disk_mib > controls.disk || resource.estimated_processes > controls.processes) return "RESOURCE_CEILING";
  if (facts.requested_effects.some((effect) => effect.class === "unknown" || effect.class === "external-reversible")) return "AMBIGUOUS_EFFECT";
  return null;
}

const stageText = (stage: WorkAttemptStageV1 | null): string => stage === null ? "No lifecycle transition remains" : stage.toLowerCase().replaceAll("_", " ");

function statusFor(snapshot: WorkAttemptSnapshotV1, progress: TicketResearchProgressV1, stop: YoloTicketStopCodeV1 | null, mode: AuthorityPosture): YoloTicketStatusV1 {
  const replay = replayWorkAttemptV1(snapshot.transitions);
  const title = boundedText(snapshot.identity.ticket_body.title) ? snapshot.identity.ticket_body.title : `approved ticket ${snapshot.identity.ticket_id}`;
  const completed = new Set(progress.closed_in_generation);
  const capabilities = progress.approved_tickets.map((ticket): YoloTicketStatusCapabilityV1 => ({
    ticket_id: ticket.ticket_id,
    track: ticket.track,
    status: ticket.ticket_id === progress.active_ticket_id ? "ACTIVE" : completed.has(ticket.ticket_id) ? "CLOSED" : "REMAINING",
    summary: ticket.ticket_id === snapshot.identity.ticket_id ? title : completed.has(ticket.ticket_id) ? "Validated closed capability" : "Approved capability remaining",
  }));
  const closed = capabilities.filter((capability) => capability.status === "CLOSED");
  const remaining = capabilities.filter((capability) => capability.status !== "CLOSED");
  const approved = capabilities.length;
  const basisPoints = approved === 0 ? 0 : Math.floor((closed.length * 10_000) / approved);
  const last = snapshot.transitions.at(-1)?.outcome ?? null;
  const body = {
    schema: "keep.yolo-ticket-status/v1" as const,
    schema_version: 1 as const,
    mode,
    project_id: snapshot.identity.project_id,
    ticket_id: snapshot.identity.ticket_id,
    ticket_title: title,
    current_work: replay.next_stage === null ? `${title} has completed its bounded lifecycle` : `Advance ${title} through ${stageText(replay.next_stage)}`,
    value: `Completes one approved ${snapshot.identity.track} capability without weakening its custody or evidence requirements`,
    next_action: stop === null ? stageText(replay.next_stage) : `Stop: ${stop.toLowerCase().replaceAll("_", " ")}`,
    attempt_generation: snapshot.generation,
    next_stage: replay.next_stage,
    last_outcome: last === "ADVANCE" || last === "FAILURE" ? last : null,
    stop_code: stop,
    completed_capabilities: closed,
    remaining_capabilities: remaining,
    completion: { closed: closed.length, approved, basis_points: basisPoints, display: `${closed.length}/${approved} (${(basisPoints / 100).toFixed(2)}%)` },
    source_receipt_digest: progress.receipt_digest,
    authoritative: false as const,
    effects_performed: false as const,
  };
  return freeze({ ...body, projection_digest: digest(body) });
}

export class YoloTicketCoordinatorV1 {
  async step(input: YoloTicketCoordinatorInputV1): Promise<YoloTicketStepResultV1> {
    const snapshot = input.attempt_authority.load(input.attempt);
    const progressResult = validateTicketResearchProgressV1(input.research_progress);
    const posture = effectivePosture(input.configured_posture, input.requested_posture);
    let stop: YoloTicketStopCodeV1 | null = null;
    if (posture !== "autonomous") stop = "POSTURE_NOT_AUTONOMOUS";
    else if (!progressResult.ok || progressResult.progress.ticket_status !== "ACTIVE" || !authorityMatches(snapshot, progressResult.progress) || !researchAuthorityMatches(snapshot, input.research_progress)) stop = "RESEARCH_AUTHORITY_INVALID";
    else if (replayWorkAttemptV1(snapshot.transitions).next_stage === null) stop = "ATTEMPT_COMPLETE";
    else stop = boundaryStop(snapshot, input.boundary_facts);
    if (stop !== null || !progressResult.ok) {
      const progress = progressResult.ok ? progressResult.progress : fallbackProgress(snapshot);
      const status = statusFor(snapshot, progress, stop ?? "RESEARCH_AUTHORITY_INVALID", posture ?? "approval-required");
      await publishStatus(input.status_sink, status);
      return freeze({ advanced: false, code: stop ?? "RESEARCH_AUTHORITY_INVALID", attempt: snapshot, status });
    }
    const stage = replayWorkAttemptV1(snapshot.transitions).next_stage;
    if (stage === null) throw new InvalidWorkAttemptError("completed attempt cannot advance");
    const action = await input.action(stage, snapshot);
    if (!plain(action) || (action.outcome !== "ADVANCE" && action.outcome !== "FAILURE") || typeof action.evidence_digest !== "string" || !HEX.test(action.evidence_digest)) throw new InvalidWorkAttemptError("bounded action returned invalid evidence");
    const recorded = await input.attempt_authority.record(input.attempt, stage, action.outcome, action.evidence_digest);
    const actionStop = action.outcome === "FAILURE" ? "ACTION_FAILURE" : null;
    const status = statusFor(recorded, progressResult.progress, actionStop, "autonomous");
    await publishStatus(input.status_sink, status);
    return action.outcome === "ADVANCE"
      ? freeze({ advanced: true, code: "ADVANCED" as const, attempt: recorded, status })
      : freeze({ advanced: false, code: "ACTION_FAILURE" as const, attempt: recorded, status });
  }
}

async function publishStatus(sink: YoloTicketStatusProjectionSinkV1 | undefined, status: YoloTicketStatusV1): Promise<void> {
  try { await sink?.publish(status); } catch { /* A disposable, non-authoritative view cannot change progression. */ }
}

function fallbackProgress(snapshot: WorkAttemptSnapshotV1): TicketResearchProgressV1 {
  const ticket = { ticket_id: snapshot.identity.ticket_id, track: snapshot.identity.track, dependency_ticket_ids: [] as string[] };
  return freeze({
    schema_version: 1, status: "TICKET_RESEARCH_PROGRESS_VALID", generation: "sha256:" + "0".repeat(64),
    receipt_digest: "0".repeat(64), active_ticket_id: null, ticket_status: "NOT_ACTIVE_NOT_CLOSED",
    approved_tickets: [ticket], closed_in_generation: [], closed_outside_generation: [], closed_in_generation_count: 0,
    authoritative: false, effects_performed: false,
  });
}
