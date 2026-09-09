import { types } from "node:util";

import { decodeCanonical, eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import {
  EventEnvelopeV1Encode,
  type EventEnvelopeV1RefusalCode,
  type EventEnvelopeV1Track,
  type EventEnvelopeV1Value,
} from "./event_envelope_v1.js";

export const EventAdmissionV1HeadDigestDomain = "keep.spine.event-head.v1" as const;

export interface EventAdmissionV1LineageRecord {
  readonly sequence: bigint;
  readonly event_id: string;
  readonly predecessor_event_id: string | null;
  readonly predecessor_head_id: string | null;
  readonly head_id: string;
}

export interface EventAdmissionV1WitnessedHead {
  readonly sequence: bigint;
  readonly event_id: string;
  readonly head_id: string;
}

interface EventAdmissionV1TrustedBase {
  readonly history_id: string;
  readonly actor_id: string;
  readonly authority_domain: string;
  readonly custody_id: string;
  readonly committed_lineage: readonly EventAdmissionV1LineageRecord[];
  readonly witnessed_head: EventAdmissionV1WitnessedHead | null;
}

export interface EventAdmissionV1N1Context extends EventAdmissionV1TrustedBase {
  readonly kind: "n1";
  readonly track: "n1";
}

export interface EventAdmissionV1EnterpriseContext extends EventAdmissionV1TrustedBase {
  readonly kind: "enterprise";
  readonly track: "enterprise";
  readonly organization_id: string;
  readonly tenant_id: string;
  readonly actor_role_id: string;
  readonly isolation_id: string;
}

export type EventAdmissionV1TrustedContext = EventAdmissionV1N1Context | EventAdmissionV1EnterpriseContext;

export type EventAdmissionV1Authority =
  | {
      readonly kind: "n1";
      readonly track: "n1";
      readonly actor_id: string;
      readonly authority_domain: string;
      readonly custody_id: string;
    }
  | {
      readonly kind: "enterprise";
      readonly track: "enterprise";
      readonly actor_id: string;
      readonly authority_domain: string;
      readonly custody_id: string;
      readonly organization_id: string;
      readonly tenant_id: string;
      readonly actor_role_id: string;
      readonly isolation_id: string;
    };

export interface EventAdmissionV1Identity {
  readonly history_id: string;
  readonly sequence: bigint;
  readonly predecessor_event_id: string | null;
  readonly predecessor_head_id: string | null;
  readonly event_id: string;
  readonly next_head_id: string;
  readonly authority: EventAdmissionV1Authority;
}

export type EventAdmissionV1Result =
  | { readonly ok: true; readonly admission: EventAdmissionV1Identity }
  | { readonly ok: false; readonly code: "EVENT_PROPOSAL_INVALID"; readonly upstream_code: EventEnvelopeV1RefusalCode }
  | { readonly ok: false; readonly code: "TRUSTED_CONTEXT_INVALID" }
  | { readonly ok: false; readonly code: "ACTOR_AUTHORITY_MISMATCH" }
  | { readonly ok: false; readonly code: "TRACK_AUTHORITY_SUBSTITUTION" }
  | { readonly ok: false; readonly code: "EVENT_SEQUENCE_MISMATCH" }
  | { readonly ok: false; readonly code: "EVENT_PREDECESSOR_MISMATCH"; readonly failed_at: bigint | null };

const MAX_UINT64 = 0xffff_ffff_ffff_ffffn;
const HEX64 = /^[0-9a-f]{64}$/;
const normalize = String.prototype.normalize;
const lineageKeys = ["sequence", "event_id", "predecessor_event_id", "predecessor_head_id", "head_id"] as const;
const witnessKeys = ["sequence", "event_id", "head_id"] as const;
const n1Keys = ["kind", "track", "history_id", "actor_id", "authority_domain", "custody_id", "committed_lineage", "witnessed_head"] as const;
const enterpriseKeys = [...n1Keys, "organization_id", "tenant_id", "actor_role_id", "isolation_id"] as const;

type Captured = Record<string, unknown>;

function captureRecord(value: unknown, keys: readonly string[]): Captured | null {
  if (value === null || typeof value !== "object" || types.isProxy(value)) return null;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return null;
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) return null;
  const out: Captured = Object.create(null) as Captured;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return null;
    out[key] = descriptor.value;
  }
  return out;
}

function captureArray(value: unknown): readonly unknown[] | null {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (length === undefined || !("value" in length) || typeof length.value !== "number") return null;
  const own = Reflect.ownKeys(value);
  if (own.length !== length.value + 1 || own.some((key) => typeof key !== "string" || (key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key)))) return null;
  const out: unknown[] = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return null;
    out.push(descriptor.value);
  }
  return out;
}

function validText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && isWellFormedText(value) && normalize.call(value, "NFC") === value;
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

function validUint64(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= 0n && value <= MAX_UINT64;
}

function headId(historyId: string, sequence: bigint, eventId: string, predecessorHeadId: string | null): string {
  return eirDigest(EventAdmissionV1HeadDigestDomain, {
    history_id: historyId,
    sequence,
    event_id: eventId,
    predecessor_head_id: predecessorHeadId,
  });
}

type CapturedContext = {
  readonly raw: Captured;
  readonly kind: "n1" | "enterprise";
  readonly lineage: readonly EventAdmissionV1LineageRecord[];
  readonly witness: EventAdmissionV1WitnessedHead | null;
};

function captureContext(value: unknown): CapturedContext | null {
  if (value === null || typeof value !== "object" || types.isProxy(value)) return null;
  const kindDescriptor = Object.getOwnPropertyDescriptor(value, "kind");
  if (kindDescriptor === undefined || !("value" in kindDescriptor) || !kindDescriptor.enumerable) return null;
  const kind = kindDescriptor.value;
  if (kind !== "n1" && kind !== "enterprise") return null;
  const raw = captureRecord(value, kind === "n1" ? n1Keys : enterpriseKeys);
  if (raw === null) return null;
  for (const key of ["history_id", "actor_id", "authority_domain", "custody_id"]) if (!validText(raw[key])) return null;
  if (kind === "enterprise") {
    for (const key of ["organization_id", "tenant_id", "actor_role_id", "isolation_id"]) if (!validText(raw[key])) return null;
  }
  const values = captureArray(raw.committed_lineage);
  if (values === null) return null;
  const lineage: EventAdmissionV1LineageRecord[] = [];
  for (const valueRecord of values) {
    const record = captureRecord(valueRecord, lineageKeys);
    if (record === null || !validUint64(record.sequence) || !validDigest(record.event_id) || !validDigest(record.head_id)
        || !(record.predecessor_event_id === null || validDigest(record.predecessor_event_id))
        || !(record.predecessor_head_id === null || validDigest(record.predecessor_head_id))) return null;
    lineage.push(Object.freeze({
      sequence: record.sequence,
      event_id: record.event_id,
      predecessor_event_id: record.predecessor_event_id,
      predecessor_head_id: record.predecessor_head_id,
      head_id: record.head_id,
    }));
  }
  let witness: EventAdmissionV1WitnessedHead | null = null;
  if (raw.witnessed_head !== null) {
    const captured = captureRecord(raw.witnessed_head, witnessKeys);
    if (captured === null || !validUint64(captured.sequence) || !validDigest(captured.event_id) || !validDigest(captured.head_id)) return null;
    witness = Object.freeze({ sequence: captured.sequence, event_id: captured.event_id, head_id: captured.head_id });
  }
  return { raw, kind, lineage, witness };
}

function predecessorFailure(index: number | null): EventAdmissionV1Result {
  return { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: index === null ? null : BigInt(index) };
}

export function EventAdmissionV1Admit(proposal: unknown, trustedContext: unknown): EventAdmissionV1Result {
  const encoded = EventEnvelopeV1Encode(proposal);
  if (!encoded.ok) return { ok: false, code: "EVENT_PROPOSAL_INVALID", upstream_code: encoded.code };
  const event = decodeCanonical(encoded.canonical_bytes) as unknown as EventEnvelopeV1Value;
  const context = captureContext(trustedContext);
  if (context === null) return { ok: false, code: "TRUSTED_CONTEXT_INVALID" };

  for (let index = 0; index < context.lineage.length; index += 1) {
    const current = context.lineage[index]!;
    const prior = index === 0 ? undefined : context.lineage[index - 1]!;
    const expectedSequence = prior === undefined ? 0n : prior.sequence + 1n;
    const expectedEvent = prior?.event_id ?? null;
    const expectedHead = prior?.head_id ?? null;
    if (current.sequence !== expectedSequence
        || current.predecessor_event_id !== expectedEvent || current.predecessor_head_id !== expectedHead
        || current.head_id !== headId(context.raw.history_id as string, current.sequence, current.event_id, current.predecessor_head_id)) {
      return predecessorFailure(index);
    }
  }
  const tail = context.lineage.at(-1);
  if (context.witness === null) {
    if (tail !== undefined) return { ok: false, code: "TRUSTED_CONTEXT_INVALID" };
  } else if (tail === undefined
      || context.witness.sequence !== tail.sequence
      || context.witness.event_id !== tail.event_id
      || context.witness.head_id !== tail.head_id) {
    return predecessorFailure(tail === undefined ? null : context.lineage.length - 1);
  }

  if (event.actor_id !== context.raw.actor_id) return { ok: false, code: "ACTOR_AUTHORITY_MISMATCH" };
  if (context.raw.track !== context.kind || event.track !== context.kind || event.authority_domain !== context.raw.authority_domain) {
    return { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" };
  }
  const expectedSequence = tail === undefined ? 0n : tail.sequence + 1n;
  if (event.sequence !== expectedSequence) return { ok: false, code: "EVENT_SEQUENCE_MISMATCH" };
  const expectedEvent = tail?.event_id ?? null;
  const expectedHead = tail?.head_id ?? null;
  if (event.history_id !== context.raw.history_id || event.predecessor_event_id !== expectedEvent || event.predecessor_head_id !== expectedHead) {
    return predecessorFailure(tail === undefined ? null : context.lineage.length - 1);
  }

  const authority: EventAdmissionV1Authority = context.kind === "n1"
    ? Object.freeze({
        kind: "n1",
        track: "n1",
        actor_id: context.raw.actor_id as string,
        authority_domain: context.raw.authority_domain as string,
        custody_id: context.raw.custody_id as string,
      })
    : Object.freeze({
        kind: "enterprise",
        track: "enterprise",
        actor_id: context.raw.actor_id as string,
        authority_domain: context.raw.authority_domain as string,
        custody_id: context.raw.custody_id as string,
        organization_id: context.raw.organization_id as string,
        tenant_id: context.raw.tenant_id as string,
        actor_role_id: context.raw.actor_role_id as string,
        isolation_id: context.raw.isolation_id as string,
      });
  return {
    ok: true,
    admission: Object.freeze({
      history_id: event.history_id,
      sequence: event.sequence,
      predecessor_event_id: event.predecessor_event_id,
      predecessor_head_id: event.predecessor_head_id,
      event_id: encoded.event_digest,
      next_head_id: headId(event.history_id, event.sequence, encoded.event_digest, event.predecessor_head_id),
      authority,
    }),
  };
}
