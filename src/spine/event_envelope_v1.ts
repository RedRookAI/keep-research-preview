import { types } from "node:util";

import { eirDigest, encodeCanonical, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";

export const EventEnvelopeV1Schema = "keep.spine.event-envelope" as const;
export const EventEnvelopeV1CodecIdentity = "keep.rfc8949-core-deterministic-cbor.v1" as const;
export const EventEnvelopeV1DigestDomain = "keep.spine.event-envelope.v1" as const;

export const EventEnvelopeV1EventTypes = Object.freeze([
  "generic",
  "identity.created",
  "identity.action",
  "sod.approval",
  "keystore.key_created",
  "keystore.key_shredded",
  "restoration.attestation",
  "checkpoint",
  "effect.intent",
  "effect.receipt",
  "effect.terminal",
  "effect.replay-disclosure",
  "goal.admitted",
  "goal.transitioned",
  "decomposition.proposed",
  "decomposition.transitioned",
  "decomposition.reviewed",
  "decomposition.approved",
  "decomposition.published",
  "ticket.admitted",
  "owner.delegation_granted",
  "owner.delegation_revoked",
  "owner.delegation_superseded",
  "delegated.admission",
  "owner.notified",
  "execution.stopped",
  "execution.resumed",
  "recovery.n1_observed",
  "recovery.enterprise_observed",
] as const);

export type EventEnvelopeV1EventType = (typeof EventEnvelopeV1EventTypes)[number];
export type EventEnvelopeV1Track = "n1" | "enterprise";
export type EventEnvelopeV1EffectCorrelation =
  | { readonly phase: "intent"; readonly correlation_id: string }
  | { readonly phase: "receipt" | "terminal" | "replay-disclosure"; readonly correlation_id: string; readonly intent_event_id: string };

export interface EventEnvelopeV1Value {
  readonly schema: typeof EventEnvelopeV1Schema;
  readonly schema_version: bigint;
  readonly codec: typeof EventEnvelopeV1CodecIdentity;
  readonly codec_version: bigint;
  readonly history_id: string;
  readonly sequence: bigint;
  readonly predecessor_event_id: string | null;
  readonly predecessor_head_id: string | null;
  readonly event_type: EventEnvelopeV1EventType;
  readonly actor_id: string;
  readonly authority_domain: string;
  readonly track: EventEnvelopeV1Track;
  readonly payload: CanonicalValue;
  readonly effect_correlation: EventEnvelopeV1EffectCorrelation | null;
}

export interface EventEnvelopeV1Golden {
  readonly canonical_hex: string;
  readonly event_digest: string;
}

export type EventEnvelopeV1RefusalCode =
  | "EVENT_ENVELOPE_FIELDS_INVALID"
  | "EVENT_SCHEMA_UNSUPPORTED"
  | "EVENT_CODEC_UNSUPPORTED"
  | "EVENT_TYPE_UNSUPPORTED"
  | "EVENT_CONTROL_INTEGER_INVALID"
  | "EVENT_TEXT_INVALID"
  | "EVENT_TRACK_INVALID"
  | "EVENT_PREDECESSOR_INVALID"
  | "EVENT_EFFECT_CORRELATION_INVALID"
  | "EVENT_CANONICAL_VALUE_INVALID"
  | "EVENT_CANONICAL_GOLDEN_MISMATCH";

export type EventEnvelopeV1Result =
  | {
      readonly ok: true;
      readonly canonical_bytes: Uint8Array;
      readonly event_digest: string;
      readonly schema: typeof EventEnvelopeV1Schema;
      readonly schema_version: 1n;
      readonly codec: typeof EventEnvelopeV1CodecIdentity;
      readonly codec_version: 1n;
    }
  | { readonly ok: false; readonly code: EventEnvelopeV1RefusalCode };

const envelopeKeys = Object.freeze([
  "schema", "schema_version", "codec", "codec_version", "history_id", "sequence",
  "predecessor_event_id", "predecessor_head_id", "event_type", "actor_id",
  "authority_domain", "track", "payload", "effect_correlation",
] as const);
const eventTypes = new Set<string>(EventEnvelopeV1EventTypes);
const maxUint64 = 0xffff_ffff_ffff_ffffn;
const normalize = String.prototype.normalize;

type CapturedRecord = Record<string, unknown>;

function captureExactRecord(value: unknown, expectedKeys: readonly string[]): CapturedRecord | null {
  if (value === null || typeof value !== "object" || types.isProxy(value)) return null;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string") || keys.length !== expectedKeys.length) return null;
  const expected = new Set(expectedKeys);
  if (keys.some((key) => !expected.has(key as string))) return null;
  const captured: CapturedRecord = Object.create(null) as CapturedRecord;
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return null;
    captured[key] = descriptor.value;
  }
  return captured;
}

function validText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && isWellFormedText(value) && normalize.call(value, "NFC") === value;
}

function validControlInteger(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= 0n && value <= maxUint64;
}

function captureEffectCorrelation(eventType: EventEnvelopeV1EventType, value: unknown): EventEnvelopeV1EffectCorrelation | null | undefined {
  if (!eventType.startsWith("effect.")) return value === null ? null : undefined;
  if (value === null) return undefined;
  const phase = eventType.slice("effect.".length) as "intent" | "receipt" | "terminal" | "replay-disclosure";
  const keys = phase === "intent" ? ["phase", "correlation_id"] : ["phase", "correlation_id", "intent_event_id"];
  const record = captureExactRecord(value, keys);
  if (record === null || record.phase !== phase || !validText(record.correlation_id)) return undefined;
  if (phase === "intent") return { phase, correlation_id: record.correlation_id };
  if (!validText(record.intent_event_id)) return undefined;
  return { phase, correlation_id: record.correlation_id, intent_event_id: record.intent_event_id };
}

/** Maps only the existing codec's stable public error name; every other fault propagates. */
export function EventEnvelopeV1CanonicalRefusal(error: unknown): "EVENT_CANONICAL_VALUE_INVALID" {
  const name = error !== null && typeof error === "object" && !types.isProxy(error)
    ? Object.getOwnPropertyDescriptor(error, "name")
    : undefined;
  if (name !== undefined && "value" in name && name.value === "CanonicalError") {
    return "EVENT_CANONICAL_VALUE_INVALID";
  }
  throw error;
}

export function EventEnvelopeV1Encode(input: unknown, expectedGolden?: EventEnvelopeV1Golden): EventEnvelopeV1Result {
  const envelope = captureExactRecord(input, envelopeKeys);
  if (envelope === null) return { ok: false, code: "EVENT_ENVELOPE_FIELDS_INVALID" };
  if (envelope.schema !== EventEnvelopeV1Schema || envelope.schema_version !== 1n) return { ok: false, code: "EVENT_SCHEMA_UNSUPPORTED" };
  if (envelope.codec !== EventEnvelopeV1CodecIdentity || envelope.codec_version !== 1n) return { ok: false, code: "EVENT_CODEC_UNSUPPORTED" };
  if (typeof envelope.event_type !== "string" || !eventTypes.has(envelope.event_type)) return { ok: false, code: "EVENT_TYPE_UNSUPPORTED" };
  if (!validControlInteger(envelope.schema_version) || !validControlInteger(envelope.codec_version) || !validControlInteger(envelope.sequence)) return { ok: false, code: "EVENT_CONTROL_INTEGER_INVALID" };
  if (!validText(envelope.history_id) || !validText(envelope.actor_id) || !validText(envelope.authority_domain)) return { ok: false, code: "EVENT_TEXT_INVALID" };
  if (envelope.track !== "n1" && envelope.track !== "enterprise") return { ok: false, code: "EVENT_TRACK_INVALID" };
  const genesis = envelope.sequence === 0n;
  if (genesis
    ? envelope.predecessor_event_id !== null || envelope.predecessor_head_id !== null
    : !validText(envelope.predecessor_event_id) || !validText(envelope.predecessor_head_id)) {
    return { ok: false, code: "EVENT_PREDECESSOR_INVALID" };
  }
  const eventType = envelope.event_type as EventEnvelopeV1EventType;
  const effect = captureEffectCorrelation(eventType, envelope.effect_correlation);
  if (effect === undefined) return { ok: false, code: "EVENT_EFFECT_CORRELATION_INVALID" };

  const canonical = Object.assign(Object.create(null), {
    schema: EventEnvelopeV1Schema,
    schema_version: 1n,
    codec: EventEnvelopeV1CodecIdentity,
    codec_version: 1n,
    history_id: envelope.history_id,
    sequence: envelope.sequence,
    predecessor_event_id: envelope.predecessor_event_id,
    predecessor_head_id: envelope.predecessor_head_id,
    event_type: eventType,
    actor_id: envelope.actor_id,
    authority_domain: envelope.authority_domain,
    track: envelope.track,
    payload: envelope.payload,
    effect_correlation: effect,
  }) as CanonicalValue;

  let canonicalBytes: Uint8Array;
  let eventDigest: string;
  try {
    canonicalBytes = encodeCanonical(canonical);
    eventDigest = eirDigest(EventEnvelopeV1DigestDomain, canonical);
  } catch (error) {
    return { ok: false, code: EventEnvelopeV1CanonicalRefusal(error) };
  }
  if (expectedGolden !== undefined) {
    const golden = captureExactRecord(expectedGolden, ["canonical_hex", "event_digest"]);
    if (golden === null
        || typeof golden.canonical_hex !== "string"
        || !/^(?:[0-9a-f]{2})+$/.test(golden.canonical_hex)
        || typeof golden.event_digest !== "string"
        || !/^[0-9a-f]{64}$/.test(golden.event_digest)
        || Buffer.from(canonicalBytes).toString("hex") !== golden.canonical_hex
        || eventDigest !== golden.event_digest) {
      return { ok: false, code: "EVENT_CANONICAL_GOLDEN_MISMATCH" };
    }
  }
  return {
    ok: true,
    canonical_bytes: canonicalBytes,
    event_digest: eventDigest,
    schema: EventEnvelopeV1Schema,
    schema_version: 1n,
    codec: EventEnvelopeV1CodecIdentity,
    codec_version: 1n,
  };
}
