/**
 * Canonical event model for the Keep audit/event spine (Phase 0, Feature 29).
 *
 * Design decisions grounded in PHASE_0_SUBSTRATE.md:
 *  - Internal canonical model; map to OTel `gen_ai.*` at the boundary (conventions
 *    are pre-stable, so the core must not depend on their naming). This file is the core.
 *  - Every event carries a `schemaVersion` so old events stay immutable and are
 *    upcast at read time (Round 18 — schema evolution without breaking the chain).
 *  - Deterministic canonical serialization is required so the hash-chain is stable
 *    across processes/platforms (sorted keys, explicit encoding).
 */

/** Monotonic-ish identifier for an event. Opaque; assigned at stage time. */
export type EventId = string;

/** The kinds of event the spine understands at Phase 0. Extensible via the registry. */
export type EventType =
  | "generic"
  | "identity.created"
  | "identity.action" // an actor performed a governed action
  | "sod.approval" // a separation-of-duties approval was recorded
  | "keystore.key_created"
  | "keystore.key_shredded" // crypto-shred erasure (Round 15)
  | "restoration.attestation" // authorized PITR fork (Round 17)
  | "checkpoint" // rolling checkpoint / genesis-root (Round 13)
  | "effect.intent" // pre-effect witness intent (Increment 12a) — sealed BEFORE a consequential effect
  | "effect.receipt" // successful completion of a sealed intent (Increment 12a) — output digest bound to the intent
  | "effect.terminal" // terminal disposition of a sealed intent (Increment 12a) — "not a crash orphan"
  | "effect.replay-disclosure"; // an idempotent replay disclosed a prior result (Increment 12a)

/**
 * A staged (not-yet-sealed) event. Workers produce these concurrently.
 * Immutable once created.
 */
export interface StagedEvent {
  readonly id: EventId;
  readonly schemaVersion: number;
  readonly type: EventType;
  /** Wall-clock milliseconds since epoch, recorded at stage time. */
  readonly ts: number;
  /** The actor (identity id) responsible, or "system". */
  readonly actor: string;
  /**
   * Arbitrary structured payload. Sensitive fields should already be encrypted
   * by the key store (crypto-shred) before landing here — the spine stores
   * ciphertext + a hash, never plaintext secrets.
   */
  readonly payload: Readonly<Record<string, unknown>>;
}

/** Current canonical schema version for newly-created events. */
export const CURRENT_SCHEMA_VERSION = 1;

/**
 * Deterministic canonical JSON serialization: object keys sorted recursively,
 * so the same logical value always produces the same bytes on every platform.
 * This is what the hash-chain hashes over.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortDeep);
  const obj = value as Record<string, unknown>;
  // JSON own keys are data, including __proto__; do not invoke an inherited setter.
  const out: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(obj).sort()) {
    out[key] = sortDeep(obj[key]);
  }
  return out;
}

/**
 * Structural well-formedness of a staged event (schema check at the value layer).
 *
 * This is the "parse, don't validate" boundary for the spine: the write-time block
 * predicate (hashchain.validateBlock) composes this over every event it is asked to
 * seal, so an event of the wrong SHAPE can never enter the chain file — the corrupt
 * state is unreachable, not merely detectable by a later scan. LOCAL and O(1) per
 * event: it inspects only the value in hand, never other events or the chain.
 */
export function isWellFormedEvent(e: unknown): e is StagedEvent {
  if (e === null || typeof e !== "object") return false;
  const o = e as Record<string, unknown>;
  return (
    typeof o.id === "string" &&
    typeof o.schemaVersion === "number" &&
    Number.isFinite(o.schemaVersion) &&
    typeof o.type === "string" &&
    typeof o.ts === "number" &&
    Number.isFinite(o.ts) &&
    typeof o.actor === "string" &&
    o.payload !== null &&
    typeof o.payload === "object" &&
    !Array.isArray(o.payload)
  );
}

/** Canonical bytes of a staged event, used as the sealing input. */
export function canonicalEventBytes(e: StagedEvent): string {
  // Explicitly enumerate fields so future non-hashed metadata can't silently
  // change the hash. Order fixed here, values canonicalized.
  return canonicalize({
    id: e.id,
    schemaVersion: e.schemaVersion,
    type: e.type,
    ts: e.ts,
    actor: e.actor,
    payload: e.payload,
  });
}
