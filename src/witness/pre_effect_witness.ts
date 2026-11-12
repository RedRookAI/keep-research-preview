/**
 * Seal a content-bound intent before a broker-mediated effect and bind its receipt to that intent.
 * Adapters bind a resolved object; plain executors bind declared authorized arguments. The latter
 * binding leaves exact wire-byte verification to the executor. Intents, receipts, terminal outcomes
 * and replay disclosures use the existing spine chain.
 *
 * The broker checks the acknowledgement against the canonical intent digest before execution.
 * A durable SpineStore is required: FileSpineStore with fsync:true flushes sealed blocks before
 * acknowledging them. Crash survival depends on the filesystem and storage honoring fsync.
 * This follows the write-ahead-log rule and Clark-Wilson's logged-transaction model.
 *
 * The witness and effect run in the same trust domain. A compromised producer can rewrite or omit
 * both. Independent checking requires an externally retained root and separate access controls.
 * The chain is unkeyed and keyEpoch is retained only for schema compatibility; it does not identify
 * a signing key. This interlock covers broker-mediated effects. Ambient filesystem, subprocess or
 * network operations outside the broker need separate mediation and isolation.
 */

import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import type { Spine } from "../spine/spine.js";

/**
 * A typed causal edge to an existing content-addressed artifact or chain entry.
 * The verifier reconstructs ordering from these references, following Lamport's happens-before model.
 */
export type CausalRef =
  | { readonly kind: "spine-entry"; readonly chainId: string; readonly seq: bigint; readonly entryHash: string }
  | { readonly kind: "decision"; readonly digest: string }
  | { readonly kind: "permit"; readonly permitId: string; readonly guardDigest: string };

/**
 * How executionDigest binds an effect:
 * - exact-object: the adapter's resolved object identity (prepared.canonicalId).
 * - semantic-invocation: the executor's declared authorized arguments; exact wire bytes remain
 *   the executor's responsibility.
 */
export type ExecutionBindingKind = "exact-object" | "semantic-invocation";

/**
 * The intended execution and its causal predecessors, with the binding described above.
 */
export interface WitnessIntent {
  readonly idemKey: string;            // the broker's full-operation idempotency identity
  readonly attemptId: string;          // unique per attempt (broker nonce + seq) — distinguishes retries of one idemKey
  readonly permitId: string;
  readonly epoch: bigint;
  readonly family: string;
  readonly operation: string;
  readonly objectId: string;           // Resolved adapter object or authorized executor object.
  readonly executionDigest: string;    // binds the prepared envelope / semantic invocation
  readonly bindingKind: ExecutionBindingKind;
  readonly keyEpoch: bigint;           // Inert compatibility field; no signing key is associated with it.
  readonly causalParents: readonly CausalRef[];
}
/**
 * A completed effect bound to its sealed intent and output. An intent without a receipt or
 * terminal remains unresolved, including after a process crash.
 */
export interface WitnessReceipt { readonly intentEntryHash: string; readonly outputDigest: string; }
/** Explicit abort or execution-error disposition for a sealed intent. */
export interface WitnessTerminal { readonly intentEntryHash: string; readonly disposition: "aborted" | "error"; readonly reason: string; }
/**
 * Record a replay disclosure against its original intent before releasing the cached output.
 */
export interface ReplayDisclosure { readonly intentEntryHash: string; readonly idemKey: string; }

/**
 * Acknowledgement returned after sealing an intent. The broker compares entryHash with its own
 * intent digest and executionDigest with the submitted execution. seq, root and headHash identify
 * the chain position for later verification.
 */
export interface WitnessAck {
  readonly chainId: string;
  readonly seq: bigint;
  readonly root: string;
  readonly headHash: string;
  readonly entryHash: string;          // = intentEntryHash(intent): the content id of the sealed intent
  readonly executionDigest: string;    // echoes intent.executionDigest
}

/**
 * Witness port used by the broker. sealIntent must durably commit before returning; a failure or
 * mismatched acknowledgement prevents execution. observeReplay must complete before disclosing
 * cached output. Implementations must honor cancellation and report failures to the caller.
 */
export interface DurableWitness {
  sealIntent(i: WitnessIntent, signal?: AbortSignal): Promise<WitnessAck>;
  sealReceipt(r: WitnessReceipt, signal?: AbortSignal): Promise<void>;
  sealTerminal(t: WitnessTerminal, signal?: AbortSignal): Promise<void>;
  observeReplay(r: ReplayDisclosure, signal?: AbortSignal): Promise<void>;
}

/**
 * Canonical intent digest using bigint-safe RFC 8949 CBOR. The broker recomputes this digest
 * and requires the acknowledgement's entryHash to match.
 */
export function intentEntryHash(i: WitnessIntent): string {
  return eirDigest("keep.witness.intent/v1", intentCanonical(i));
}

function refCanonical(r: CausalRef): CanonicalValue {
  switch (r.kind) {
    case "spine-entry": return { kind: "spine-entry", chainId: r.chainId, seq: r.seq, entryHash: r.entryHash };
    case "decision": return { kind: "decision", digest: r.digest };
    case "permit": return { kind: "permit", permitId: r.permitId, guardDigest: r.guardDigest };
  }
}
function intentCanonical(i: WitnessIntent): CanonicalValue {
  return {
    idemKey: i.idemKey, attemptId: i.attemptId, permitId: i.permitId, epoch: i.epoch, family: i.family,
    operation: i.operation, objectId: i.objectId, executionDigest: i.executionDigest, bindingKind: i.bindingKind,
    keyEpoch: i.keyEpoch, causalParents: i.causalParents.map(refCanonical),
  };
}

/** Refuse a cancelled seal so the broker cannot dispatch its effect. */
function throwIfAborted(signal?: AbortSignal): void {
  let aborted = false; try { aborted = signal?.aborted === true; } catch { aborted = true; } // hostile getter ⇒ treat as aborted
  if (aborted) throw new Error("witness seal aborted by caller signal");
}

/** A JSON-safe (bigint→decimal-string) projection of a value for the spine event payload — the spine hashes over
 *  `JSON.stringify`, which cannot encode bigint. The authoritative binding is the eirDigest content id, not this. */
function jsonSafe(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(jsonSafe);
  if (v !== null && typeof v === "object") { const o: Record<string, unknown> = {}; for (const k of Object.keys(v as object)) o[k] = jsonSafe((v as Record<string, unknown>)[k]); return o; }
  return v;
}

/**
 * DurableWitness backed by the spine chain. Each method stages a typed record and seals it.
 * sealIntent returns the resulting chain position only after the store confirms the seal.
 * FileSpineStore with fsync:true supplies the required durable write.
 *
 * Cancellation is checked before and after sealing. The broker awaits the witness rather than
 * abandoning a pending seal, which could later commit without a recorded terminal outcome.
 * A sink that ignores cancellation can stall dispatch. External implementations must preserve
 * this contract. Independent retention of the chain root is configured separately.
 */
export class SpineDurableWitness implements DurableWitness {
  readonly #spine: Spine;
  readonly #chainId: string;
  readonly #actor: string;
  constructor(spine: Spine, chainId: string, actor = "effect-broker") {
    if (spine === null || typeof spine !== "object" || typeof spine.stage !== "function" || typeof spine.seal !== "function" || typeof spine.witnessHead !== "function") throw new Error("SpineDurableWitness requires a Spine");
    if (typeof chainId !== "string" || chainId.length === 0) throw new Error("SpineDurableWitness requires a chainId");
    this.#spine = spine; this.#chainId = chainId; this.#actor = actor;
  }

  async sealIntent(i: WitnessIntent, signal?: AbortSignal): Promise<WitnessAck> {
    throwIfAborted(signal);
    const entryHash = intentEntryHash(i);
    this.#spine.stage({ type: "effect.intent", actor: this.#actor, payload: {
      kind: "effect.intent", intentEntryHash: entryHash, chainId: this.#chainId,
      ...(jsonSafe(intentCanonical(i)) as Record<string, unknown>),
    } });
    const w = await this.#seal();
    throwIfAborted(signal); // A post-commit abort enters the broker's aborted-terminal path.
    return { chainId: this.#chainId, seq: w.seq, root: w.root, headHash: w.headHash, entryHash, executionDigest: i.executionDigest };
  }

  async sealReceipt(r: WitnessReceipt, signal?: AbortSignal): Promise<void> {
    throwIfAborted(signal);
    this.#spine.stage({ type: "effect.receipt", actor: this.#actor, payload: { kind: "effect.receipt", intentEntryHash: r.intentEntryHash, outputDigest: r.outputDigest } });
    await this.#seal();
  }

  async sealTerminal(t: WitnessTerminal, signal?: AbortSignal): Promise<void> {
    throwIfAborted(signal);
    this.#spine.stage({ type: "effect.terminal", actor: this.#actor, payload: { kind: "effect.terminal", intentEntryHash: t.intentEntryHash, disposition: t.disposition, reason: t.reason } });
    await this.#seal();
  }

  async observeReplay(r: ReplayDisclosure, signal?: AbortSignal): Promise<void> {
    throwIfAborted(signal);
    this.#spine.stage({ type: "effect.replay-disclosure", actor: this.#actor, payload: { kind: "effect.replay-disclosure", intentEntryHash: r.intentEntryHash, idemKey: r.idemKey } });
    await this.#seal();
    throwIfAborted(signal); // A post-seal abort prevents disclosure of the cached result.
  }

  /**
   * Seal pending records and return the resulting head. Refuse an acknowledgement without a
   * reachable chain head.
   */
  async #seal(): Promise<{ seq: bigint; root: string; headHash: string }> {
    await this.#spine.seal();
    const head = this.#spine.witnessHead();
    if (head === undefined) throw new Error("witness seal produced no chain head");
    return { seq: BigInt(head.seq), root: head.cumulativeRoot, headHash: head.headHash };
  }
}
