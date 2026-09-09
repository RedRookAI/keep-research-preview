/**
 * PRE-EFFECT WITNESS INTERLOCK (Mechanical-Enforcement Increment 12a).
 *
 * THE PROPERTY: a consequential effect is structurally unreachable unless a DURABLE commitment to its execution
 * envelope was sealed FIRST, and the effect's receipt is bound back to that commitment. "Envelope" is scope-honest:
 * for an Incr-11 ADAPTER family it is the RESOLVED object (exact-object binding); for a plain EXECUTOR it is the
 * DECLARED authorized args (semantic-invocation binding — NOT the exact wire bytes). This is Anderson-1972's fourth
 * reference-monitor requirement (audit to a separate domain) + Clark-Wilson's "no effect without a logged, well-formed
 * transaction" + the WAL log-then-act rule, made LOAD-BEARING on the broker's live effect path.
 *
 * DURABILITY is real and delivered here, not deferred: the ack is returned only after the intent is sealed into the
 * chain AND that write is fsync-flushed to stable storage — provided the injected SpineStore is durable (use
 * `FileSpineStore(dir, { fsync: true })`; the in-memory store is for logic tests only). Crash-survival then rests on
 * the OS/filesystem fsync contract (a named substrate seam — a lying drive / network FS weakens it), never on this
 * library. What 12b adds is INDEPENDENCE (exporting the chain root out of the producer's write-set + a standalone
 * external-root verifier), NOT durability.
 *
 * HONEST SEAM — READ THIS. This is IN-PROCESS, SAME-TRUST-DOMAIN. A compromised Keep can forge the effect AND the
 * witness together: this layer is tamper-EVIDENT, NOT tamper-PROOF, NOT omission-resistant, NOT independent. What
 * 12a delivers that is real: (1) FAIL-CLOSED COUPLING — no first execution without a durably-sealed, content-bound
 * intent whose ack the broker re-validates; (2) a RECEIPT bound to that intent so a replay cannot disclose an
 * unwitnessed result. What makes the evidence chain actually checkable by a third party — exporting the chain ROOT
 * out of the producer's write-set and a standalone verifier that REQUIRES an independently-held root — is Increment
 * 12b. True independence (a witness QUORUM / separate host / TEE, and a separate-role ACK) are named seams C-4/C-5;
 * this module never claims them. The forward-secure key ratchet was deliberately CUT (no secure key erasure in Node,
 * and the key must persist across restarts on the same disk — an external root pins the past without any secret);
 * `keyEpoch` is a placeholder field. SELF-AUDIT 2026-08-18 correction: today it names custody of a key that does not
 * exist (the spine chain is unkeyed, exported roots unsigned). node:crypto ed25519 is PRESENT here, so real signing of
 * chain heads/roots is BUILDABLE (WIRE-BATCH B1/U5) — that makes keyEpoch real and delivers forward integrity via
 * external anchoring. The genuinely-seam residual is HARDWARE-backed forward-secure signing with attested secure
 * erasure in a TEE (S-tee, next capable model). Until B1 lands, keyEpoch is inert (kept for schema stability).
 *
 * SCOPE (conditional guarantee): the interlock gates only the BROKER-MEDIATED effect path. Until Increment 10's
 * ambient-authority closure is complete (fs/subprocess/env/other-net owners), a buggy/compromised workload can still
 * effect AROUND the broker without touching this interlock — stated, never hidden.
 *
 * COMPOSE-DON'T-DUPLICATE: this builds NO new hash chain. The reference `SpineDurableWitness` records intents /
 * terminals / replay-disclosures as events on the EXISTING spine chain (src/spine) and derives its ack from the
 * spine's own `ChainWitness`. The INTENT's content id (the authoritative binding the broker re-validates) is an
 * `eirDigest` over the full canonical intent (bigint-safe); the spine event payload carries JSON-safe projections.
 */

import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import type { Spine } from "../spine/spine.js";

/** A typed happens-before edge to an existing content-addressed artifact or chain entry (Lamport: causality is an
 *  edge set, not timestamps). The verifier reconstructs the causal DAG from these; each edge names WHAT it proves. */
export type CausalRef =
  | { readonly kind: "spine-entry"; readonly chainId: string; readonly seq: bigint; readonly entryHash: string }
  | { readonly kind: "decision"; readonly digest: string }
  | { readonly kind: "permit"; readonly permitId: string; readonly guardDigest: string };

/** How tightly the witnessed `executionDigest` binds the real effect (seam-honest naming, per the design attack):
 *  - "exact-object": an Incr-11 ADAPTER family — bound to the RESOLVED object identity (prepared.canonicalId).
 *  - "semantic-invocation": a plain EXECUTOR family — bound to the DECLARED authorized args, NOT the exact wire
 *    bytes (HTTP body / argv / RPC frame); exact-byte binding for those is a named seam. */
export type ExecutionBindingKind = "exact-object" | "semantic-invocation";

/** The pre-effect intent: the execution ENVELOPE about to happen (exact-object for an adapter, semantic-invocation
 *  for an executor — see ExecutionBindingKind), plus its causal predecessors. */
export interface WitnessIntent {
  readonly idemKey: string;            // the broker's full-operation idempotency identity
  readonly attemptId: string;          // unique per attempt (broker nonce + seq) — distinguishes retries of one idemKey
  readonly permitId: string;
  readonly epoch: bigint;
  readonly family: string;
  readonly operation: string;
  readonly objectId: string;           // the RESOLVED object (adapter) / authorized object (executor)
  readonly executionDigest: string;    // binds the prepared envelope / semantic invocation
  readonly bindingKind: ExecutionBindingKind;
  readonly keyEpoch: bigint;           // INERT placeholder until B1/U5 ed25519 signing lands (see header self-audit note)
  readonly causalParents: readonly CausalRef[];
}
/** The successful completion of a sealed intent: the effect ran and produced `outputDigest`. Together with
 *  WitnessTerminal it makes the chain COMPLETE — an intent event followed by NEITHER a receipt NOR a terminal is the
 *  ONLY shape that reads as a crash (the WAL orphan), so ordinary denials never raise a false "may-have-fired" alarm. */
export interface WitnessReceipt { readonly intentEntryHash: string; readonly outputDigest: string; }
/** A terminal disposition of a sealed intent (abort/execute-error) — "NOT a crash orphan". */
export interface WitnessTerminal { readonly intentEntryHash: string; readonly disposition: "aborted" | "error"; readonly reason: string; }
/** A served idempotent replay is an INFORMATION effect: it is witnessed (parent = the original intent) fail-closed
 *  BEFORE the cached output is disclosed. */
export interface ReplayDisclosure { readonly intentEntryHash: string; readonly idemKey: string; }

/** The acknowledgement a durable witness returns after sealing an intent. The broker RE-VALIDATES that `entryHash`
 *  equals the intent content id IT computed and that `executionDigest` echoes what it sent — so a stale/unrelated ack
 *  can never open the gate. `seq`/`root`/`headHash` pin the chain position (12b exports these out of the write-set). */
export interface WitnessAck {
  readonly chainId: string;
  readonly seq: bigint;
  readonly root: string;
  readonly headHash: string;
  readonly entryHash: string;          // = intentEntryHash(intent): the content id of the sealed intent
  readonly executionDigest: string;    // echoes intent.executionDigest
}

/** The pre-effect witness the broker consults. `sealIntent` MUST durably commit before returning an ack (the reference
 *  sink is fsync-durable when backed by `FileSpineStore(dir, {fsync:true})`); it THROWS if it cannot — the broker treats a throw / missing / mismatched ack
 *  as FAIL-CLOSED (no effect). `sealTerminal` / `observeReplay` are post-authorization records; `observeReplay` is
 *  fail-closed BEFORE a replay discloses. All are async so a real out-of-process / quorum sink (timeout, network,
 *  cancellation) fits behind the SAME interface — no method may "continue anyway" on failure. */
export interface DurableWitness {
  sealIntent(i: WitnessIntent, signal?: AbortSignal): Promise<WitnessAck>;
  sealReceipt(r: WitnessReceipt, signal?: AbortSignal): Promise<void>;
  sealTerminal(t: WitnessTerminal, signal?: AbortSignal): Promise<void>;
  observeReplay(r: ReplayDisclosure, signal?: AbortSignal): Promise<void>;
}

/** The AUTHORITATIVE binding: the content id of an intent, computed with eirDigest (RFC-8949 CBOR, bigint-safe). The
 *  broker recomputes this itself and requires the ack's `entryHash` to equal it — the ack is not trusted on its word. */
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

/** Honor a caller AbortSignal: a pre/mid-seal abort throws so the broker denies pre-effect (see class SIGNAL note). */
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
 * The reference DurableWitness, backed by the EXISTING spine chain (composition, not a new log). Each seal stages a
 * typed event and seals it into the hash-chain, then derives the ack from the spine's head witness. The ack is
 * returned ONLY after the intent is sealed into the chain; crash-survival requires a durable store —
 * `FileSpineStore(dir, { fsync: true })` fsync-flushes each block before the seal returns.
 *
 * SIGNAL: `sealIntent` honors the caller AbortSignal (a pre/mid-seal abort throws → the broker denies pre-effect). The
 * broker does NOT independently race the witness await — racing-and-abandoning a seal that then commits would create a
 * false crash orphan — so a witness that IGNORES the signal and hangs can strand dispatch. That is the same trusted-
 * component seam class as a hung executor/store: an out-of-process/quorum sink MUST honor the signal (named, not hidden).
 *
 * SEAM: this witness sink lives (today) in the agent's own write-set → DETECTION, not independence. 12b exports the
 * root out of the write-set; a quorum/separate host is C-4/C-5.
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
    throwIfAborted(signal); // re-check AFTER the seal: a post-commit abort throws → the broker's commit-then-throw path seals an aborted terminal (no false crash orphan)
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
    throwIfAborted(signal); // re-check AFTER the seal: a post-seal abort denies the replay disclosure (broker fail-closes)
  }

  /** Seal pending events into the chain and return the head witness. A seal that yields no reachable head (empty
   *  chain — impossible right after a stage, but total) THROWS so the broker fails closed rather than trusting a
   *  witness-less ack. */
  async #seal(): Promise<{ seq: bigint; root: string; headHash: string }> {
    await this.#spine.seal();
    const head = this.#spine.witnessHead();
    if (head === undefined) throw new Error("witness seal produced no chain head");
    return { seq: BigInt(head.seq), root: head.cumulativeRoot, headHash: head.headHash };
  }
}
