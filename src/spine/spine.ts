/**
 * The Spine (Feature 29) — the two-stage append-only, hash-chained event spine.
 *
 * Two-stage (Round 8): workers `stage()` events concurrently; a leader-elected
 * `seal()` batches staged events into the hash-chain under the DistributedLock,
 * so tamper-evidence never blocks concurrent ingestion.
 *
 * Primitives included:
 *  - checkpoint() (Round 13): emit a checkpoint block attesting the cumulative root,
 *    so the active chain can be bounded (older blocks offloadable).
 *  - attestRestoration() (Round 17): append a signed restoration-attestation event
 *    declaring an authorized PITR fork that reconciles with an external anchor.
 *  - verify()/replay(): the chain is the source of truth (CQRS); derived state is a
 *    projection that can be deterministically rebuilt by replaying events.
 */

import { randomUUID } from "node:crypto";
import type { SpineStore } from "./store.js";
import type { StagedEvent, EventType } from "./event.js";
import { CURRENT_SCHEMA_VERSION, canonicalize } from "./event.js";
import type { SealedBlock, VerifyResult, ChainWitness, WitnessCheck } from "./hashchain.js";
import { sealBlock, verifyChain, makeWitness, verifyAgainstWitness } from "./hashchain.js";
import type { WitnessSink } from "./witness_sink.js";
import { reconcileWithWitness, extractAttestations, type ReconcileVerdict } from "./witness_reconcile.js";
import type { DistributedLock } from "../lock/lock.js";
import type { SchemaRegistry } from "./upcaster.js";

export interface StageInput {
  readonly type: EventType;
  readonly actor: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

export class Spine {
  constructor(
    private readonly store: SpineStore,
    private readonly lock: DistributedLock,
    private readonly registry: SchemaRegistry,
    private readonly clock: () => number = () => Date.now(),
    /**
     * L4 (witness materialization). An independent witness sink. When present, `seal()`
     * and `checkpoint()` auto-publish the new head witness to it, so the chain becomes
     * tamper-evident against TRUNCATION and FORK — which `verifyChain()`/`verify()` alone
     * cannot detect (see witness_sink.ts). ABSENT → behavior is byte-identical to before
     * (no witnessing): every existing `new Spine(store, lock, registry[, clock])` caller is
     * unaffected. HONEST SEAM: a sink inside the agent's own write-set gives DETECTION, not
     * independence from a full-host compromise; a real independent location / fleet cosign
     * is the deployment's job (declared SEAM in witness_sink.ts).
     */
    private readonly witnessSink?: WitnessSink,
  ) {}

  /** Whether the backing store promises fsync-durable appends. Consequential effects must require true. */
  durableStorage(): boolean { return this.store.durable === true; }

  /** Reconfirm visible bytes after an uncertain append. Use inside withStableEventView
   * when making a read/deduplicate decision; absence of this capability is not success. */
  confirmEventDurability(): void {
    if (this.store.durable !== true || this.store.confirmEventDurability === undefined) throw new Error("spine cannot confirm event durability");
    this.store.confirmEventDurability();
  }

  /**
   * Coordinate a higher-level transaction with the same deployment lock domain as sealing. Callers must use a
   * distinct key and may invoke `seal()` while holding it; the fixed order is transaction key -> `spine.sealer`.
   */
  withCoordinationLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    if (key === "spine.sealer") throw new Error("higher-level coordination cannot acquire the sealer key recursively");
    return this.lock.withLock(key, fn);
  }

  /** Short synchronous read/append decision, serialized with sealers and other such decisions.
   * Moving staging into the chain cannot hide an event between the two reads. Do not
   * dispatch work, await effects, or recursively seal while holding this view. */
  withStableEventView<T>(fn: (events: readonly StagedEvent[]) => T): Promise<T> {
    return this.lock.withLock("spine.sealer", async () => fn(this.currentEvents()));
  }

  /** Finish the second half of an interrupted block->cursor transaction before producing another block. */
  private recoverCommittedStagingPrefix(staged: readonly StagedEvent[], last: SealedBlock | undefined): number {
    if (!last || staged.length === 0) return 0;
    // A checkpoint marker is synthesized by seal/checkpoint and is absent from staging, but a caller is also
    // allowed to stage an ordinary event whose type happens to be "checkpoint". Never infer provenance from type.
    // Consume only the longest exact staged prefix that is already present at the block head; the unmatched suffix
    // must be zero or one synthesized marker. This makes block->cursor crash recovery identity-based.
    let matched = 0;
    while (matched < staged.length && matched < last.events.length &&
      JSON.stringify(last.events[matched]) === JSON.stringify(staged[matched])) matched += 1;
    if (matched === 0 || last.events.length - matched > 1) return 0;
    this.store.removeStaged(matched);
    return matched;
  }

  /** Stage an event (concurrent-safe). Returns the assigned event id. */
  stage(input: StageInput): string {
    let canonicalPayload: string;
    try { canonicalPayload = canonicalize(input.payload); }
    catch (error) { throw new Error("spine event payload is not canonically serializable", { cause: error }); }
    if (typeof canonicalPayload !== "string") throw new Error("spine event payload is not canonically serializable");
    if (Buffer.byteLength(canonicalPayload, "utf8") > 1024 * 1024) throw new Error("spine event payload exceeds the 1 MiB canonical bound");
    const e: StagedEvent = {
      id: randomUUID(),
      schemaVersion: CURRENT_SCHEMA_VERSION,
      type: input.type,
      ts: this.clock(),
      actor: input.actor,
      payload: input.payload,
    };
    this.store.appendStaged(e);
    return e.id;
  }

  /**
   * Seal all currently-staged events into a single new block, under the sealer
   * lock. Returns the sealed block, or undefined if there was nothing to seal.
   */
  async seal(): Promise<SealedBlock | undefined> {
    return this.lock.withLock("spine.sealer", async () => {
      let staged = this.store.readStaged();
      let prev = this.store.lastBlock();
      if (this.recoverCommittedStagingPrefix(staged, prev) > 0) staged = this.store.readStaged();
      if (staged.length === 0) return undefined;
      prev = this.store.lastBlock();
      const block = sealBlock(prev, staged, this.clock());
      this.store.appendBlock(block);
      this.store.removeStaged(staged.length);
      // L4: publish the new head to the independent witness so truncation/fork are detectable.
      if (this.witnessSink) this.emitWitness(this.witnessSink);
      return block;
    });
  }

  /**
   * Emit a checkpoint block (Round 13). It seals any pending events plus a
   * checkpoint marker event attesting the cumulative root, bounding the active
   * chain. Runs under the sealer lock.
   */
  async checkpoint(actor: string): Promise<SealedBlock> {
    return this.lock.withLock("spine.sealer", async () => {
      let prev = this.store.lastBlock();
      const priorRoot = prev ? prev.cumulativeRoot : "0".repeat(64);
      let staged = this.store.readStaged();
      if (this.recoverCommittedStagingPrefix(staged, prev) > 0) staged = this.store.readStaged();
      prev = this.store.lastBlock();
      const marker: StagedEvent = {
        id: randomUUID(),
        schemaVersion: CURRENT_SCHEMA_VERSION,
        type: "checkpoint" satisfies EventType,
        ts: this.clock(),
        actor,
        payload: { attestsRootUpTo: priorRoot },
      };
      const events = [...staged, marker];
      const block = sealBlock(prev, events, this.clock());
      this.store.appendBlock(block);
      this.store.removeStaged(staged.length);
      // L4: witness the checkpoint head to the independent sink (same as seal()).
      if (this.witnessSink) this.emitWitness(this.witnessSink);
      return block;
    });
  }

  /**
   * Append a restoration-attestation (Round 17). After a PITR restore, this
   * operator-signed event declares the authorized fork so it reconciles with the
   * external anchor instead of reading as tampering.
   */
  attestRestoration(params: {
    operator: string;
    restoredToSeq: number;
    priorWitnessedHash: string;
    signature: string;
  }): string {
    return this.stage({
      type: "restoration.attestation",
      actor: params.operator,
      payload: {
        restoredToSeq: params.restoredToSeq,
        priorWitnessedHash: params.priorWitnessedHash,
        signature: params.signature,
      },
    });
  }

  /** Verify the sealed chain end-to-end (tamper-evidence check). */
  verify(): VerifyResult {
    return verifyChain(this.store.readBlocks());
  }

  /** Verify and replay one immutable block snapshot, avoiding a second full store read between the two claims. */
  verifiedReplay(): { readonly verification: VerifyResult; readonly events: readonly StagedEvent[] } {
    const blocks = this.store.readBlocks();
    const verification = verifyChain(blocks);
    if (!verification.ok) return Object.freeze({ verification, events: Object.freeze([]) });
    const events: StagedEvent[] = [];
    for (const block of blocks) for (const event of block.events) events.push(this.registry.upcast(event));
    return Object.freeze({ verification, events: Object.freeze(events) });
  }

  /**
   * Produce an external witness pinning the current chain head (Build Step 1 —
   * hardening the spine root). Publish this to an independent store/replica; a
   * later `checkAgainstWitness` then detects truncation/rollback or forking of
   * the local chain that `verify()` alone cannot see. Undefined for an empty chain.
   */
  witnessHead(): ChainWitness | undefined {
    return makeWitness(this.store.readBlocks());
  }

  /**
   * Check the local chain against an independently-held witness: detects internal
   * tampering, truncation/rollback, and forking. This is the tamper-evidence that
   * survives an adversary with write access to the local chain file, because the
   * reference lives elsewhere.
   */
  checkAgainstWitness(witness: ChainWitness): WitnessCheck {
    return verifyAgainstWitness(this.store.readBlocks(), witness);
  }

  /**
   * Emit the current head witness to an independent sink (the LIVE anchor). Call
   * after seal/checkpoint so the sink accumulates a published trail the chain can be
   * reconciled against. No-op on an empty chain.
   */
  emitWitness(sink: WitnessSink): ChainWitness | undefined {
    const w = makeWitness(this.store.readBlocks());
    if (w) sink.publish(w);
    return w;
  }

  /** Seal pending events, then emit the resulting head witness. Returns both. */
  async sealAndWitness(sink: WitnessSink): Promise<{ block?: SealedBlock; witness?: ChainWitness }> {
    const block = await this.seal();
    const witness = this.emitWitness(sink);
    return { ...(block ? { block } : {}), ...(witness ? { witness } : {}) };
  }

  /**
   * Reconcile the local chain against the sink's latest published witness: consistent
   * forward-extension, authorized-restore (a signed attestation references the
   * witnessed hash), or tamper (unattested fork/truncation). If the sink has no
   * witness yet, there is nothing to reconcile against ("consistent" by absence).
   */
  reconcileAgainst(sink: WitnessSink): ReconcileVerdict {
    const witness = sink.latest();
    if (!witness) return { status: "consistent" };
    const attestations = extractAttestations(this.replay());
    return reconcileWithWitness(this.store.readBlocks(), witness, attestations);
  }

  /**
   * Replay all sealed events in order, upcast to the current schema version
   * (Round 18). This is how derived projections (memory, graph) are
   * deterministically rebuilt from the source-of-truth chain (CQRS / DR replay).
   */
  replay(): StagedEvent[] {
    const out: StagedEvent[] = [];
    for (const block of this.store.readBlocks()) {
      for (const e of block.events) {
        out.push(this.registry.upcast(e));
      }
    }
    return out;
  }

  /**
   * Staged-but-not-yet-sealed events, upcast to the current schema version. These
   * are durable (persisted to the staging store) but not yet in the hash-chain.
   * Derived readers that must reflect the COMPLETE current state (e.g. an auditor
   * asking for the governance trail on demand) use replay() + pending() so the
   * trail has no gap between staging and the next seal.
   */
  pending(): StagedEvent[] {
    return this.store.readStaged().map((e) => this.registry.upcast(e));
  }

  /** The complete current event view: sealed (source of truth) then pending. */
  currentEvents(): StagedEvent[] {
    return [...this.replay(), ...this.pending()];
  }
}
