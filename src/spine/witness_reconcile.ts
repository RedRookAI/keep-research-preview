/**
 * Witness reconcile (Build Step 1 — the live anchor's decision rule).
 *
 * Given a local chain and the last INDEPENDENTLY-PUBLISHED witness, decide whether
 * the chain is a legitimate forward extension, an AUTHORIZED restore, or TAMPER.
 *
 * The rule unifies two field-tested disciplines:
 *  - tlog-witness (C2SP / RFC 6962): a new checkpoint is trusted only if it is a
 *    consistent forward extension of the last witnessed one; a same-seq-different-root
 *    (fork) or a non-consistent state (truncation) is misbehavior.
 *  - double-entry bookkeeping: you NEVER alter a posted entry; a correction is a NEW
 *    reversing entry that REFERENCES the original and is authorized. So a legitimate
 *    history fork must be an append-only, signed `restoration.attestation` that
 *    references the superseded witnessed hash. Anything else is fraud.
 */

import { createHash } from "node:crypto";
import type { SealedBlock, ChainWitness } from "./hashchain.js";
import { verifyAgainstWitness, verifyChain } from "./hashchain.js";
import { canonicalize } from "./event.js";
import type { StagedEvent } from "./event.js";
import { restorationSignatureValid } from "../tcb/attestation.js";

/**
 * A digest that BINDS the exact restored content (BUILD-ORDER 8.44A-FIX). A restoration authorization
 * must sign over WHAT it restores, not merely the seq it restores TO — otherwise one valid authorization
 * transfers to any fork sharing that seq + superseded witness hash (the cross-family veto, GPT-5.6). This
 * folds every restored block's `{seq, hash}` in order; each block hash already commits to that block's
 * events / prevHash / cumulativeRoot, so this digest pins the WHOLE restored chain. A different fork —
 * even one sharing the head seq and the superseded witness hash — yields a DIFFERENT digest, so an
 * authorization minted for restore A does not verify for fork B.
 */
export function restoredContentDigest(blocks: readonly SealedBlock[]): string {
  return createHash("sha256")
    .update(canonicalize(blocks.map((b) => ({ seq: b.seq, hash: b.hash }))), "utf8")
    .digest("hex");
}

export type ReconcileVerdict =
  | { readonly status: "consistent" }
  // `blocks` is the VERIFIED, owned-plain-data snapshot the authorization was checked against. The live restore
  // wiring (8.44A-WIRE) MUST restore from THESE blocks, never the caller's original (possibly proxy) input — the
  // returned artifact is exactly the artifact that was verified (closes the cross-boundary check-use gap, GPT-5.6).
  | { readonly status: "authorized-restore"; readonly attestation: RestorationRef; readonly blocks: readonly SealedBlock[] }
  | { readonly status: "tamper"; readonly kind: "fork" | "truncation"; readonly reason: string };

/** A restoration attestation extracted from the chain (the reversing-entry). */
export interface RestorationRef {
  readonly restoredToSeq: number;
  readonly priorWitnessedHash: string;
  /**
   * BINDS the restored content (BUILD-ORDER 8.44A-FIX): the digest of the ACTUAL restored blocks the
   * authorization was signed over. reconcile re-computes the digest of the SUPPLIED blocks and refuses
   * the authorization unless it matches — so an authorization minted for restore A does NOT verify for a
   * different fork B that merely shares the seq + superseded witness hash. An empty digest never binds.
   */
  readonly contentDigest: string;
  readonly signature: string;
  /**
   * Anti-replay binding (BUILD-ORDER 8.44A): a per-authorization nonce, signed together with the
   * rest of the restore. A captured VALID signature carries its own nonce; once that nonce has
   * authorized a restore it cannot authorize a second — so a legitimately-signed authorization
   * cannot be replayed to re-bless a DIFFERENT later fork. An empty nonce never authorizes.
   */
  readonly nonce: string;
}

/** Extract restoration attestations from replayed chain events. */
export function extractAttestations(events: readonly StagedEvent[]): RestorationRef[] {
  const out: RestorationRef[] = [];
  for (const e of events) {
    if (e.type === "restoration.attestation") {
      const p = e.payload as Partial<RestorationRef>;
      if (typeof p.priorWitnessedHash === "string" && typeof p.restoredToSeq === "number") {
        out.push({
          restoredToSeq: p.restoredToSeq,
          priorWitnessedHash: p.priorWitnessedHash,
          contentDigest: typeof p.contentDigest === "string" ? p.contentDigest : "",
          signature: typeof p.signature === "string" ? p.signature : "",
          nonce: typeof p.nonce === "string" ? p.nonce : "",
        });
      }
    }
  }
  return out;
}

/**
 * A monotone record of restoration nonces already honored, so a captured valid authorization is
 * single-use (replay resistance). `remember` is called ONLY when a signature verifies and the restore
 * is accepted, so a rejected attestation never consumes a nonce.
 */
export interface ReplayGuard {
  seen(nonce: string): boolean;
  remember(nonce: string): void;
  /**
   * ATOMIC check-and-consume (BUILD-ORDER 8.44A-FIX6, GPT-5.6): consume `nonce` and return true iff it was not
   * already seen. Separate `seen()`+`remember()` leaves a check-use window in which a re-entrant/concurrent caller
   * could honor the same nonce twice; `consumeIfUnseen` closes it in one indivisible step at the accept point.
   */
  consumeIfUnseen(nonce: string): boolean;
}

/**
 * In-memory replay guard — the run-local default. A durable deployment persists the seen-set alongside
 * the chain so the anti-replay window survives a restart (the honest persistence SEAM); the in-memory
 * form is correct within a run and is what the tests exercise deterministically.
 */
export class SeenNonceGuard implements ReplayGuard {
  private readonly seenSet = new Set<string>();
  seen(nonce: string): boolean {
    return this.seenSet.has(nonce);
  }
  /** Atomic: add + report whether it was newly added (false ⇒ already consumed). Single indivisible op. */
  consumeIfUnseen(nonce: string): boolean {
    if (this.seenSet.has(nonce)) return false;
    this.seenSet.add(nonce);
    return true;
  }
  remember(nonce: string): void {
    this.seenSet.add(nonce);
  }
}

/**
 * What authorizes a restore: the ENROLLED verification key + a replay guard. If a reconcile is called
 * WITHOUT a verifier, NO restore can be cryptographically authorized — the divergence stays TAMPER
 * (fail-closed). This is the object the live boot-reconcile must thread the enrolled key through.
 */
export interface RestorationVerifier {
  readonly key: Buffer;
  readonly replay: ReplayGuard;
}

/**
 * Reconcile a chain against its last published witness.
 *
 * - Forward extension (chain still contains the witnessed block unchanged) → consistent.
 * - Otherwise (fork or truncation) → TAMPER, UNLESS an attestation references the
 *   witnessed head hash (an authorized, append-only correction) → authorized-restore.
 *
 * HONESTY (BUILD-ORDER 8.44A / 8.44A-FIX): the link (an attestation referencing the superseded witnessed
 * hash) is necessary but NOT sufficient. A restore is authorized only if a `RestorationVerifier` is
 * supplied AND the attestation BINDS THE SUPPLIED CONTENT (its `contentDigest` reproduces the digest of
 * these `blocks`, and `restoredToSeq` is the head seq of these `blocks`) AND its signature
 * CRYPTOGRAPHICALLY VERIFIES against the enrolled key over the canonical restore bytes AND its nonce has
 * not already been consumed. Without a verifier, or on any content/seq mismatch / failed verification /
 * replayed nonce, the divergence stays TAMPER (fail-closed) — an authorization minted for a DIFFERENT
 * fork, a well-formed-but-bogus signature, or a replayed valid one, authorizes NOTHING. Verifying against
 * an asymmetric OPERATOR key held off-box is the LOAD-BEARING 8.R0 key-custody SEAM (a compromised box can
 * read a same-box symmetric key and mint a correctly-bound authorization); against the enrolled symmetric
 * run key it is TRUE on-box but binding alone does not defeat a compromised box.
 */
/**
 * Recursively normalize a value into OWNED, PLAIN, JSON-shaped data (BUILD-ORDER 8.44A-FIX7, GPT-5.6). Reads each
 * own enumerable property EXACTLY ONCE (defeats getter/Proxy check-use) and does NOT honor `toJSON`. REJECTS any
 * non-plain value — Date/Map/Set/SharedArrayBuffer/TypedArray/functions/symbols/bigint/class instances — by throwing,
 * because `structuredClone` preserves such exotics and `Object.freeze` cannot make their internal bytes/state
 * immutable (a SharedArrayBuffer stays concurrently mutable after the snapshot). Only after this can `deepFreeze`
 * guarantee end-to-end immutability of the verified artifact. Restore inputs are persisted JSON, so legitimate
 * blocks/witness/attestations are always plain data; anything else is an attack surface and is refused fail-closed.
 */
function normalizePlainData<T>(value: T): T {
  const norm = (v: unknown): unknown => {
    if (v === null) return null;
    const t = typeof v;
    if (t === "string" || t === "number" || t === "boolean") return v;
    if (Array.isArray(v)) return v.map(norm);
    if (t === "object") {
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new Error("non-plain object in restore input");
      const out: Record<string, unknown> = {};
      // Use defineProperty, not `out[k] = …` (8.44A-FIX8, GPT-5.6): a `"__proto__"` key assigned via `out[k]` would
      // set the object's PROTOTYPE (prototype pollution) rather than an own data property, leaving a mutable proto
      // that reopens the check-use gap. defineProperty makes EVERY key — including `__proto__` — an own data property.
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        Object.defineProperty(out, k, { value: norm(val), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    throw new Error(`non-plain-data value in restore input (${t})`);
  };
  return norm(value) as T;
}

/** Recursively `Object.freeze` an object graph so a verified snapshot cannot be mutated after the fact. */
function deepFreeze<T>(o: T): T {
  if (o !== null && typeof o === "object" && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o as Record<string, unknown>)) deepFreeze(v);
  }
  return o;
}

export function reconcileWithWitness(
  blocks: readonly SealedBlock[],
  witness: ChainWitness,
  attestations: readonly RestorationRef[],
  verifier?: RestorationVerifier,
): ReconcileVerdict {
  // SNAPSHOT the attacker-supplied inputs into OWNED PLAIN DATA once, up front (BUILD-ORDER 8.44A-FIX3/FIX4,
  // cross-family findings GPT-5.6): `blocks`/`attestations` are only COMPILE-TIME readonly — a caller could pass
  // getter/Proxy-backed objects whose fields return DIFFERENT values on successive reads, so the value
  // `verifyChain` validated could differ from the one `restoredContentDigest` folds or the signature covers (a
  // check-use / TOCTOU differential that would let an authorization for fork A bless fork B). `structuredClone`
  // reads each own property EXACTLY ONCE into owned plain data and — unlike `JSON.stringify` — does NOT honour a
  // malicious `toJSON` (which could present benign bytes to verification while the live object differs). The
  // verified `snap` is what we then verify AND what the accepted verdict RETURNS, so the caller restores exactly
  // what was verified, never the original mutable reference (FIX4: the returned artifact IS the verified artifact).
  // Snapshot EVERY attacker-reachable input (blocks, witness, attestations) — not just blocks. `verifyAgainstWitness`
  // reads witness.{seq,cumulativeRoot,headHash} internally while the authorization-binding check reads the witness
  // head hash separately, so a getter-backed witness could present one identity to the divergence check and another
  // to the binding check (8.44A-FIX5, GPT-5.6). Freezing all three inputs to owned plain data once means every read
  // below — divergence, internal validity, digest, binding, signature, and the returned artifact — observes ONE
  // consistent value. This closes the whole external-object check-use class, not one input at a time.
  // Deep-FREEZE the block snapshot (8.44A-FIX6, GPT-5.6): structuredClone owns the data but leaves it mutable, so
  // the returned `blocks` could be altered AFTER verification and BEFORE the caller restores from it — reopening a
  // check-use gap at the boundary. Freezing the whole graph makes the verified artifact immutable end-to-end.
  let snap: SealedBlock[], w: ChainWitness, atts: RestorationRef[];
  try {
    snap = deepFreeze(normalizePlainData(blocks)) as SealedBlock[];
    w = normalizePlainData(witness) as ChainWitness;
    atts = normalizePlainData(attestations) as RestorationRef[];
  } catch {
    // Any non-plain-data input (exotic/mutable-after-freeze value, e.g. a SharedArrayBuffer in an event payload)
    // is refused fail-closed — a restore is authorized only over normalized, immutable, plain data.
    return { status: "tamper", kind: "fork", reason: "restore inputs contain non-plain-data — refused" };
  }
  const witnessHeadHash = w.headHash;
  const check = verifyAgainstWitness(snap, w);
  if (check.ok) return { status: "consistent" };

  // Not a forward extension. Authorize a restore ONLY if the attestation (a) references the superseded
  // witnessed head, (b) BINDS the supplied content — its contentDigest reproduces the digest of THESE
  // blocks AND restoredToSeq is the head seq of THESE blocks (so an authorization minted for a different
  // fork cannot transfer here), (c) carries a nonce that has NOT been seen (anti-replay), and (d) whose
  // signature VERIFIES against the enrolled key over the canonical restore bytes (which INCLUDE the
  // contentDigest). Fail-closed: no verifier, a content/seq mismatch, an unverifiable signature, or a
  // replayed nonce ⇒ the divergence stays TAMPER. A signature is CHECKED, never merely counted, and it
  // authorizes exactly the content it signed, never a fork that merely shares the seq + witness hash.
  // INTERNAL VALIDITY IS A PRECONDITION OF ANY RESTORE (BUILD-ORDER 8.44A-FIX2, cross-family veto): the restore
  // branch runs BECAUSE `verifyAgainstWitness` failed — but that failure conflates "internally-invalid blocks"
  // with "a valid chain that forks from the old witness". Only the latter can ever be an authorized restore.
  // Without this guard, an attacker supplies INTERNALLY-INVALID blocks whose `hash` FIELDS are pasted from a real
  // fork A (so `restoredContentDigest`, which folds those hashes, reproduces A's contentDigest and A's genuine
  // authorization verifies) while the actual block CONTENT is attacker-chosen — the content-binding is defeated
  // because nothing forced `b.hash` to equal the recompute of `b`'s content. `verifyChain` re-derives every block
  // hash from its own content and confirms the prev-linkage + cumulative-root fold, so requiring it here makes each
  // `b.hash` AUTHENTIC — and therefore `restoredContentDigest` genuinely binds the restored CONTENT, not claimed
  // metadata. Internally-invalid blocks can NEVER be an authorized restore; they fall through to TAMPER (fail-closed).
  if (verifier && verifyChain(snap).ok) {
    const head = snap.length > 0 ? snap[snap.length - 1]! : undefined;
    const suppliedDigest = restoredContentDigest(snap);
    for (const aRaw of atts) {
      // Skip a null/non-object array element (8.44A-FIX9, Fable): reading a field off `null` would throw uncaught;
      // an ill-shaped attestation authorizes nothing, so drop it and continue (fail-closed, never a crash).
      if (aRaw === null || typeof aRaw !== "object") continue;
      // Read each authorization field EXACTLY ONCE into a local (8.44A-FIX3): no getter/Proxy can then return one
      // value to a correspondence check and a different value to the signature verification. Every check below and
      // the signed `fields` and the returned attestation all use these frozen locals, never `aRaw` re-reads.
      const restoredToSeq = aRaw.restoredToSeq;
      const priorWitnessedHash = String(aRaw.priorWitnessedHash);
      const contentDigest = String(aRaw.contentDigest);
      const nonce = String(aRaw.nonce);
      const signature = String(aRaw.signature);
      if (priorWitnessedHash !== witnessHeadHash) continue;
      // BIND THE RESTORE: the authorization must be for exactly THIS restored content and seq.
      if (contentDigest.length === 0 || contentDigest !== suppliedDigest) continue;
      if (head === undefined || restoredToSeq !== head.seq) continue;
      if (nonce.length === 0 || verifier.replay.seen(nonce)) continue;
      const fields = { restoredToSeq, priorWitnessedHash, contentDigest, nonce };
      if (!restorationSignatureValid(verifier.key, fields, signature)) continue;
      // ATOMIC consume at the accept point (8.44A-FIX6): a valid signature + a nonce not-yet-consumed. If a
      // re-entrant/concurrent caller consumed it between the early `seen` fast-check and here, this returns false
      // and we reject — the nonce is honored at most once. Consumed ONLY on a verified signature (no DoS: a bogus
      // signature never burns a nonce, since we reach here only after `restorationSignatureValid`).
      if (!verifier.replay.consumeIfUnseen(nonce)) continue;
      // Return the FROZEN fields AND the VERIFIED snapshot blocks, never the mutable `aRaw`/original `blocks`, so
      // the verdict carries exactly what was verified and the caller restores THAT (8.44A-FIX4).
      return { status: "authorized-restore", attestation: { restoredToSeq, priorWitnessedHash, contentDigest, nonce, signature }, blocks: snap };
    }
  }

  // Classify the tamper for the record (truncation vs fork), from the witness check.
  const kind: "fork" | "truncation" = /truncation|rollback/.test(check.reason ?? "")
    ? "truncation"
    : "fork";
  return { status: "tamper", kind, reason: check.reason ?? "diverges from witness" };
}
