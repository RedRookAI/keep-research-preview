/**
 * EFFECT BROKER KERNEL (Mechanical-Enforcement Increment 9).
 *
 * The frontier property (one sentence): a real side-effecting operation runs ONLY as the second half of an atomic
 * permit-redemption → dispatch transaction — the broker maps the requested OPERATION to the RIGHT it requires (a sealed
 * per-family operation allowlist), single-use REDEEMS a monitor-minted permit (Increment 7) bound to this exact
 * subject/session/effect/object AND that required right and this family's audience, and ONLY THEN invokes the ONE
 * closed-world executor that owns the family, passing it the AUTHORIZED (effect, object, operation, right) — so the
 * action performed is mechanically the action authorized. Every path is audited fail-closed; there is no generic
 * "execute" escape hatch. If redemption fails, or the operation is not declared, nothing is dispatched.
 *
 * Why the operation is bound to the right (the keystone): a caller does NOT supply the "right" — the broker DERIVES it
 * from the operation via the sealed allowlist, so a `delete` operation requires the `delete` right and a permit that
 * grants only `read` cannot drive a delete (redemption fails). The executor receives the authorized object + operation,
 * not free-form caller args as its target — binding to the EXACT resolved runtime object (TOCTOU-safe) is Increment 11.
 *
 * Closed-world executors (Increment 4). Sealed against the signed effect manifest: exactly one executor per DECLARED
 * family, plus a per-family audience that MUST be UNIQUE (so a permit's audience maps to exactly one family — no
 * family-swap via a shared audience) and a per-family operation→right allowlist (so an undeclared operation is denied).
 *
 * Atomic transaction (fail-closed transactional outbox): INTENT → redeem (atomic single-use, on the SHARED injected
 * ledger) → REDEEMED → DISPATCH record → executor (raced against a caller AbortSignal; result sanitized to inert,
 * deeply-frozen canonical data) → RESULT. Every pre-effect record is written BEFORE the effect and a write failure
 * ABORTS (no effect) — a broken audit sink cannot let an unrecorded effect proceed. A repeated FULL-OPERATION
 * idempotency key (session+key+family+effect+object+operation+argsDigest+subject) is served single-flight from the
 * recorded result WITHOUT re-dispatching (exactly-once effect under safe retries + concurrency); it never re-authorizes
 * a DIFFERENT operation (a different op ⇒ a different key). A dispatch that throws spends the single-use permit.
 *
 * Trusted, sealed deployment config (NOT attacker input — the workload controls none of it): the per-family bindings —
 * the executor, its unique audience, and the OPERATION→REQUIRED-RIGHT allowlist — are provided at construction alongside
 * the signed manifest, exactly as Increment 8's issuance policy is. The operation→right map is the same trust level as
 * that policy (a mis-mapping is an operator error, not an attacker bypass); authenticating it inside the SIGNED effect
 * manifest is a possible Increment-4 strengthening. The SHARED RedemptionLedger and the idempotency store are the
 * deployment's SINGLE stores; a multi-process deployment replaces the in-memory reference impls with durable, compare-and-
 * swap-backed stores behind the same interfaces — the ledger's, and the IdempotencyStore's atomic insert-if-absent
 * `reserve` (the documented persistence seam, as in Increment 7). TRUST BOUNDARY, stated precisely (the store is trusted
 * sealed config, but the broker minimizes what it must trust): the AUTHORITY CEILING — no effect without an exactly-
 * authorized, single-use REDEEMED permit — holds against ANY store behaviour, because the ledger, not the store, gates
 * redemption; a Byzantine store can at worst re-drive an identical idempotency identity up to the permit's authorized
 * REDEMPTION BUDGET (exactly-once dedup for budgets > 1 trusts the store's atomic CAS — it cannot be enforced from the
 * store's return values alone), never beyond it, and never an UNAUTHORIZED effect. CONFIDENTIALITY of a cached replay does
 * NOT trust the store: every stored result carries a broker-keyed BINDING to its full idempotency identity + output
 * (Sealed), re-derived and constant-time-verified before disclosure, so the store cannot substitute another operation's
 * output (cross-key disclosure) or synthesize a success. TOTALITY does not trust the store: a store that throws, returns a
 * malformed/hostile value, or violates the reservation-ownership invariant yields a FAIL-CLOSED DENY (never a rejected
 * dispatch) and never strands the broker's OWN deferred (`mine`). LIVENESS of the replay WAIT is bounded exactly like the
 * executor wait: a store that hands back a NEVER-SETTLING entry is the SAME documented residual as a never-settling
 * executor — a caller deadline via the AbortSignal bounds it to a `{ok:false}`; with NO signal it is the accepted liveness
 * residual (still never an unauthorized effect or a disclosure). This presumes trusted-config CALLS terminate by returning
 * or throwing: a SYNCHRONOUSLY non-terminating store method or getter (reserve/release, or a fresh/entry/then getter that
 * never returns) — like a non-terminating injected callback, already out of scope in the monitor threat model — cannot be
 * preempted on JS's single thread, so the AbortSignal bounds only ASYNC waits; a synchronously-diverging trusted component
 * is the documented residual. An executor MUST NOT synchronously await a `dispatch` for its OWN operation
 * identity (a self-cycle would deadlock — a programming error at the executor boundary; the reservation still prevents
 * any double-execution within the authorized budget).
 *
 * Defers (honest): the executor holds RAW host authority — physically removing every ambient effect path so the broker
 * is the ONLY route to one is Increment 10; binding to the EXACT resolved object is Increment 11; ingress→effect
 * causality is Increment 12. `now`/`currentEpoch` are the trusted monitor's clock/epoch; the AuditSink, the shared
 * RedemptionLedger + idempotency store, the PermitKey, and the per-family executors (which must be the manifest-declared
 * owner modules — an attestation seam completed at Incr 10) are trusted broker-internal. A never-settling executor with
 * no AbortSignal — OR a Byzantine store that hands back a never-settling replay ENTRY — is the documented out-of-scope
 * LIVENESS residual; a caller deadline via the signal bounds either to `{ok:false}`, and neither is an unauthorized effect
 * or a disclosure. Likewise an executor that registers a THROWING abort listener on the broker's cancellation controller can
 * raise `uncaughtException` (Node EventTarget semantics — the throw does not propagate through `abort()`, and the
 * broker's own result still resolves fail-closed); that is the same trusted-executor residual, not a broker bypass.
 *
 * Grounding: transactional outbox; capability invocation (authority is the redeemed permit, never ambient); reference-
 * monitor complete mediation; structured effect systems (one owner + a declared operation set per effect family).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { eirDigest, encodeCanonical, decodeCanonical, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { redeem, type RedemptionLedger } from "../permit/ledger.js";
import { verify as verifyPermit, type Permit, type PermitKey, type RedeemContext } from "../permit/permit.js";
import { verifyEffectManifest, type SignedEffectManifest } from "../effect/effect_manifest.js";
import { isEffectFamily, type EffectFamily } from "../effect/effect.js";
import type { SignedBundle } from "../policy/compiler.js";
import type { TrustPolicy } from "../bom/bom_signing.js";
import { intentEntryHash, type DurableWitness, type WitnessIntent, type CausalRef, type ExecutionBindingKind } from "../witness/pre_effect_witness.js";

export const BROKER = { name: "keep.effect.broker", version: "9.0.0" } as const;

// CAPTURED PLATFORM INTRINSICS. A caller-supplied AbortSignal is a genuine instance (brand-checked), but an EXTENSIBLE
// instance can shadow `addEventListener`/`removeEventListener`/`aborted` with own no-op/synchronously-firing/throwing
// properties. We therefore never call those THROUGH the object — we invoke the captured platform methods/getter against
// it, so shadowing cannot defeat the deadline wiring. A non-signal (or prototype-forged instance without the internal
// slot) makes these throw "Illegal invocation", which every call site treats as fail-closed. (Same primordial-capture
// discipline as permit.ts.) Captured once at module load, before any workload code could tamper with the prototypes.
const _AbortSignal: typeof AbortSignal | undefined = typeof AbortSignal !== "undefined" ? AbortSignal : undefined;
const _abortedGetter: ((this: AbortSignal) => boolean) | undefined =
  _AbortSignal !== undefined ? (Object.getOwnPropertyDescriptor(_AbortSignal.prototype, "aborted")?.get as ((this: AbortSignal) => boolean) | undefined) : undefined;
const _addListener: typeof EventTarget.prototype.addEventListener | undefined =
  typeof EventTarget !== "undefined" ? EventTarget.prototype.addEventListener : undefined;
const _removeListener: typeof EventTarget.prototype.removeEventListener | undefined =
  typeof EventTarget !== "undefined" ? EventTarget.prototype.removeEventListener : undefined;
// The broker's OWN cancellation controller is likewise captured: workload code could replace `globalThis.AbortController`
// after module load with one whose `abort()` is a no-op, so a compliant executor observing the broker-supplied signal
// would never be cancelled past the deadline. We construct via the captured constructor and invoke the captured `signal`
// getter + `abort` method via `.call`, so a replaced global cannot defeat executor cancellation.
const _AbortController: typeof AbortController | undefined = typeof AbortController !== "undefined" ? AbortController : undefined;
const _acSignalGetter: ((this: AbortController) => AbortSignal) | undefined =
  _AbortController !== undefined ? (Object.getOwnPropertyDescriptor(_AbortController.prototype, "signal")?.get as ((this: AbortController) => AbortSignal) | undefined) : undefined;
const _acAbort: ((this: AbortController) => void) | undefined = _AbortController !== undefined ? _AbortController.prototype.abort : undefined;
// `Promise` is captured too: the broker's OWN reservation deferred (`mine`) and race() must not become a hostile thenable
// (leaked resolver / lying waiters) if workload replaces `globalThis.Promise` after module load. Same discipline.
const _Promise: PromiseConstructor = Promise;
/** Brand check that can NEVER throw — a hostile Proxy with a throwing `getPrototypeOf` trap is simply "not a signal". */
function isRealAbortSignal(signal: unknown): boolean { try { return _AbortSignal !== undefined && signal instanceof _AbortSignal; } catch { return false; } }
/** A broker-owned cancellation handle built ENTIRELY from captured intrinsics — its `abort()` cannot be no-op'd by a
 * replaced global. Returns the real signal to hand the executor and a captured `abort` thunk to cancel it. */
function freshController(): { readonly signal: AbortSignal; readonly abort: () => void } {
  const c = new _AbortController!();
  const signal = _acSignalGetter!.call(c);
  return { signal, abort: (): void => { try { _acAbort!.call(c); } catch { /* best-effort cancel */ } } };
}

export class BrokerError extends Error {
  constructor(m: string) { super(`effect broker: ${m}`); this.name = "BrokerError"; }
}
/** Message from a thrown value, sanitized to bounded well-formed NFC text so it cannot break a content-addressed record. */
function safeText(e: unknown): string {
  let s: string; try { s = String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; }
  s = s.slice(0, 256);
  if (!isWellFormedText(s) || s.normalize("NFC") !== s) return "non-canonical-message"; // never let a bad string reach eirDigest
  return s.length === 0 ? "unknown" : s;
}
function deepFreeze<T>(o: T): T { if (o !== null && typeof o === "object") { for (const k of Object.keys(o)) deepFreeze((o as Record<string, unknown>)[k]); Object.freeze(o); } return o; }

/** The AUTHORIZED context handed to an executor: what was actually redeemed. The executor acts on `objectId` (the
 * authorized object; exact resolution is Increment 11) via `operation` (already right-checked). */
export interface Authorized { readonly effectId: string; readonly objectId: string; readonly operation: string; readonly right: string; }
/** An executor performs a family's raw effect on the AUTHORIZED object. Returns INERT canonical data (broker-sanitized).
 * The broker passes an AbortSignal for cancellation/timeout (the executor should observe it — a documented seam). */
export type Executor = (authz: Authorized, args: CanonicalValue, signal: AbortSignal) => CanonicalValue | Promise<CanonicalValue>;

/** RESOLVER-BOUND OBJECT ADAPTER (Mechanical-Enforcement Increment 11). For object-based effects (fs path, db row, …) the
 * caller's `objectId` is a DECOY — authorization must be over the EXACT object the effect acts on. An adapter PREPAREs the
 * target from the args (resolve-and-open under the family's symlink/traversal policy, sealing BOTH the target selector and
 * the payload into an opaque, adapter-private live HANDLE), returns its CANONICAL identity, and later executes THROUGH that
 * same handle (never re-resolving a name — TOCTOU-safe). The broker binds redemption + the idempotency key to the prepared
 * canonical id (NOT the caller's objectId), passes the executor ONLY the opaque prepared value (no target-bearing args), and
 * ALWAYS releases. Selected from the broker's CLOSED family registry — never caller-supplied. The OS-atomic open
 * (openat/O_NOFOLLOW/fd-identity) is the ADAPTER's verified seam; the broker enforces the SPINE. */
export interface PreparedTarget { readonly canonicalId: string; }
export interface ObjectAdapter {
  // prepare resolves+opens+seals the target. It MUST either RETURN a valid PreparedTarget or THROW — and if it throws (or
  // otherwise cannot return a valid handle) it MUST SELF-CLEAN any partial acquisition. The broker releases every handle
  // prepare RETURNS exactly once (on every path); it cannot release one it never received (a throwing/undefined prepare
  // is the adapter's own cleanup responsibility). No effect / no permit is spent when prepare throws.
  prepare(operation: string, args: CanonicalValue): PreparedTarget;
  execute(prepared: PreparedTarget, signal: AbortSignal): CanonicalValue | Promise<CanonicalValue>; // act via the sealed handle ONLY — no re-resolvable args
  release(prepared: PreparedTarget): void;                                          // cleanup; the broker calls it exactly once for every RETURNED handle
}

/** A per-family binding: EXACTLY ONE of {executor (plain, args-based — e.g. net egress), adapter (RESOLVER-BOUND, Incr 11 —
 * object-based effects)}, plus the audience a permit must carry and the declared operations → required right. */
export interface FamilyBinding { readonly executor?: Executor; readonly adapter?: ObjectAdapter; readonly audience: string; readonly operations: ReadonlyMap<string, string>; }

/** The broker-only audit writer. Every intent/decision/dispatch/result is written here; a write failure is fail-closed. */
export interface AuditSink { write(record: CanonicalValue): void; }

/** A request to perform an effect. The permit is the authority; the RIGHT is DERIVED from the operation, not supplied. */
export interface BrokerRequest {
  readonly permit: Permit;
  readonly subject: string;
  readonly session: string;
  readonly effectId: string;
  readonly objectId: string;
  readonly family: EffectFamily;
  readonly operation: string;
  readonly args: CanonicalValue;
  readonly idempotencyKey: string;
}
export type BrokerResult =
  | { readonly ok: true; readonly output: CanonicalValue; readonly auditId: string; readonly replayed: boolean; readonly resultAudited: boolean; readonly witnessEntry?: string }
  | { readonly ok: false; readonly reason: string; readonly auditId: string };

const isText = (s: unknown): s is string => typeof s === "string" && s.length > 0 && s.length <= (1 << 16) && isWellFormedText(s) && s.normalize("NFC") === s;

/** What the idempotency store actually holds for single-flight + idempotent replay: a completed result PLUS a broker-
 * authenticated BINDING to its full idempotency identity (idemKey) and output. The binding is an HMAC under a broker-only
 * key derived from the permit root, so a (Byzantine) store cannot substitute ANOTHER operation's result for this key, nor
 * synthesize a fake success, without detection — the broker re-derives and constant-time-compares the binding before it
 * discloses any cached output. Store implementations treat this value opaquely (persist + return it); they never mint it. */
export type Sealed = { readonly result: BrokerResult; readonly bind: string };
export type InFlight = Promise<Sealed>;
/** Lower-case-hex HMAC-SHA256 over domain-separated parts (0x1f unit separator). */
function macHex(key: string, ...parts: string[]): string { const h = createHmac("sha256", key); for (const p of parts) { h.update(p); h.update("\x1f"); } return h.digest("hex"); }
/** Constant-time comparison of two hex strings; false (never throws) on any length/shape mismatch. */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) return false;
  try { const ba = Buffer.from(a, "hex"), bb = Buffer.from(b, "hex"); return ba.length === bb.length && ba.length > 0 && timingSafeEqual(ba, bb); } catch { return false; }
}
/** The canonical projection a replay binding authenticates — EXCLUDES `replayed` (it flips on replay) and uses the output
 * DIGEST (stable under the inert re-copy), so the binding sealed at completion equals the one recomputed after
 * asBrokerResult normalization. */
function resultBindContent(r: BrokerResult): CanonicalValue {
  if (!r.ok) return { ok: false, auditId: r.auditId, reason: r.reason };
  const base = { ok: true, auditId: r.auditId, resultAudited: r.resultAudited, outputDigest: eirDigest("keep.broker.output/v1", r.output) };
  // Incr 12a: when the result was witnessed, BIND the receipt to the pre-effect intent entry (both directions — the
  // intent commits the effect-to-be, the receipt commits back to the intent). Presence-conditional so a pre-12a / no-
  // witness result yields byte-identical bind content to before (see #replayBind domain versioning) → v1 Sealeds in a
  // durable idempotency store still verify; a witnessed result binds under the v2 domain. No mixed-fleet flip-flop.
  return typeof r.witnessEntry === "string" ? { ...base, witnessEntry: r.witnessEntry } : base;
}
/** Defensively read a store-returned reservation value as {result, bind}: total (a hostile getter → null), normalizing
 * the result via asBrokerResult (inert output, replayed:true). The BINDING itself is verified by the broker (keyed). */
function asSealed(v: unknown): { readonly result: BrokerResult; readonly bind: string } | null {
  if (v === null || typeof v !== "object") return null;
  let rawResult: unknown, bind: unknown;
  try { rawResult = (v as { result?: unknown }).result; bind = (v as { bind?: unknown }).bind; } catch { return null; }
  if (typeof bind !== "string") return null;
  const result = asBrokerResult(rawResult);
  if (result === null) return null;
  return { result, bind };
}

/**
 * The deployment's single idempotency/single-flight store. `reserve` MUST be ATOMIC (insert-if-absent): if `key` is
 * absent it installs the CALLER-OWNED `entry` and returns {fresh:true, entry}; otherwise it returns {fresh:false, entry:
 * the existing one} without installing — never both an install and a miss for two concurrent callers. The CALLER (the
 * broker) owns `entry` and its resolver, so even a store that commits the reservation and THEN throws (or returns a
 * malformed value) can never strand waiters — the broker settles its own entry on every exit path. In-process, JS
 * run-to-completion makes the Map impl below atomic. A MULTI-PROCESS deployment supplies a durable, compare-and-swap-
 * backed implementation of THIS interface (the same persistence seam as the shared RedemptionLedger): it CAS-installs a
 * durable marker for `key` and, for a losing racer, returns a promise resolving to the winner's recorded result — so two
 * processes racing the same idempotency identity cannot both win and double-execute. `release` removes a reservation
 * ONLY if it is still the exact entry installed (a later reservation is never clobbered); it is called for PRE-EFFECT
 * retryable failures (and on the deny paths) so a subsequent attempt can proceed.
 */
export interface IdempotencyStore {
  reserve(key: string, entry: InFlight): { readonly entry: InFlight; readonly fresh: boolean };
  release(key: string, entry: InFlight): void;
}

/** The in-process reference IdempotencyStore (atomic by run-to-completion). A multi-process deployment replaces it with
 * a durable CAS-backed store implementing the same interface. Accepts an existing Map so callers can share raw state. */
export class MapIdempotencyStore implements IdempotencyStore {
  readonly #m: Map<string, InFlight>;
  constructor(backing?: Map<string, InFlight>) { this.#m = backing instanceof Map ? backing : new Map(); }
  reserve(key: string, entry: InFlight): { readonly entry: InFlight; readonly fresh: boolean } {
    const existing = this.#m.get(key);
    if (existing !== undefined) return { entry: existing, fresh: false };
    this.#m.set(key, entry);
    return { entry, fresh: true };
  }
  release(key: string, entry: InFlight): void { if (this.#m.get(key) === entry) this.#m.delete(key); }
}
/** A value is usable as an InFlight reservation iff it is thenable (a store must never hand back a non-awaitable entry). */
function isInFlight(v: unknown): v is InFlight { return v !== null && (typeof v === "object" || typeof v === "function") && typeof (v as { then?: unknown }).then === "function"; }
/** The validated, inert per-dispatch working set handed to #run. Exactly one of {executor, adapter+prepared} is set. */
interface RunArgs { permit: Permit; subject: string; session: string; effectId: string; objectId: string; family: EffectFamily; operation: string; right: string; argsCanon: CanonicalValue; argsDigest: string; audience: string; executor?: Executor | undefined; adapter?: ObjectAdapter | undefined; prepared?: PreparedTarget | undefined; idemKey: string; }

export class EffectBroker {
  readonly #executors: ReadonlyMap<EffectFamily, Executor>;
  readonly #adaptersOf: ReadonlyMap<EffectFamily, ObjectAdapter>; // Incr 11: RESOLVER-BOUND families (object-based effects)
  readonly #audienceOf: ReadonlyMap<EffectFamily, string>;
  readonly #opsOf: ReadonlyMap<EffectFamily, ReadonlyMap<string, string>>;
  readonly #trust: PermitKey;
  readonly #ledger: RedemptionLedger;            // SHARED, injected — single-use is global to the deployment's ledger
  readonly #idem: IdempotencyStore;              // full-op idempotency (INJECTED shared store: single-flight across instances/processes)
  readonly #audit: AuditSink;
  readonly #nonce: string;                        // per-instance nonce → audit ids unique across instances/restarts
  readonly #replayKey: string;                    // broker-only HMAC key for replay bindings (domain-separated from the permit root)
  readonly #witness?: DurableWitness;             // Incr 12a: pre-effect witness interlock (optional; absent ⇒ legacy behavior)
  #seq = 0n;

  constructor(manifest: SignedEffectManifest, policyBundle: SignedBundle, trust: { manifestTrust: TrustPolicy; policyTrust?: TrustPolicy }, permitKey: PermitKey, ledger: RedemptionLedger, idemStore: IdempotencyStore, bindings: ReadonlyMap<EffectFamily, FamilyBinding>, audit: AuditSink, brokerNonce: string, witness?: DurableWitness) {
    const v = verifyEffectManifest(manifest, policyBundle, trust);
    if (!v.valid) throw new BrokerError(`effect manifest does not verify: ${v.reason}`);
    const families = new Set(v.manifest.payload.declarations.map((d) => d.family));
    if (permitKey === null || typeof permitKey !== "object" || typeof permitKey.issuer !== "string" || typeof permitKey.rootKey !== "string") throw new BrokerError("a permit verification key is required");
    if (ledger === null || typeof ledger !== "object" || typeof (ledger as { tryConsume?: unknown }).tryConsume !== "function") throw new BrokerError("a shared RedemptionLedger is required");
    if (idemStore === null || typeof idemStore !== "object" || typeof idemStore.reserve !== "function" || typeof idemStore.release !== "function") throw new BrokerError("a shared IdempotencyStore (reserve/release) is required");
    if (audit === null || typeof audit !== "object" || typeof audit.write !== "function") throw new BrokerError("an audit sink is required");
    if (!(bindings instanceof Map)) throw new BrokerError("bindings must be a Map");
    if (!isText(brokerNonce)) throw new BrokerError("a per-instance brokerNonce is required");
    // Incr 12a: an OPTIONAL pre-effect witness. When present ALL FOUR methods must be functions — a malformed witness
    // is a construction error, never a silently-skipped interlock (a missing sealReceipt would otherwise be swallowed
    // post-effect, leaving every success a false crash orphan). Absent ⇒ byte-identical legacy behavior.
    if (witness !== undefined && !(witness !== null && typeof witness === "object" && typeof witness.sealIntent === "function" && typeof witness.sealReceipt === "function" && typeof witness.sealTerminal === "function" && typeof witness.observeReplay === "function")) throw new BrokerError("witness, if provided, must be a DurableWitness {sealIntent, sealReceipt, sealTerminal, observeReplay}");
    const ex = new Map<EffectFamily, Executor>(); const ad = new Map<EffectFamily, ObjectAdapter>(); const aud = new Map<EffectFamily, string>(); const ops = new Map<EffectFamily, ReadonlyMap<string, string>>();
    const audienceSeen = new Set<string>();
    for (const [fam, b] of bindings) {
      if (!isEffectFamily(fam)) throw new BrokerError(`binding for unknown family "${String(fam)}"`);
      if (!families.has(fam)) throw new BrokerError(`binding for family "${fam}" not declared in the manifest`);
      if (b === null || typeof b !== "object" || !isText(b.audience) || !(b.operations instanceof Map) || b.operations.size === 0) throw new BrokerError(`binding for "${fam}" must be {executor|adapter, audience, operations}`);
      // EXACTLY ONE of {executor, adapter} must be a PRESENT PROPERTY (Object.hasOwn — an explicit `executor: undefined`
      // alongside an adapter is ambiguous and rejected, not silently treated as adapter-only). hasOwn also ignores a
      // PROTOTYPE-inherited alternative, but that is inert here: only the own, validated member is copied into the ex/ad
      // family maps below and dispatch reads exclusively from those internal maps. Then the present one must be well-formed, so
      // `{adapter: valid, executor: 0}` / `{executor: valid, adapter: {}}` / `{adapter: null}` cannot slip through.
      const exPresent = Object.hasOwn(b, "executor");
      const adPresent = Object.hasOwn(b, "adapter");
      if (exPresent === adPresent) throw new BrokerError(`binding for "${fam}" must have EXACTLY ONE of {executor, adapter} present (an object-bound family is RESOLVER-BOUND via an adapter — Incr 11)`);
      if (exPresent && typeof b.executor !== "function") throw new BrokerError(`family "${fam}" executor must be a function`);
      // note: `typeof null === "object"`, so the explicit `!== null` guard keeps a `{adapter: null}` binding a BRANDED
      // BrokerError instead of a raw TypeError from the `.prepare` access — construction fails closed with the right class.
      if (adPresent && !(typeof b.adapter === "object" && b.adapter !== null && typeof b.adapter.prepare === "function" && typeof b.adapter.execute === "function" && typeof b.adapter.release === "function")) throw new BrokerError(`family "${fam}" adapter must be {prepare, execute, release}`);
      const hasExecutor = exPresent;
      if (audienceSeen.has(b.audience)) throw new BrokerError(`audience "${b.audience}" is bound to more than one family (audiences must be unique)`);
      audienceSeen.add(b.audience);
      const opMap = new Map<string, string>();
      for (const [op, right] of b.operations) { if (!isText(op) || !isText(right)) throw new BrokerError(`family "${fam}" has a malformed operation→right entry`); opMap.set(op, right); }
      if (hasExecutor) ex.set(fam, b.executor!); else ad.set(fam, b.adapter!);
      aud.set(fam, b.audience); ops.set(fam, opMap);
    }
    for (const fam of families) if (!ex.has(fam) && !ad.has(fam)) throw new BrokerError(`no executor/adapter bound for declared family "${fam}" (closed-world coverage)`);
    this.#executors = ex; this.#adaptersOf = ad; this.#audienceOf = aud; this.#opsOf = ops; this.#trust = permitKey; this.#ledger = ledger; this.#idem = idemStore; this.#audit = audit; this.#nonce = brokerNonce;
    if (witness !== undefined) this.#witness = witness;
    // Derive the replay-binding key from the (secret, deployment-wide) permit root — domain-separated so it is not the
    // permit key itself. Shared across instances/processes (same permitKey), so a replay sealed by one broker verifies in
    // another; unknown to the idempotency store, so the store cannot forge a binding.
    this.#replayKey = macHex(permitKey.rootKey, "keep.broker.replay-bind-key/v1");
  }

  /** Bind a completed result to THIS idempotency identity + its output under the broker-only replay key (store-unforgeable). */
  #replayBind(idemKey: string, result: BrokerResult): string {
    // Domain versioned by witness-binding presence: a witnessed result binds under /v2 (its content includes
    // witnessEntry), a legacy/no-witness result under /v1 (content byte-identical to pre-12a) — so a v1 Sealed
    // persisted in a durable store still verifies here, and a v2 Sealed never collides with a v1 domain.
    const domain = (result.ok && typeof result.witnessEntry === "string") ? "keep.broker.bind/v2" : "keep.broker.bind/v1";
    return macHex(this.#replayKey, idemKey, eirDigest(domain, resultBindContent(result)));
  }
  /** Wrap a result as the authenticated Sealed value the idempotency store holds. */
  #seal(idemKey: string, result: BrokerResult): Sealed { return Object.freeze({ result, bind: this.#replayBind(idemKey, result) }); }

  /** Incr 12a: the digest the witness binds to the effect-to-be. For an ADAPTER family the target is RESOLVED
   *  (x.objectId is the prepared canonical id) so the binding is EXACT-OBJECT; for a plain EXECUTOR it is over the
   *  DECLARED authorized args — SEMANTIC-INVOCATION binding (exact wire bytes are a named seam, not claimed here). */
  #executionBinding(x: RunArgs): { executionDigest: string; bindingKind: ExecutionBindingKind } {
    const isAdapter = x.adapter !== undefined && x.prepared !== undefined;
    const bindingKind: ExecutionBindingKind = isAdapter ? "exact-object" : "semantic-invocation";
    const executionDigest = eirDigest("keep.witness.exec/v1", { bindingKind, objectId: x.objectId, operation: x.operation, right: x.right, argsDigest: x.argsDigest });
    return { executionDigest, bindingKind };
  }

  /** Incr 12a: best-effort seal a receipt completing a witnessed intent. RETURNS whether it durably sealed — only then
   *  is the result marked witnessed (/v2 replayable-as-witnessed); a failed receipt leaves the intent's completion NOT
   *  durably recorded (the effect still ran; the output is returned but as an ordinary /v1 result). */
  async #sealReceiptSafe(witnessEntry: string | undefined, outputDigest: string): Promise<boolean> {
    if (witnessEntry === undefined || this.#witness === undefined) return false;
    try { await this.#witness.sealReceipt({ intentEntryHash: witnessEntry, outputDigest }); return true; } catch { return false; }
  }
  /** Incr 12a: best-effort seal a TERMINAL disposition of an intent so it is not a false crash orphan. `disposition`
   *  is plumbed honestly — "aborted" for a caller-signal abort or a pre-effect abandonment, "error" for a definite
   *  executor throw / bad output. Best-effort: a failure here cannot mask the outcome (the intent is already sealed). */
  async #sealTerminalSafe(intentEntry: string | undefined, disposition: "aborted" | "error", reason: string): Promise<void> {
    if (intentEntry === undefined || this.#witness === undefined) return;
    try { await this.#witness.sealTerminal({ intentEntryHash: intentEntry, disposition, reason }); } catch { /* post-commit best-effort */ }
  }

  /** Write an audit record; RETURNS the content id. THROWS if the sink fails (the caller decides fail-closed handling). */
  #write(kind: string, seq: bigint, fields: Record<string, CanonicalValue>): string {
    const record: CanonicalValue = { broker: BROKER.name, nonce: this.#nonce, kind, seq, ...fields };
    const id = eirDigest("keep.broker.audit/v1", record);
    this.#audit.write({ ...(record as Record<string, CanonicalValue>), id });
    return id;
  }

  /**
   * Perform an effect through the atomic redeem→dispatch transaction. TOTAL: any failure is `{ok:false, reason}` and
   * NOTHING is dispatched. `now`/`currentEpoch` are the trusted monitor's; `signal` (optional) bounds a hostile executor.
   */
  async dispatch(req: BrokerRequest, now: bigint, currentEpoch: bigint, signal?: AbortSignal): Promise<BrokerResult> {
    const seq = this.#seq; this.#seq += 1n;
    // [0] request shape — read every field ONCE inside a try (a hostile Proxy / throwing getter is a deny, not a throw).
    let permit: Permit, subject: string, session: string, effectId: string, objectId: string, family: unknown, operation: string, args: unknown, idempotencyKey: string;
    try {
      if (req === null || typeof req !== "object") return this.#failClosed(seq, "malformed request");
      permit = req.permit; subject = req.subject; session = req.session; effectId = req.effectId; objectId = req.objectId; family = req.family; operation = req.operation; args = req.args; idempotencyKey = req.idempotencyKey;
    } catch (e) { return this.#failClosed(seq, `malformed request: ${safeText(e)}`); }
    if (!isText(subject) || !isText(session) || !isText(effectId) || !isText(objectId) || !isText(operation) || !isText(idempotencyKey)) return this.#failClosed(seq, "malformed request fields");
    if (!isEffectFamily(family)) return this.#failClosed(seq, "unknown effect family");
    const executor = this.#executors.get(family), adapter = this.#adaptersOf.get(family), audience = this.#audienceOf.get(family), ops = this.#opsOf.get(family);
    if ((executor === undefined && adapter === undefined) || audience === undefined || ops === undefined) return this.#failClosed(seq, `no executor/adapter for family "${family}" (closed-world deny-by-default)`);
    const right = ops.get(operation);
    if (right === undefined) return this.#failClosed(seq, `operation "${operation}" is not declared for family "${family}"`); // no generic execute
    let argsCanon: CanonicalValue;
    try { argsCanon = decodeInert(args); } catch { return this.#failClosed(seq, "args are not canonical/inert"); }
    const argsDigest = eirDigest("keep.broker.args/v1", argsCanon);
    // The signal, if present, MUST be a genuine AbortSignal — a brand check (not duck-typing) so a hostile object with
    // fake/no-op or synchronously-firing listener methods cannot defeat the deadline or slip past the abort wiring.
    if (signal !== undefined && !isRealAbortSignal(signal)) return this.#failClosed(seq, "malformed abort signal");
    // Pre-aborted request ⇒ a CLEAN deny that does not spend the permit or start any effect (checked BEFORE redemption).
    if (abortedSafe(signal)) return this.#failClosed(seq, "aborted before dispatch");
    // [0b] RESOLVER-BOUND (Increment 11): for an object-based family the caller's `objectId` is a DECOY. PREPARE the EXACT
    //      target from the args (resolve+open+seal into an opaque adapter-held handle) and bind everything below — the
    //      idempotency key, the redemption context, and the execution — to the RESOLVED canonical id. The RETURNED handle
    //      is RELEASED on every path after this point (the try/finally below); a prepare that THROWS self-cleans (adapter contract).
    let prepared: PreparedTarget | undefined;
    if (adapter !== undefined) {
      try { prepared = adapter.prepare(operation, argsCanon); } catch (e) { return this.#failClosed(seq, `object prepare failed: ${safeText(e)}`); }
    }
    try {
    if (adapter !== undefined) {
      // Read canonicalId EXACTLY ONCE into an immutable snapshot (a hostile Proxy getter that throws on a 2nd read cannot
      // escape as a raw reject), INSIDE the release-protected region (a malformed prepared still releases the handle).
      let cid: unknown; try { cid = (prepared as { canonicalId?: unknown } | undefined)?.canonicalId; } catch { cid = undefined; }
      if (prepared === null || typeof prepared !== "object" || !isText(cid)) return this.#failClosed(seq, "adapter returned a malformed prepared target");
      objectId = cid; // the RESOLVED object identity is authoritative; the caller's objectId is ignored
    }
    // FULL-OPERATION idempotency key (NO broker nonce — a deployment's shared store keys the SAME op identically across
    // instances). A DIFFERENT operation/object/subject/args cannot false-replay another's result.
    const idemKey = eirDigest("keep.broker.idem/v1", { session, idempotencyKey, family, effectId, objectId, operation, right, subject, argsDigest });
    const ctx: RedeemContext = { now, currentEpoch, subject, session, effectId, audience, objectId, right };

    // [1] SINGLE-FLIGHT idempotency — RESERVE a deferred promise BEFORE running #run (so even a synchronously-reentrant
    //     executor and concurrent identical requests all share the ONE dispatch). A completed/in-flight identical op is
    //     served from the reservation WITHOUT re-dispatching — but ONLY to a caller who presents a currently-VALID
    //     permit for this op (verified, NOT spent), so a party lacking authority cannot read a prior op's output.
    // The broker OWNS the deferred + its resolver (created BEFORE reserve, so `settle` is ALWAYS bound; `mine` uses the
    // CAPTURED Promise so a replaced global cannot make it a hostile thenable). reserve + ALL reservation inspection run
    // inside ONE try: a store that installs `mine` then throws — OR returns a hostile object whose fresh/entry/then getter
    // throws — routes to #settleDeny (settle `mine`, best-effort release, deny), never a rejected dispatch or a stranded
    // waiter. The OWNERSHIP INVARIANT fresh ⟺ (entry === mine) is enforced: a store that returns an ALIEN entry on fresh,
    // or claims NOT-fresh while handing back our own never-installed deferred (which no path would settle → self-strand),
    // is denied before we act on it.
    let settle!: (s: Sealed) => void;
    const mine: InFlight = new _Promise<Sealed>((res) => { settle = res; });
    let entry!: InFlight, fresh!: boolean;
    try {
      const reservation = this.#idem.reserve(idemKey, mine);
      if (reservation === null || typeof reservation !== "object") throw new BrokerError("malformed reservation");
      const rFresh: unknown = reservation.fresh, rEntry: unknown = reservation.entry;
      if (typeof rFresh !== "boolean" || !isInFlight(rEntry)) throw new BrokerError("malformed reservation");
      if (rFresh ? rEntry !== mine : rEntry === mine) throw new BrokerError("reservation ownership violation");
      entry = rEntry; fresh = rFresh;
    } catch (e) { return this.#settleDeny(seq, idemKey, mine, settle, `idempotency store unavailable: ${safeText(e)}`); }
    if (!fresh) {
      // `mine` is UNUSED on this path (the store returned an EXISTING reservation). SETTLE + best-effort release it so a
      // store that lyingly INSTALLED `mine` (then reported not-fresh with a different entry) cannot strand later callers
      // who receive it. Harmless for a conforming store (nobody holds `mine`).
      settle(this.#seal(idemKey, Object.freeze({ ok: false, reason: "reservation superseded", auditId: "" })));
      try { this.#idem.release(idemKey, mine); } catch { /* best-effort */ }
      let valid: boolean; try { valid = verifyPermit(permit, this.#trust, ctx).valid; } catch { valid = false; } // broker-local totality
      if (!valid) return this.#failClosed(seq, "replay requires a valid permit for this operation");
      // Race the replay WAIT against the caller's own signal (nothing to cancel — the shared op is NOT cancelled), so a
      // replay caller that aborts gets {ok:false} instead of hanging on a slow shared op.
      let servedRaw: Sealed;
      try { servedRaw = await race<Sealed>(() => entry, signal, () => { /* no shared op to cancel */ }); } catch { return this.#failClosed(seq, "in-flight dispatch failed / replay aborted"); }
      // TOTAL validate+normalize (hostile getters → deny; success output re-copied to inert canonical data).
      const sealed = asSealed(servedRaw);
      if (sealed === null) return this.#failClosed(seq, "in-flight reservation resolved to a malformed result");
      // AUTHENTICATED REPLAY: the cached result must carry a valid broker binding to THIS idemKey + its output. A Byzantine
      // store cannot substitute another operation's result (cross-key disclosure) or synthesize one — the binding is keyed
      // to the broker-only replay key. Constant-time compare; a mismatch DENIES, never discloses.
      if (!timingSafeEqualHex(sealed.bind, this.#replayBind(idemKey, sealed.result))) return this.#failClosed(seq, "in-flight reservation binding mismatch");
      // Incr 12a: gate on the RESULT'S witnessed-ness FIRST, not the broker's config. A WITNESSED (/v2) cached result's
      // disclosure is itself an INFORMATION effect and MUST be witnessed (parent = the original intent) FAIL-CLOSED
      // before returning — so a witness-less OR broken-witness broker DENIES the disclosure rather than leaking an
      // unwitnessed replay of a witnessed result. A legacy (/v1, unwitnessed) result carries no intent to parent to and
      // replays unchanged (mixed-fleet safe). The replay path NEVER re-runs the executor — disclosure only. This gate
      // runs BEFORE the replay-served audit so a witness-deny leaves NO spurious "served" record for a replay never served.
      if (sealed.result.ok && typeof sealed.result.witnessEntry === "string") {
        if (this.#witness === undefined) return this.#failClosed(seq, "a witnessed result cannot be disclosed by a witness-less broker");
        try { await this.#witness.observeReplay({ intentEntryHash: sealed.result.witnessEntry, idemKey }, signal); }
        catch (e) { return this.#failClosed(seq, `witness unavailable (replay): ${safeText(e)}`); }
      }
      // FAIL-CLOSED replay-disclosure audit: the cached output is an information effect, so it is recorded BEFORE it is
      // returned — a broken sink denies the replay rather than disclosing an unrecorded result.
      try { this.#write("replay-served", seq, { idemKey }); } catch (e) { return this.#failClosed(seq, `audit unavailable (replay): ${safeText(e)}`); }
      return sealed.result;
    }
    const { result, retryable } = await this.#runSafe(seq, { permit, subject, session, effectId, objectId, family, operation, right, argsCanon, argsDigest, audience, executor, adapter, prepared, idemKey }, now, currentEpoch, signal);
    settle(this.#seal(idemKey, result));               // SEAL + settle waiters FIRST — a release() throw must never strand them
    if (retryable) { try { this.#idem.release(idemKey, mine); } catch { /* best-effort; release OUR entry (=== mine by the invariant). A stale reservation only over-DENIES a later retry, never causes an effect */ } }
    return result;
    } finally {
      // RELEASE the prepared handle on EVERY post-prepare path (fresh-complete, replay, deny, throw) — the effect executed
      // THROUGH it (fresh) or it was unused (replay/deny); either way the resource is closed exactly once.
      if (adapter !== undefined && prepared !== undefined) { try { adapter.release(prepared); } catch { /* best-effort cleanup */ } }
    }
  }

  /** #run wrapped so it NEVER rejects — always resolves to {result, retryable}. `retryable` is true ONLY for failures
   * that occurred BEFORE the executor was invoked (no effect performed), so a started effect is never re-executed. */
  async #runSafe(seq: bigint, x: RunArgs, now: bigint, currentEpoch: bigint, signal?: AbortSignal): Promise<{ result: BrokerResult; retryable: boolean }> {
    try { return await this.#run(seq, x, now, currentEpoch, signal); }
    catch (e) { return { result: this.#failClosed(seq, `internal error: ${safeText(e)}`), retryable: true }; }
  }

  async #run(seq: bigint, x: RunArgs, now: bigint, currentEpoch: bigint, signal?: AbortSignal): Promise<{ result: BrokerResult; retryable: boolean }> {
    const pre = (r: BrokerResult): { result: BrokerResult; retryable: boolean } => ({ result: deepFreeze(r), retryable: true }); // pre-effect: retryable
    const done = (r: BrokerResult): { result: BrokerResult; retryable: boolean } => ({ result: deepFreeze(r), retryable: false }); // effect started: terminal
    // [2] INTENT — fail-closed: a broken audit sink aborts BEFORE any authority is spent (no effect).
    let intentId: string;
    try { intentId = this.#write("intent", seq, { subject: x.subject, session: x.session, effectId: x.effectId, objectId: x.objectId, right: x.right, family: x.family, operation: x.operation, argsDigest: x.argsDigest, idemKey: x.idemKey }); }
    catch (e) { return pre({ ok: false, reason: `audit unavailable (intent): ${safeText(e)}`, auditId: "" }); }

    // [3] REDEEM — verify + atomically single-use redeem, bound to THIS subject/session/effect/object + the DERIVED right + this family's audience.
    const ctx: RedeemContext = { now, currentEpoch, subject: x.subject, session: x.session, effectId: x.effectId, audience: x.audience, objectId: x.objectId, right: x.right };
    const verdict = redeem(x.permit, this.#trust, ctx, this.#ledger);
    if (!verdict.valid) return pre(this.#deny(seq, `permit not redeemable: ${verdict.reason}`, { intentId }));
    try { this.#write("redeemed", seq, { intentId, permitId: verdict.permitId, rootId: verdict.rootId }); } catch (e) { return pre({ ok: false, reason: `audit unavailable (redeemed): ${safeText(e)}`, auditId: intentId }); }

    // [4] DISPATCH record BEFORE the executor (fail-closed proof the effect began) — a write failure aborts here (permit
    //     spent, but no effect performed → still retryable).
    try { this.#write("dispatch", seq, { intentId, permitId: verdict.permitId, operation: x.operation }); } catch (e) { return pre({ ok: false, reason: `audit unavailable (dispatch): ${safeText(e)}`, auditId: intentId }); }

    // [4.5] PRE-EFFECT WITNESS INTERLOCK (Increment 12a) — THE LAST FALLIBLE PRE-EFFECT STEP. After reserve(single-
    //       flight) + redeem(permit) + prepare(envelope) + the mandatory intent/redeemed/dispatch audit, a DURABLE
    //       commitment to the execution ENVELOPE (adapter: the resolved object = exact-object; executor: the declared
    //       authorized args = semantic-invocation, NOT exact wire bytes) is sealed and its ack RE-VALIDATED against the
    //       intent content id the broker itself computed (a stale/forged ack cannot open the gate). A throw/missing/mismatched ack is
    //       FAIL-CLOSED and RETRYABLE (no effect performed; the effect is structurally unreachable without it). Absent
    //       witness ⇒ this whole step is skipped → byte-identical legacy behavior. HONEST: same-trust-domain (a
    //       compromised Keep forges effect+witness together); independence begins at the 12b root export.
    // Build the execution machinery FIRST (pure setup — the captured-intrinsic controller + the invocation thunk) so
    // that after the witness ack the ONLY remaining fallible step is the executor invocation itself. sealIntent is thus
    // literally the LAST fallible pre-effect step. RESOLVER-BOUND (Incr 11): an adapter family executes THROUGH the
    // prepared handle (no re-resolvable args); else the plain executor gets the AUTHORIZED (effect,object,op,right)+args.
    const controller = freshController(); // captured-intrinsic controller: a replaced global cannot no-op executor cancel
    const work: () => CanonicalValue | Promise<CanonicalValue> = x.adapter !== undefined && x.prepared !== undefined
      ? () => x.adapter!.execute(x.prepared!, controller.signal)
      : () => x.executor!(Object.freeze({ effectId: x.effectId, objectId: x.objectId, operation: x.operation, right: x.right }), x.argsCanon, controller.signal);

    let witnessEntry: string | undefined;
    if (this.#witness !== undefined) {
      const { executionDigest, bindingKind } = this.#executionBinding(x);
      const intent: WitnessIntent = {
        idemKey: x.idemKey, attemptId: `${this.#nonce}:${seq}`, permitId: verdict.permitId, epoch: currentEpoch,
        family: x.family, operation: x.operation, objectId: x.objectId, executionDigest, bindingKind, keyEpoch: 0n,
        // ONE causal edge, carrying guardDigest — which IS the authorizing decision's digest (the permit↔decision tie,
        // permit.ts). A distinct "decision" edge is DROPPED until decisions are recorded on the chain as their own
        // artifact (the ingress→decision edge is threaded then); fabricating an edge to a nonexistent record would mislead the verifier.
        causalParents: [{ kind: "permit", permitId: verdict.permitId, guardDigest: verdict.claims.guardDigest }] satisfies CausalRef[],
      };
      const expected = intentEntryHash(intent);
      let ackEntry: unknown, ackExec: unknown;
      try {
        const ack = await this.#witness.sealIntent(intent, signal);
        ackEntry = (ack as { entryHash?: unknown } | null)?.entryHash; ackExec = (ack as { executionDigest?: unknown } | null)?.executionDigest;
      } catch (e) {
        // The intent MAY have durably committed before the throw (commit-then-throw / abort racing the returned ack).
        // Seal a best-effort ABORTED terminal bound to the broker-computed intent id so a committed intent is not a
        // false crash orphan; if nothing committed, a terminal-without-intent is a harmless verifier anomaly. Then fail
        // closed (retryable — no effect ran).
        await this.#sealTerminalSafe(expected, "aborted", `witness intent failed: ${safeText(e)}`);
        return pre({ ok: false, reason: `witness unavailable (intent): ${safeText(e)}`, auditId: intentId });
      }
      // RE-VALIDATE: the ack must bind THIS exact intent (content id) AND echo THIS execution digest, else deny — and
      // terminalize the possibly-committed intent so it is not a false crash orphan.
      if (ackEntry !== expected || ackExec !== executionDigest) {
        await this.#sealTerminalSafe(expected, "aborted", "witness ack does not bind this intent");
        return pre({ ok: false, reason: "witness ack does not bind this intent", auditId: intentId });
      }
      witnessEntry = expected;
    }

    // [5] EXECUTE — raced against the caller's AbortSignal. From here the effect may have occurred, so every outcome is
    //     TERMINAL (not retryable). A failure seals a terminal bound to the intent — "aborted" for a caller-signal abort
    //     (the executor may ignore cancel and complete later → outcome-unknown), "error" for a definite executor throw.
    let raw: unknown;
    try { raw = await race(work, signal, controller.abort); }
    catch (e) { const id = this.#writeSafe("error", seq, { intentId, stage: "dispatch", message: safeText(e) }); await this.#sealTerminalSafe(witnessEntry, abortedSafe(signal) ? "aborted" : "error", safeText(e)); return done({ ok: false, reason: `dispatch failed: ${safeText(e)}`, auditId: id }); }
    let output: CanonicalValue;
    try { output = deepFreeze(decodeInert(raw)); } catch { const id = this.#writeSafe("error", seq, { intentId, stage: "sanitize", message: "non-canonical output" }); await this.#sealTerminalSafe(witnessEntry, "error", "non-canonical output"); return done({ ok: false, reason: "executor returned non-canonical output", auditId: id }); }

    // [6] RESULT (post-effect). The effect is done; a result-write failure is surfaced EXPLICITLY (resultAudited:false),
    //     never as a silent success. Incr 12a: complete the intent with a receipt; ONLY if the receipt DURABLY sealed is
    //     `witnessEntry` bound into the result (→ Sealed under bind /v2, replayable-as-witnessed). If the receipt seal
    //     FAILS the effect still ran and the output is returned, but the result is NOT marked witnessed (/v1) — a replay
    //     discloses it as an ordinary cached result, and the chain honestly shows an intent whose completion was not
    //     durably recorded (an orphan means "completion not durably witnessed" — crash OR receipt-seal failure).
    const outputDigest = eirDigest("keep.broker.output/v1", output);
    let auditId = intentId; let resultAudited = false;
    try { auditId = this.#write("result", seq, { intentId, permitId: verdict.permitId, outputDigest }); resultAudited = true; } catch { /* effect done; result record unavailable */ }
    const receiptSealed = await this.#sealReceiptSafe(witnessEntry, outputDigest);
    const boundWitness = receiptSealed ? witnessEntry : undefined;
    return done(boundWitness === undefined
      ? { ok: true, output, auditId, replayed: false, resultAudited }
      : { ok: true, output, auditId, replayed: false, resultAudited, witnessEntry: boundWitness });
  }

  /** Best-effort audit write (used on post-authorization error paths where a throw must not mask the outcome). */
  #writeSafe(kind: string, seq: bigint, fields: Record<string, CanonicalValue>): string { try { return this.#write(kind, seq, fields); } catch { return ""; } }

  #deny(seq: bigint, reason: string, fields: Record<string, CanonicalValue>): BrokerResult {
    const auditId = this.#writeSafe("denied", seq, { ...fields, reason });
    return Object.freeze({ ok: false, reason, auditId });
  }
  /** A pre-redemption fail-closed deny (best-effort audit; a sink failure here cannot hide an effect — none occurred). */
  #failClosed(seq: bigint, reason: string): BrokerResult { return this.#deny(seq, reason, {}); }

  /** Deny after `reserve` MAY have installed the broker-owned deferred (durable store commits-then-throws, or returns a
   * malformed value): SETTLE that deferred (a concurrent waiter that received it resolves — never strands) and best-effort
   * RELEASE the possibly-installed entry (so a retry can proceed), then return the fail-closed deny. `settle` is broker-
   * owned so it cannot be undefined; the release runs regardless of whether reserve actually installed anything. */
  #settleDeny(seq: bigint, idemKey: string, mine: InFlight, settle: (s: Sealed) => void, reason: string): BrokerResult {
    const r = this.#failClosed(seq, reason);
    try { settle(this.#seal(idemKey, r)); } catch { /* broker-owned resolver; a double-settle is a no-op */ }
    try { this.#idem.release(idemKey, mine); } catch { /* best-effort; a stale reservation only over-DENIES a later retry */ }
    return r;
  }
}

/** Read a signal's abort state via the CAPTURED platform getter (an own-property `aborted` shadow cannot lie about it);
 * a throwing/forged object ⇒ true (fail-closed). */
function abortedSafe(signal: AbortSignal | undefined): boolean { if (signal === undefined) return false; try { return _abortedGetter!.call(signal) === true; } catch { return true; } }

/** Race the executor (a THUNK) against an optional caller AbortSignal. The abort listener is installed BEFORE the thunk
 * runs, so a synchronous abort DURING the executor is not lost (no hang); a `settled` guard + cleanup avoid double-settle
 * and listener leaks; a malformed signal (no addEventListener) fails closed WITHOUT invoking the executor. On abort it
 * calls `onCancel` — a CAPTURED abort thunk (not a raw controller) so a replaced global cannot no-op executor cancel. */
function race<T>(workFn: () => Promise<T> | T, signal: AbortSignal | undefined, onCancel: () => void): Promise<T> {
  if (signal === undefined) { try { return _Promise.resolve(workFn()); } catch (e) { return _Promise.reject(e); } }
  return new _Promise<T>((resolve, reject) => {
    let settled = false;
    // Install/remove the listener via the CAPTURED EventTarget methods (not through the object) so a genuine-but-extended
    // signal that shadows addEventListener/removeEventListener with own no-op properties cannot silently drop the abort.
    const finish = (fn: () => void): void => { if (settled) return; settled = true; try { _removeListener!.call(signal, "abort", onAbort); } catch { /* hostile signal */ } fn(); };
    const onAbort = (): void => finish(() => { try { onCancel(); } catch { /* best-effort cancel */ } reject(new BrokerError("dispatch aborted/timed out")); });
    try { _addListener!.call(signal, "abort", onAbort, { once: true }); } catch { try { onCancel(); } catch { /* best-effort */ } reject(new BrokerError("malformed abort signal")); return; } // executor NOT invoked
    if (abortedSafe(signal)) { onAbort(); return; }             // re-check after install (executor NOT invoked)
    if (settled) return;                                        // a listener that fired synchronously already settled us
    let work: Promise<T> | T;
    try { work = workFn(); } catch (e) { finish(() => reject(e)); return; }
    _Promise.resolve(work).then((v) => finish(() => resolve(v)), (e) => finish(() => reject(e)));
  });
}

/** TOTAL validator+normalizer for a reservation's RESOLVED value (the effect already happened exactly once). Returns a
 * fresh, deeply-frozen BrokerResult with replayed:true — re-canonicalizing a success output to INERT data — or null if the
 * value is not a well-formed BrokerResult. Every field is read defensively so a hostile getter DENIES (null), never throws.
 * A trusted in-process reservation always passes; the validation only bites a (Byzantine) store that resolves to garbage. */
function asBrokerResult(v: unknown): BrokerResult | null {
  if (v === null || typeof v !== "object") return null;
  let ok: unknown, auditId: unknown;
  try { ok = (v as { ok?: unknown }).ok; auditId = (v as { auditId?: unknown }).auditId; } catch { return null; }
  if (typeof ok !== "boolean" || typeof auditId !== "string") return null;
  if (ok) {
    let output: unknown, resultAudited: unknown;
    try { output = (v as { output?: unknown }).output; resultAudited = (v as { resultAudited?: unknown }).resultAudited; } catch { return null; }
    if (typeof resultAudited !== "boolean") return null;
    let inert: CanonicalValue;
    try { inert = deepFreeze(decodeInert(output)); } catch { return null; } // validate + copy to inert canonical
    // Incr 12a: carry witnessEntry through normalization so a replayed result rebinds under the SAME (v2) domain it
    // was sealed with — a stored witnessed Sealed must re-verify. A malformed/absent value degrades to a v1 rebind
    // (which then fails the constant-time bind check for a genuinely-v2 stored result → deny, never mis-disclose).
    let witnessEntry: unknown; try { witnessEntry = (v as { witnessEntry?: unknown }).witnessEntry; } catch { return null; }
    if (witnessEntry !== undefined && !isText(witnessEntry)) return null;
    return Object.freeze(witnessEntry === undefined
      ? { ok: true, output: inert, auditId, replayed: true, resultAudited }
      : { ok: true, output: inert, auditId, replayed: true, resultAudited, witnessEntry });
  }
  let reason: unknown;
  try { reason = (v as { reason?: unknown }).reason; } catch { return null; }
  if (!isText(reason)) return null;
  return Object.freeze({ ok: false, reason, auditId });
}

/** Sanitize to INERT canonical data: encode + re-decode (getters/proxies/non-canonical rejected); returns owned data. */
function decodeInert(v: unknown): CanonicalValue { return decodeCanonical(encodeCanonical(v as CanonicalValue)); }
