/**
 * TOTAL DECISION KERNEL (Mechanical-Enforcement Increment 6).
 *
 * The frontier property (one sentence): a single, small, deterministic evaluator is the SOLE producer of an allow/deny
 * decision for an EIR request, and EVERY path through it — a request naming an unknown effect, a guard whose atoms
 * cannot be resolved, a revoked capability, a stale policy epoch, an evaluation that would exceed its bound, or any
 * internal fault — resolves to DENY. There is no code path to allow except a live, in-bound, current-epoch, un-revoked
 * request that a real permit definitely grants and that no deny even possibly fires against.
 *
 * What it is. Given a threshold-signed policy bundle (Increment 2) and a trust policy, the kernel VERIFIES the bundle
 * at construction (an unverifiable policy yields no kernel — deny-by-default at the substrate: no policy ⇒ no permit)
 * and then answers `decide(request)` totally:
 *   - deny-overrides combining over the effect's compiled DECISION ROOT;
 *   - THREE-VALUED (Kleene) guard evaluation via the typed predicate theory (predicate.ts): a permit grants only when
 *     its guard is DEFINITELY true (T); a deny fires whenever its guard is possibly true (T or U). Unknown never
 *     grants and never suppresses a deny — U is the fail-closed value;
 *   - policy EPOCHS + MONOTONIC REVOCATION: revoking an effect / subject / entry-point only ever removes authority and
 *     advances the epoch; a request must present the CURRENT epoch (a replayed pre-revocation request is stale ⇒ deny);
 *   - BOUNDED evaluation: a per-request operation budget; a decision that would exceed it denies rather than runs on;
 *   - a content-addressed DECISION record — verdict + reason + proof trace (which denies fired, which permit granted)
 *     bound to the bundle digest, both epochs (the fence epoch and the request's presented epoch), the full request
 *     identity (subject, entry point, effect, resolved budget), and a digest of the request context — the audit
 *     commitment. The same bundle and request always produce the same decision digest, in-process or inside the
 *     monitor VM. INJECTIVITY BOUND (honest): for a WELL-FORMED request the digest is injective over every
 *     decision-relevant input above; a MALFORMED request denies with reason `malformed-request` and a deliberately
 *     COARSE commitment (invalid fields collapse — the verdict is invariantly deny, so there is nothing to forge). The
 *     `internal-error` denial (the catch backstop) is the coarsest: it commits reset requestedEpoch=0n/budget=0 so the
 *     re-seal cannot itself fault. (`epoch-exhausted` still commits the validated request identity — finer, and safe.)
 *
 * Where it runs. The kernel is pure and deterministic so the SAME bytes execute behind the Increment-5 attested monitor
 * boundary (the isolated monitor is where the sole decision is made) and in-process for conformance. It consumes an
 * already-verified bundle and an already-typed request context; it does not itself do measured boot (Increment 5) or
 * resolve a request attribute to its actual runtime object (Increment 11 — Resolver-Bound Guards).
 *
 * Defers (honest). Delegable authority / capability minting is Increment 7 (Object-Capability Permits); actual effect
 * DISPATCH once allowed is Increment 9 (Effect Broker Kernel); STATIC cross-atom theory (compile-time interval unsat)
 * is a possible later refinement over predicate.ts, not attempted here — the runtime evaluation that gates the effect
 * is complete and sound.
 *
 * Grounding: reference-monitor completeness/tamper-resistance (Anderson); Cedar/XACML deny-overrides with errors-deny;
 * Kleene three-valued logic for partial information; monotonic authorization + epoch fencing; deterministic decision
 * commitments (content-addressed audit). Zero runtime dependency (node:crypto via eir/canonical only).
 */
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { verifyBundle, type SignedBundle, type BundlePayload, type DecisionRoot, type CompiledRule, type RuleRef } from "../policy/compiler.js";
import { parseCanonical as parseGuard, type NormGuard } from "../policy/guard_dag.js";
import type { TrustPolicy } from "../bom/bom_signing.js";
import { evalAtom, type PredicateContext, type ContextValue, type Scalar, type Tri } from "./predicate.js";

export const KERNEL = { name: "keep.kernel.decision", version: "6.0.0" } as const;

/** Default per-request evaluation budget (guard-node visits). A decision that would exceed it denies (fail-closed). */
export const DEFAULT_BUDGET = 100_000;
/** Upper bound on request-context size — caps the attacker-controllable work done BEFORE the eval budget is consulted
 * (capture + canonicalize + hash). A context exceeding either bound is a malformed request (fail-closed). */
export const MAX_CONTEXT_ATTRS = 256;
export const MAX_CONTEXT_LIST_LEN = 1024;
/** Per-string code-unit cap (identities + context keys/values). Bounds normalize/canonicalize/hash work per string —
 * the length is checked BEFORE `normalize()` so a giant string never gets normalized (cross-family review, SEV2). */
export const MAX_TEXT_LEN = 1 << 16;
/** Magnitude cap on any committed integer (context ints, presented epoch) — |v| < 2^64. This is NOT arbitrary: the
 * canonical CBOR encoder admits an integer argument only up to 2^64-1 (it has no bignum path and THROWS above that), so
 * a value in [2^64, ∞) would fault inside #seal. Aligning the gate to the encoder makes an over-range value a clean
 * malformed/deny (never a throw). (cross-family review, Fable — the earlier 2^2048 bound left an encoder-range crash.) */
export const MAX_INT_MAG = 1n << 64n;

export class KernelError extends Error {
  constructor(m: string) { super(`decision kernel: ${m}`); this.name = "KernelError"; }
}

/**
 * Advance the epoch by one, or SEAL if the encodable epoch space is exhausted. The kernel's own epoch is committed in
 * every decision and so must stay within the canonical encoder's integer range (< 2^64); after that many DISTINCT
 * revocations the kernel enters a permanent fail-closed state rather than wrapping or letting #seal throw (cross-family
 * review, GPT-5.6). Pure + unit-testable at the boundary (2^64 real revocations are not otherwise reachable in a test).
 */
export function nextEpoch(current: bigint): { readonly epoch: bigint; readonly sealed: boolean } {
  const n = current + 1n;
  return n < MAX_INT_MAG ? { epoch: n, sealed: false } : { epoch: current, sealed: true };
}

/** A revocation TARGET — revoking only ever removes authority (monotonic) and advances the epoch. */
export type Revocation =
  | { readonly effect: string }
  | { readonly subject: string }
  | { readonly entryPoint: string };

/** A decision request. `atEpoch` must equal the kernel's CURRENT epoch or the request is stale (deny). */
export interface DecisionRequest {
  readonly atEpoch: bigint;
  readonly subject: string;      // the principal identity the caller presents (matched against rule subjects / "*")
  readonly entryPoint: string;   // the entry point the request arrives on (matched against rule entryPoints / "*")
  readonly effectId: string;     // the declared effect (content id) the request seeks to perform
  readonly context: PredicateContext; // typed attributes the guards are evaluated against
  readonly budget?: number;      // evaluation budget; defaults to DEFAULT_BUDGET
}

export type Verdict = "allow" | "deny";

/** The fixed, closed set of decision reasons. Exactly one — `matched-permit` — is an allow; every other is a deny. */
export type DecisionReason =
  | "matched-permit"        // ALLOW: a permit definitely granted and no deny fired
  | "matched-deny"          // an applicable deny fired (guard T or U)
  | "no-applicable-permit"  // the decision root's explicit default-deny leaf
  | "unknown-effect"        // no decision root for this effect id
  | "revoked-effect" | "revoked-subject" | "revoked-entryPoint"
  | "stale-epoch"           // atEpoch != current epoch (a replayed / future request)
  | "epoch-exhausted"       // the encodable epoch space is exhausted — permanent fail-closed (2^64 revocations)
  | "eval-bound-exceeded"   // evaluation would exceed the request budget
  | "malformed-request"     // request shape / context types invalid
  | "internal-error";       // any unexpected fault — total fail-closed backstop

export interface FiredDeny { readonly ruleId: string; readonly guardId: string; readonly guardValue: Tri; }
export interface GrantingPermit { readonly ruleId: string; readonly guardId: string; }
export interface DecisionProof {
  readonly firedDenies: readonly FiredDeny[];
  readonly grantingPermit: GrantingPermit | null;
  readonly opsUsed: number;
}
/** A total decision + its content-addressed commitment. `digest` binds every other field (the audit anchor). */
export interface Decision {
  readonly kernel: { readonly name: string; readonly version: string };
  readonly bundleDigest: string;
  readonly epoch: bigint;            // the kernel's epoch at decision time (the fence the request was tested against)
  readonly requestedEpoch: bigint;   // the epoch the request PRESENTED — committed so two stale requests don't collide
  readonly subject: string;
  readonly entryPoint: string;
  readonly effectId: string;
  readonly contextDigest: string;
  readonly budget: number;           // the RESOLVED evaluation budget — part of the request, so part of the commitment
  readonly verdict: Verdict;
  readonly reason: DecisionReason;
  readonly proof: DecisionProof;
  readonly digest: string;
}

// ── Three-valued (Kleene) evaluation of a normalized guard ──────────────────────────────────────────────────────
function kleene(g: NormGuard, atomVal: (a: string) => Tri): Tri {
  switch (g.t) {
    case "const": return g.v ? "T" : "F";
    case "atom": return atomVal(g.atom);
    case "not": { const x = kleene(g.op, atomVal); return x === "U" ? "U" : x === "T" ? "F" : "T"; }
    case "and": { let u = false; for (const o of g.ops) { const x = kleene(o, atomVal); if (x === "F") return "F"; if (x === "U") u = true; } return u ? "U" : "T"; }
    case "or": { let u = false; for (const o of g.ops) { const x = kleene(o, atomVal); if (x === "T") return "T"; if (x === "U") u = true; } return u ? "U" : "F"; }
  }
}
/** Guard-node count — the evaluation cost charged against the budget when a rule's guard is evaluated. */
function nodeCount(g: NormGuard): number {
  switch (g.t) { case "const": case "atom": return 1; case "not": return 1 + nodeCount(g.op); case "and": case "or": return 1 + g.ops.reduce((s, o) => s + nodeCount(o), 0); }
}

// Length is checked BEFORE normalize() so an oversized string is never normalized (bounds the work). Identities must
// be non-empty; a context string VALUE may be empty. Integers are magnitude-bounded so their encoding cost is bounded.
// WELL-FORMEDNESS is required too: a lone/unpaired surrogate is NFC-stable but not injective under the canonical
// encoder (it would collide with U+FFFD) — rejecting it here makes an ill-formed field a clean malformed-request deny
// with a bound digest, rather than relying on the canonical layer to throw (cross-family review, Fable SEV1).
const isNfcText = (s: unknown): s is string => typeof s === "string" && s.length > 0 && s.length <= MAX_TEXT_LEN && isWellFormedText(s) && s.normalize("NFC") === s;
const isScalar = (v: unknown): v is Scalar =>
  (typeof v === "bigint" && v > -MAX_INT_MAG && v < MAX_INT_MAG) ||
  (typeof v === "string" && v.length <= MAX_TEXT_LEN && isWellFormedText(v) && v.normalize("NFC") === v);

/** A request context captured into OWNED, plain data — read exactly once from the caller's (possibly hostile) object. */
interface CapturedContext {
  /** Owned plain Map used for BOTH the digest and evaluation, so the committed context IS the evaluated context. */
  readonly ctx: ReadonlyMap<string, ContextValue>;
  /** Domain-separated digest over the owned, sorted, valid entries (always computable; never trusts the input). */
  readonly digest: string;
  /** false ⇒ the context was malformed (ill-typed value, non-NFC key, duplicate key, or over a cap) ⇒ deny. */
  readonly ok: boolean;
}

/**
 * Capture a caller's request context ONCE into owned, plain data. This is the load-bearing boundary against a hostile
 * `Map` subclass: the caller's object is iterated exactly once here and NEVER touched again — evaluation runs against
 * the OWNED copy (plain `Map.prototype.get`), so it cannot (a) re-enter the kernel via an overridden `get()` after the
 * epoch/revocation checks, nor (b) present one value to iteration and another to lookup (cross-family review, GPT-5.6
 * SEV0). The context digest is computed from the SAME owned copy, so the commitment binds exactly what is evaluated.
 * Total: any defect sets `ok:false` (⇒ malformed-request deny) rather than throwing, and the digest still binds the
 * valid entries collected so far.
 *
 * THREAT-MODEL note (residual, documented): a SAME-ISOLATE caller could still hand a Map whose iterator `.next()` /
 * `.return()` (or a request-field getter) synchronously NEVER RETURNS — no bound can catch non-termination inside one
 * hostile callback, and no `allow` is ever produced during such a hang (fail-closed). The kernel's contract is that it
 * runs BEHIND the Increment-5 attested boundary, which delivers already-decoded, callback-free PLAIN data over the
 * authenticated channel; hostile in-isolate objects are out of scope. The bounds here (attr/list/text/int caps, indexed
 * array reads, read-once fields) defend the in-process conformance path against every attack that is not literal
 * non-termination of an injected callback.
 */
function captureContext(raw: unknown): CapturedContext {
  const own = new Map<string, ContextValue>();
  const pairs: [string, CanonicalValue][] = [];
  let ok = true;
  const fail = (): void => { ok = false; };
  if (!(raw instanceof Map)) { ok = false; }
  else {
    let count = 0;
    for (const [k, v] of raw) {           // the ONE and ONLY traversal of the caller's object
      if (++count > MAX_CONTEXT_ATTRS) { fail(); break; }
      if (!isNfcText(k)) { fail(); continue; }
      if (own.has(k)) { fail(); continue; } // duplicate attribute (a subclass could yield one)
      let cv: CanonicalValue | undefined; let owned: ContextValue | undefined;
      if (isScalar(v)) { cv = v; owned = v; }
      else if (Array.isArray(v)) {
        // INDEXED reads (not `for..of`): a hostile own Symbol.iterator must not be consulted — it could yield past
        // `length` unboundedly or never return, defeating the cap and decide()'s totality (cross-family review, SEV1).
        const len = (v as readonly unknown[]).length;
        if (!Number.isInteger(len) || len < 0 || len > MAX_CONTEXT_LIST_LEN) { fail(); continue; } // reject a proxy's NaN/negative/fractional length
        const list: Scalar[] = [];
        let good = true;
        for (let i = 0; i < len; i++) { const e = (v as readonly unknown[])[i]; if (!isScalar(e)) { good = false; break; } list.push(e); }
        if (!good) { fail(); continue; }
        cv = [...list]; owned = Object.freeze(list);
      } else { fail(); continue; }
      own.set(k, owned);
      pairs.push([k, cv]);
    }
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const canon: CanonicalValue = pairs.map(([k, cv]) => [k, cv] as CanonicalValue);
  return { ctx: own, digest: eirDigest("keep.kernel.context/v1", canon), ok };
}

/**
 * The Total Decision Kernel. Construct with a signed bundle + trust policy (verified at construction, else throws).
 * `decide` is TOTAL — it never throws and always returns a committed Decision.
 */
export class DecisionKernel {
  readonly #bundleDigest: string;
  readonly #roots: ReadonlyMap<string, DecisionRoot>;
  readonly #ruleById: ReadonlyMap<string, CompiledRule>;
  readonly #guardById: ReadonlyMap<string, { norm: NormGuard; cost: number }>;
  #epoch = 0n;
  #sealed = false; // set once the epoch space is exhausted (2^64 revocations) — permanent fail-closed
  readonly #revokedEffects = new Set<string>();
  readonly #revokedSubjects = new Set<string>();
  readonly #revokedEntryPoints = new Set<string>();

  constructor(signed: SignedBundle, trust: TrustPolicy) {
    const v = verifyBundle(signed, trust);
    if (!v.valid) throw new KernelError(`bundle does not verify (${v.reason}) — no policy, no permit`);
    const p: BundlePayload = v.bundle.payload; // OWNED, verified snapshot
    this.#bundleDigest = v.bundle.payloadDigest;
    const roots = new Map<string, DecisionRoot>();
    for (const r of p.decisionRoots) roots.set(r.effectId, r);
    const rules = new Map<string, CompiledRule>();
    for (const r of p.rules) rules.set(r.id, r);
    const guards = new Map<string, { norm: NormGuard; cost: number }>();
    for (const g of p.guards) { const norm = parseGuard(g.expr); guards.set(g.id, { norm, cost: nodeCount(norm) }); }
    this.#roots = roots; this.#ruleById = rules; this.#guardById = guards;
  }

  /** The verified bundle's payload digest (the decision-commitment anchor). */
  get bundleDigest(): string { return this.#bundleDigest; }
  /** The current policy epoch. A request must present exactly this value or it is stale (deny). */
  get epoch(): bigint { return this.#epoch; }

  /**
   * Revoke authority. Monotonic: the revocation set only grows; a genuinely-new revocation advances the epoch (so any
   * request minted before it becomes stale ⇒ deny) and returns the new epoch. A repeat no-op returns the current epoch.
   */
  revoke(rev: Revocation): bigint {
    let set: Set<string> | undefined; let key: string | undefined;
    if ("effect" in rev && isNfcText(rev.effect)) { set = this.#revokedEffects; key = rev.effect; }
    else if ("subject" in rev && isNfcText(rev.subject)) { set = this.#revokedSubjects; key = rev.subject; }
    else if ("entryPoint" in rev && isNfcText(rev.entryPoint)) { set = this.#revokedEntryPoints; key = rev.entryPoint; }
    if (set === undefined || key === undefined) throw new KernelError("malformed revocation");
    if (!set.has(key)) { set.add(key); const adv = nextEpoch(this.#epoch); this.#epoch = adv.epoch; if (adv.sealed) this.#sealed = true; }
    return this.#epoch;
  }

  /** The sole allow/deny decision for an EIR request. Total (never throws); always returns a committed Decision. */
  decide(req: DecisionRequest): Decision {
    // Every request field is read EXACTLY ONCE into an owned local (read-once discipline): a getter/proxy whose value
    // varies between reads cannot pass validation and then poison a later use (cross-family review, GPT-5.6 SEV1).
    // The locals default to safe values so #seal is total even on the failure paths.
    let subject = "", entryPoint = "", effectId = "", contextDigest = "";
    let budget = DEFAULT_BUDGET;
    let requestedEpoch = 0n; // the presented epoch, once validated as a bigint (committed for stale-request injectivity)
    const mk = (verdict: Verdict, reason: DecisionReason, proof: DecisionProof): Decision =>
      this.#seal({ subject, entryPoint, effectId, contextDigest, budget, requestedEpoch, verdict, reason, proof });
    try {
      if (req === null || typeof req !== "object") return mk("deny", "malformed-request", EMPTY_PROOF);
      const atEpoch = req.atEpoch;         // ── read once ──
      const subjectRaw = req.subject;
      const entryRaw = req.entryPoint;
      const effectRaw = req.effectId;
      const rawContext = req.context;      // reference only; captured (traversed once) below
      const budgetRaw = req.budget;
      // atEpoch must be a NON-NEGATIVE, magnitude-BOUNDED bigint: an unbounded attacker bigint would otherwise cost
      // unbounded encode/hash work at seal (and could re-throw inside the catch), breaking totality (GPT-5.6 r4 SEV1).
      if (typeof atEpoch !== "bigint" || atEpoch < 0n || atEpoch >= MAX_INT_MAG || !isNfcText(subjectRaw) || !isNfcText(entryRaw) || !isNfcText(effectRaw)) {
        subject = str(subjectRaw); entryPoint = str(entryRaw); effectId = str(effectRaw);
        return mk("deny", "malformed-request", EMPTY_PROOF);
      }
      subject = subjectRaw; entryPoint = entryRaw; effectId = effectRaw; requestedEpoch = atEpoch;
      if (budgetRaw !== undefined) {
        // Upper-bound the budget too: it is committed as BigInt(budget), which must stay within the encoder's 2^64
        // argument range. MAX_SAFE_INTEGER (2^53-1) is far beyond any real evaluation and is precisely representable.
        if (typeof budgetRaw !== "number" || !Number.isInteger(budgetRaw) || budgetRaw < 0 || budgetRaw > Number.MAX_SAFE_INTEGER) return mk("deny", "malformed-request", EMPTY_PROOF);
        budget = Object.is(budgetRaw, -0) ? 0 : budgetRaw; // normalize -0 → +0 so the committed budget is canonical (GPT-5.6 r4)
      }
      // Capture the context ONCE into owned plain data — evaluation runs against this copy, never the caller's object,
      // so it can neither re-enter the kernel after the checks nor split iteration from lookup (GPT-5.6 SEV0). The
      // digest is over the SAME owned copy ⇒ the commitment binds exactly what is evaluated.
      const cap = captureContext(rawContext);
      contextDigest = cap.digest;
      if (!cap.ok) return mk("deny", "malformed-request", EMPTY_PROOF);
      // Epoch space exhausted (2^64 revocations) ⇒ permanent fail-closed. #epoch is capped < 2^64 so this seal is safe.
      if (this.#sealed) return mk("deny", "epoch-exhausted", EMPTY_PROOF);

      // Epoch fence: a request must be current (a replayed pre-revocation / future request is stale).
      if (atEpoch !== this.#epoch) return mk("deny", "stale-epoch", EMPTY_PROOF);
      // Monotonic revocation: a revoked dimension denies outright (revocation only ever removes authority).
      if (this.#revokedEffects.has(effectId)) return mk("deny", "revoked-effect", EMPTY_PROOF);
      if (this.#revokedSubjects.has(subject)) return mk("deny", "revoked-subject", EMPTY_PROOF);
      if (this.#revokedEntryPoints.has(entryPoint)) return mk("deny", "revoked-entryPoint", EMPTY_PROOF);
      // Unknown effect ⇒ no decision root ⇒ deny-by-default.
      const root = this.#roots.get(effectId);
      if (root === undefined) return mk("deny", "unknown-effect", EMPTY_PROOF);

      // Bounded, memoized atom evaluation against the OWNED context (plain Map.get — no callback into the caller).
      const memo = new Map<string, Tri>();
      const atomVal = (a: string): Tri => { let t = memo.get(a); if (t === undefined) { t = evalAtom(a, cap.ctx); memo.set(a, t); } return t; };
      let ops = 0;
      const guardOf = (ref: RuleRef): { norm: NormGuard; cost: number } => {
        const g = this.#guardById.get(ref.guardId);
        if (g === undefined) throw new KernelError(`rule "${ref.ruleId}" references guard "${ref.guardId}" absent from the verified bundle`);
        return g;
      };
      const applicable = (ref: RuleRef): boolean =>
        (ref.subjects.includes("*") || ref.subjects.includes(subject)) &&
        (ref.entryPoints.includes("*") || ref.entryPoints.includes(entryPoint));

      // deny-overrides: evaluate every applicable deny first; a deny fires on T OR U (fail-closed).
      const firedDenies: FiredDeny[] = [];
      for (const ref of root.denies) {
        if (!applicable(ref)) continue;
        const g = guardOf(ref);
        ops += 1 + g.cost;
        if (ops > budget) return mk("deny", "eval-bound-exceeded", { firedDenies: freeze(firedDenies), grantingPermit: null, opsUsed: ops });
        const gv = kleene(g.norm, atomVal);
        if (gv === "T" || gv === "U") firedDenies.push(Object.freeze({ ruleId: ref.ruleId, guardId: ref.guardId, guardValue: gv }));
      }
      if (firedDenies.length > 0) return mk("deny", "matched-deny", { firedDenies: freeze(firedDenies), grantingPermit: null, opsUsed: ops });

      // No deny fired: a permit grants only when DEFINITELY true (T). First (canonically least ruleId) wins.
      for (const ref of root.permits) {
        if (!applicable(ref)) continue;
        const g = guardOf(ref);
        ops += 1 + g.cost;
        if (ops > budget) return mk("deny", "eval-bound-exceeded", { firedDenies: [], grantingPermit: null, opsUsed: ops });
        if (kleene(g.norm, atomVal) === "T") return mk("allow", "matched-permit", { firedDenies: [], grantingPermit: Object.freeze({ ruleId: ref.ruleId, guardId: ref.guardId }), opsUsed: ops });
      }
      // No applicable permit definitely granted ⇒ the root's explicit default-deny leaf.
      return mk("deny", "no-applicable-permit", { firedDenies: [], grantingPermit: null, opsUsed: ops });
    } catch {
      // Total fail-closed backstop: any unexpected fault denies. Reset the two locals that carry caller-influenced
      // MAGNITUDE (the only fields whose value could make a re-seal throw) to safe constants BEFORE sealing, so the
      // backstop itself can never double-fault — regardless of any future committed field (cross-family review, Fable).
      requestedEpoch = 0n; budget = 0;
      return mk("deny", "internal-error", EMPTY_PROOF);
    }
  }

  #seal(d: { subject: string; entryPoint: string; effectId: string; contextDigest: string; budget: number; requestedEpoch: bigint; verdict: Verdict; reason: DecisionReason; proof: DecisionProof }): Decision {
    // Deep-freeze the proof so the returned Decision cannot be mutated while retaining its committed digest (GPT-5.6
    // SEV1: TS `readonly` is erased at runtime — a mechanical monitor interface must not hand back a mutable record).
    for (const f of d.proof.firedDenies) Object.freeze(f);
    Object.freeze(d.proof.firedDenies);
    if (d.proof.grantingPermit !== null) Object.freeze(d.proof.grantingPermit);
    Object.freeze(d.proof);
    const base = {
      kernel: Object.freeze({ name: KERNEL.name, version: KERNEL.version }),
      bundleDigest: this.#bundleDigest, epoch: this.#epoch, requestedEpoch: d.requestedEpoch,
      subject: d.subject, entryPoint: d.entryPoint, effectId: d.effectId, contextDigest: d.contextDigest,
      budget: d.budget, verdict: d.verdict, reason: d.reason, proof: d.proof,
    };
    const digest = eirDigest("keep.kernel.decision/v1", decisionCanonical(base));
    return Object.freeze({ ...base, digest });
  }
}

const EMPTY_PROOF: DecisionProof = Object.freeze({ firedDenies: Object.freeze([]) as readonly FiredDeny[], grantingPermit: null, opsUsed: 0 });
const freeze = <T>(xs: T[]): readonly T[] => Object.freeze([...xs]);
const str = (x: unknown): string => (isNfcText(x) ? x : "");

/** Canonical value of a decision (everything the digest commits to — excludes `digest` itself). */
function decisionCanonical(d: Omit<Decision, "digest">): CanonicalValue {
  return {
    kernel: { name: d.kernel.name, version: d.kernel.version },
    bundleDigest: d.bundleDigest,
    epoch: d.epoch,
    requestedEpoch: d.requestedEpoch,
    subject: d.subject, entryPoint: d.entryPoint, effectId: d.effectId, contextDigest: d.contextDigest,
    budget: BigInt(d.budget),
    verdict: d.verdict, reason: d.reason,
    proof: {
      firedDenies: d.proof.firedDenies.map((f) => ({ ruleId: f.ruleId, guardId: f.guardId, guardValue: f.guardValue })),
      grantingPermit: d.proof.grantingPermit === null ? null : { ruleId: d.proof.grantingPermit.ruleId, guardId: d.proof.grantingPermit.guardId },
      opsUsed: BigInt(d.proof.opsUsed),
    },
  };
}

/** Re-derive a decision's committed digest from its own fields — a verifier recomputes, never trusts the claim. */
export function decisionDigest(d: Decision): string {
  return eirDigest("keep.kernel.decision/v1", decisionCanonical(d));
}
