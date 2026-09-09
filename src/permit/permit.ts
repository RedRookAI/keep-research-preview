/**
 * UNFORGEABLE OBJECT-CAPABILITY PERMITS (Mechanical-Enforcement Increment 7).
 *
 * The frontier property (one sentence): authority to act on a specific object is conveyed ONLY by an unforgeable,
 * object-bound, single-use permit whose every field is cryptographically bound, whose attenuation can only ever REMOVE
 * authority, and whose total redemptions across an entire delegation subtree are capped by the root — so a holder can
 * neither forge a permit it was not given, amplify one it holds, detach a restriction, move it to another session or
 * subject, nor multiply its redemptions by branching.
 *
 * The construction (Macaroon-style caveat chain over an HMAC session-MAC). A ROOT permit is minted by the monitor from
 * an authorized decision: its authenticator is a keyed tag `t0 = HMAC(K, root-domain ‖ claimsDigest)` where K is the
 * monitor's SECRET root key (the session-MAC reference of the signer seam; the asymmetric Ed25519 "monitor-signs /
 * broker-verifies-with-public-key" option is the documented alternative when monitor and broker are separate trust
 * domains). The holder ATTENUATES by appending a CAVEAT and folding the tag forward `t_i = HMAC(t_{i-1}, caveat-domain ‖
 * caveatDigest_i)` — no key needed. HMAC (not a bare `sha256(K‖m)`) means the construction never depends on inputs
 * staying fixed-length to resist length extension. The verifier (the trusted-side broker, which also holds K) recomputes
 * t0 from K and folds every presented caveat; a tampered claim, an added/removed/reordered caveat, or a wrong tag fails
 * the constant-time tag check. Amplification is impossible two ways: effective authority is computed by MONOTONE
 * NARROWING, AND every caveat is required to STRICTLY narrow at least one dimension (a no-op caveat is rejected, so a
 * holder cannot mint distinct-looking-but-equal permits to launder around the redemption budget).
 *
 * What a permit binds: issuer, subject + session (non-transferable — both are checked against the redeemer), the
 * authorizing effect + the EXACT object id, the granted rights, the authorizing guard digest, the policy epoch
 * (monotonic revocation — a permit is valid only AT its epoch), a validity interval, a unique nonce, a max-redemption
 * count, and an audience. Single-use is enforced by the ledger (permit/ledger.ts) with a PER-PREFIX budget: verify()
 * emits one {id, cap} per chain prefix (the root claims digest is prefix 0; each interior prefix id is shared by every
 * descendant carrying it; cap is the running-min maxRedemptions), and redeem() consumes one from EVERY prefix, so every
 * node's whole-subtree total is bounded by that node's cap — a holder of a delegated cap-N permit cannot exceed N by
 * branching it into siblings, and the root bounds the whole tree to its `maxRedemptions`.
 *
 * Defers (honest): INITIAL authority issuance — deriving a root permit's claims from a kernel decision and the policy
 * that governs what may be minted — is Increment 8 (Ingress Admission Gate); the permit-CONSUMING effect dispatch is
 * Increment 9 (Effect Broker Kernel); binding `objectId` to the ACTUAL resolved runtime object (TOCTOU-safe identity,
 * not a caller-supplied id) is Increment 11 (Resolver-Bound Guards). This increment delivers the permit ALGEBRA +
 * verification completely and fails closed on everything else.
 *
 * Grounding: object-capability security (unforgeable references, no ambient authority); Macaroon caveat chains (HMAC-
 * chained holder-side attenuation); SPKI/SDSI attenuation (authority is the intersection down a chain, monotone);
 * proof-of-possession + replay-resistant tokens (nonce + per-prefix single-use ledger + audience + session/subject binding).
 */
import { createHmac } from "node:crypto";
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";

export const PERMIT = { name: "keep.permit", version: "7.0.0" } as const;

/** Bounds on caller-controllable set/chain sizes — cap the work done before a permit is rejected (fail-closed). The
 * worst-case validated permit is MAX_CAVEATS × MAX_SET × MAX_MEMBER_LEN × 2 ≈ 0.5 MiB of member text; the Increment-5
 * authenticated-frame size limit is the outer bound on the encoded permit (cross-family review, GPT-5.6 r4 SEV1 DoS). */
export const MAX_SET = 32;        // rights / audience members per set
export const MAX_CAVEATS = 32;    // attenuation-chain length
export const MAX_MEMBER_LEN = 256; // a right / audience id is a short token — capped tightly to bound aggregate size
const MAX_TEXT_LEN = 1 << 16;      // identities (subject/object/…) may be longer (URLs/paths)
const MAX_INT_MAG = 1n << 64n;  // committed integers must stay within the canonical encoder's argument range

export class PermitError extends Error {
  constructor(m: string) { super(`permit: ${m}`); this.name = "PermitError"; }
}
/** Extract a message from an arbitrary thrown value without letting a hostile getter/proxy escape (totality). */
function safeMsg(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; } }

// ── Envelope shapes (all content-addressed / canonical) ──────────────────────────────────────────────────────────

/** The root claims a permit conveys. Bound by the root tag; nothing here is mutable without breaking verification. */
export interface PermitClaims {
  readonly issuer: string;      // the minting monitor's key id
  readonly subject: string;     // the principal the permit authorizes (checked against the redeemer)
  readonly session: string;     // the session it is bound to (checked against the redeemer)
  readonly effectId: string;    // the authorized effect (checked against the redeemer)
  readonly objectId: string;    // the EXACT object id the permit is for (checked against the redeemer)
  readonly rights: readonly string[];   // granted operation rights (sorted, duplicate-free, non-empty)
  readonly guardDigest: string; // the authorizing guard (ties the permit to the decision that granted it)
  readonly epoch: bigint;       // the policy epoch it was minted at (monotonic revocation)
  readonly notBefore: bigint;   // validity interval (inclusive), in ms
  readonly notAfter: bigint;    // validity interval (inclusive), in ms; must be >= notBefore
  readonly nonce: string;       // unique per permit (mint-time uniqueness)
  readonly maxRedemptions: bigint; // the ROOT subtree redemption budget (>= 1)
  readonly audience: readonly string[]; // which broker/effect-family ids may redeem it (sorted, non-empty)
}
const CLAIMS_KEYS = ["issuer", "subject", "session", "effectId", "objectId", "rights", "guardDigest", "epoch", "notBefore", "notAfter", "nonce", "maxRedemptions", "audience"] as const;

/** A caveat: an attenuation layer. Every present field can only NARROW; a caveat must strictly narrow ≥1 dimension. */
export interface Caveat {
  readonly rights?: readonly string[];    // intersect the granted rights
  readonly notBefore?: bigint;             // raise the lower validity bound
  readonly notAfter?: bigint;              // lower the upper validity bound
  readonly audience?: readonly string[];   // intersect the audience
  readonly maxRedemptions?: bigint;        // lower the redemption ceiling
}
const CAVEAT_KEYS = new Set(["rights", "notBefore", "notAfter", "audience", "maxRedemptions"]);

/** A presented permit: root claims + the monitor's keyed root tag folded through the holder-added caveat chain. */
export interface Permit {
  readonly claims: PermitClaims;
  readonly caveats: readonly Caveat[];
  readonly tag: string; // HMAC chain tag: t0 = HMAC(K, claimsDigest); t_i = HMAC(t_{i-1}, caveatDigest_i); tag = t_n
}
const PERMIT_KEYS = ["claims", "caveats", "tag"] as const;

/** The monitor's/broker's root-key seam. Symmetric session MAC in the reference impl (HSM/PoP key in production). */
export interface PermitKey { readonly issuer: string; readonly rootKey: string; }

/** Effective (fully-attenuated) authority — what the permit actually grants after every caveat narrows it. */
export interface EffectiveAuthority {
  readonly rights: readonly string[];
  readonly notBefore: bigint;
  readonly notAfter: bigint;
  readonly audience: readonly string[];
  readonly maxRedemptions: bigint;
}

/** The context a redemption is checked against — every binding dimension the broker must present. */
export interface RedeemContext {
  readonly now: bigint;              // current time (ms) — validity interval check
  readonly currentEpoch: bigint;     // the kernel's current policy epoch — monotonic revocation
  readonly subject: string;          // the authenticated principal acting (must equal the permit's)
  readonly session: string;          // the redeemer's session (must equal the permit's)
  readonly effectId: string;         // the effect being invoked (must equal the permit's)
  readonly audience: string;         // the redeeming broker/effect-family id (must be in the effective audience)
  readonly objectId: string;         // the exact object being acted on (must equal the permit's)
  readonly right: string;            // the operation right required (must be in the effective rights)
}

/** A shared redemption budget for a chain PREFIX: a subtree id and the effective redemption cap at that node. */
export interface PermitBudget { readonly id: string; readonly cap: bigint; }
export type PermitVerdict =
  | { readonly valid: true; readonly permitId: string; readonly rootId: string; readonly budgets: readonly PermitBudget[]; readonly effective: EffectiveAuthority; readonly claims: PermitClaims }
  | { readonly valid: false; readonly reason: string };

// ── Captured PRIMORDIALS ─────────────────────────────────────────────────────────────────────────────────────────
// The identity + validation path calls these captured references (not `obj.method(...)`), and iterates caller-supplied
// arrays by INDEX with a captured length — so a hostile object cannot vary the authenticated identity or the work bound
// by mutating a built-in prototype (e.g. Array.prototype.map) as a getter side effect, nor by an overridden own method
// / custom Symbol.iterator (cross-family review, GPT-5.6 r3). This is defense-in-depth ABOVE the deployment boundary:
// a permit reaches the broker as DECODED, INERT plain data over the Increment-5 authenticated channel (no getters,
// proxies, or prototype tricks) — the same threat-model boundary as the Increment-6 kernel; a same-isolate adversary
// that has already achieved code execution to pollute prototypes is out of scope (and even then the ROOT-subtree
// budget, the hard security ceiling, still cannot be exceeded and no authority is forged).
const reflectApply = Reflect.apply;
const rawNormalize = String.prototype.normalize;
const P = {
  keys: Object.keys,
  ownSymbols: Object.getOwnPropertySymbols,
  isArray: Array.isArray,
  setAdd: Set.prototype.add as (this: Set<string>, v: string) => Set<string>,
  setHas: Set.prototype.has as (this: Set<string>, v: string) => boolean,
  setForEach: Set.prototype.forEach as (this: Set<string>, cb: (v: string) => void) => void,
} as const;
/** NFC via captured String.prototype.normalize (no `s.normalize(...)` dispatch through a mutable prototype). */
const nfcOf = (s: string): string => reflectApply(rawNormalize, s, ["NFC"]) as string;
const strEq = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
/** Build a Set from an array by INDEXED reads + captured add (no iterable constructor / Array iterator). */
function setOf(arr: readonly string[]): Set<string> { const s = new Set<string>(); for (let i = 0; i < arr.length; i++) P.setAdd.call(s, arr[i]!); return s; }
/** Collect a Set into a fresh SORTED array via captured forEach (no spread / Set iterator). */
function setToSorted(s: ReadonlySet<string>): string[] { const out: string[] = []; P.setForEach.call(s as Set<string>, (v: string) => { out[out.length] = v; }); return sortedStrings(out); }
/** Membership by INDEXED scan (no Array.prototype.includes) — `arr` is our own inert effective-authority array. */
function contains(arr: readonly string[], x: string): boolean { for (let i = 0; i < arr.length; i++) if (arr[i] === x) return true; return false; }
/** Sort a caller-influenced string array by captured comparison, returning a NEW inert array (no Array.prototype.sort). */
function sortedStrings(arr: readonly string[]): string[] {
  const len = arr.length; const out: string[] = [];
  for (let i = 0; i < len; i++) out[i] = arr[i]!;               // indexed copy (no spread/iterator)
  for (let i = 1; i < out.length; i++) { const v = out[i]!; let j = i - 1; while (j >= 0 && strEq(out[j]!, v) > 0) { out[j + 1] = out[j]!; j--; } out[j + 1] = v; } // insertion sort (bounded by MAX_SET)
  return out;
}

// ── Canonical digests (domain-separated) ─────────────────────────────────────────────────────────────────────────
const HEX64 = /^[0-9a-f]{64}$/;
const isText = (s: unknown): s is string => typeof s === "string" && s.length > 0 && s.length <= MAX_TEXT_LEN && isWellFormedText(s) && nfcOf(s) === s;
const inRangeInt = (v: unknown): v is bigint => typeof v === "bigint" && v > -MAX_INT_MAG && v < MAX_INT_MAG;
const noSymbols = (o: object): void => { if (P.ownSymbols(o).length) throw new PermitError("symbol keys are not allowed"); };
const exactKeys = (o: object, allowed: readonly string[], where: string): void => {
  noSymbols(o);
  const k = P.keys(o);
  if (k.length !== allowed.length) throw new PermitError(`${where} has unexpected or missing fields`);
  for (let i = 0; i < k.length; i++) { let ok = false; for (let j = 0; j < allowed.length; j++) if (k[i] === allowed[j]) { ok = true; break; } if (!ok) throw new PermitError(`${where} has unexpected or missing fields`); }
};

/** Canonical value of a caller-provided string SET (sorted, duplicate-free, non-empty, all NFC well-formed text). */
function canonSet(xs: unknown, where: string): readonly string[] {
  if (!P.isArray(xs)) throw new PermitError(`${where} must be a non-empty array`);
  const len = (xs as { length: unknown }).length;                // captured, bounded — a custom iterator is never used
  if (!Number.isInteger(len) || (len as number) <= 0) throw new PermitError(`${where} must be a non-empty array`);
  if ((len as number) > MAX_SET) throw new PermitError(`${where} exceeds the ${MAX_SET} member cap`);
  const seen = new Set<string>(); const out: string[] = [];
  for (let i = 0; i < (len as number); i++) {                     // INDEXED read (a hostile Symbol.iterator is ignored)
    const x = (xs as readonly unknown[])[i];
    if (!isText(x) || (x as string).length > MAX_MEMBER_LEN) throw new PermitError(`${where} has a non-text / oversized member`);
    if (P.setHas.call(seen, x)) throw new PermitError(`${where} has a duplicate member`);
    P.setAdd.call(seen, x); out[out.length] = x;
  }
  return sortedStrings(out);
}

function claimsCanonical(c: PermitClaims): CanonicalValue {
  // Sets are sorted here (not only in validation) so the digest is order-INDEPENDENT: an external caller computing
  // claimsDigest / rootId from unsorted claims gets the same id the enforcement path does (Fable footgun note).
  return {
    issuer: c.issuer, subject: c.subject, session: c.session, effectId: c.effectId, objectId: c.objectId,
    rights: sortedStrings(c.rights), guardDigest: c.guardDigest, epoch: c.epoch,
    notBefore: c.notBefore, notAfter: c.notAfter, nonce: c.nonce, maxRedemptions: c.maxRedemptions, audience: sortedStrings(c.audience),
  };
}
/** Content id of the root claims — the preimage the root tag authenticates, and the ROOT (subtree) ledger identity. */
export function claimsDigest(c: PermitClaims): string { return eirDigest("keep.permit.claims/v1", claimsCanonical(c)); }

function caveatCanonical(c: Caveat): CanonicalValue {
  const o: Record<string, CanonicalValue> = {};
  if (c.rights !== undefined) o["rights"] = sortedStrings(c.rights);
  if (c.notBefore !== undefined) o["notBefore"] = c.notBefore;
  if (c.notAfter !== undefined) o["notAfter"] = c.notAfter;
  if (c.audience !== undefined) o["audience"] = sortedStrings(c.audience);
  if (c.maxRedemptions !== undefined) o["maxRedemptions"] = c.maxRedemptions;
  return o;
}
/** Content id of a caveat (the preimage folded into the tag chain at its layer). */
export function caveatDigest(c: Caveat): string { return eirDigest("keep.permit.caveat/v1", caveatCanonical(c)); }

/** Map a caveat array via INDEXED access (never the caller's overridable `.map`) into a fresh, inert plain array. */
function mapByIndex<T>(arr: readonly Caveat[], f: (c: Caveat) => T): T[] {
  if (!P.isArray(arr)) throw new PermitError("caveat chain must be an array");
  const len = (arr as { length: unknown }).length;
  if (!Number.isInteger(len) || (len as number) < 0 || (len as number) > MAX_CAVEATS) throw new PermitError("caveat chain has an invalid length");
  const out: T[] = [];
  for (let i = 0; i < (len as number); i++) out[i] = f(arr[i] as Caveat); // index assignment (no Array.prototype.push)
  return out;
}
/** Validate a presented caveat array into a fresh, inert snapshot — the ONLY caveat data any later step may read. */
function validateChain(raw: readonly Caveat[]): Caveat[] { return mapByIndex(raw, validateCaveat); }

/** The permit's stable identity for the per-permit redemption cap: root claims + the full, ordered caveat chain. */
export function permitId(p: Permit): string {
  // Validate to a fresh inert snapshot, then digest it by INDEX (no `.map`), so neither a hostile own method nor a
  // polluted Array.prototype can vary the authenticated identity across calls.
  const snap = validateChain(p.caveats);
  return eirDigest("keep.permit.id/v1", { claims: claimsDigest(p.claims), caveats: mapByIndex(snap, caveatDigest) });
}
/** A root/session key or a chain tag used as an HMAC key — bounded + well-formed so the HMAC work + byte encoding are canonical. */
const MAX_KEY_LEN = 4096;
const isKeyMaterial = (s: unknown): s is string => typeof s === "string" && s.length > 0 && s.length <= MAX_KEY_LEN && isWellFormedText(s);

// ── HMAC caveat-chain (domain-separated; not a length-extendable sha256(k‖m)) ────────────────────────────────────
const ROOT_DOMAIN = "keep.permit.root-tag/v1";
const CAVEAT_DOMAIN = "keep.permit.caveat-tag/v1";
const mac = (key: string, domain: string, contentDigest: string): string =>
  createHmac("sha256", key).update(domain).update("|").update(contentDigest).digest("hex");
/** Recompute a permit's tag from the root key and the caveat chain (never trusts the presented tag). */
function recomputeTag(claims: PermitClaims, caveats: readonly Caveat[], rootKey: string): string {
  let t = mac(rootKey, ROOT_DOMAIN, claimsDigest(claims)); // t0 binds the immutable claims to the secret root key
  for (let i = 0; i < caveats.length; i++) t = mac(t, CAVEAT_DOMAIN, caveatDigest(caveats[i]!)); // indexed; folds forward
  return t;
}

// ── Validation of caller-supplied claims / caveats ───────────────────────────────────────────────────────────────
// Read a field EXACTLY ONCE into a local, validate the local, use the local — a stateful getter that returns a valid
// value on one read and junk on another can never land an unvalidated value in the snapshot (read-once discipline).
function reqText(o: Record<string, unknown>, k: string): string { const v = o[k]; if (!isText(v)) throw new PermitError(`claims.${k} must be non-empty NFC text`); return v; }
function reqInt(o: Record<string, unknown>, k: string, where: string): bigint { const v = o[k]; if (!inRangeInt(v)) throw new PermitError(`${where}.${k} must be a bounded bigint`); return v; }
function validateClaims(c: unknown): PermitClaims {
  if (c === null || typeof c !== "object" || Array.isArray(c)) throw new PermitError("claims must be an object");
  exactKeys(c, CLAIMS_KEYS, "claims");
  const o = c as Record<string, unknown>;
  const issuer = reqText(o, "issuer"), subject = reqText(o, "subject"), session = reqText(o, "session");
  const effectId = reqText(o, "effectId"), objectId = reqText(o, "objectId"), guardDigest = reqText(o, "guardDigest"), nonce = reqText(o, "nonce");
  if (!HEX64.test(guardDigest)) throw new PermitError("claims.guardDigest must be a content hash");
  const rights = canonSet(o["rights"], "claims.rights");
  const audience = canonSet(o["audience"], "claims.audience");
  const epoch = reqInt(o, "epoch", "claims"), notBefore = reqInt(o, "notBefore", "claims"), notAfter = reqInt(o, "notAfter", "claims"), maxRedemptions = reqInt(o, "maxRedemptions", "claims");
  if (epoch < 0n) throw new PermitError("claims.epoch must be >= 0");
  if (notAfter < notBefore) throw new PermitError("claims.notAfter must be >= notBefore");
  if (maxRedemptions < 1n) throw new PermitError("claims.maxRedemptions must be >= 1");
  return { issuer, subject, session, effectId, objectId, rights, guardDigest, epoch, notBefore, notAfter, nonce, maxRedemptions, audience };
}

function validateCaveat(c: unknown): Caveat {
  if (c === null || typeof c !== "object" || Array.isArray(c)) throw new PermitError("caveat must be an object");
  noSymbols(c);
  const o = c as Record<string, unknown>;
  const keys = P.keys(o);
  if (keys.length === 0) throw new PermitError("caveat must restrict at least one dimension");
  for (let i = 0; i < keys.length; i++) if (!CAVEAT_KEYS.has(keys[i]!)) throw new PermitError(`caveat has unknown field "${keys[i]}"`);
  const out: { rights?: readonly string[]; notBefore?: bigint; notAfter?: bigint; audience?: readonly string[]; maxRedemptions?: bigint } = {};
  if ("rights" in o) out.rights = canonSet(o["rights"], "caveat.rights");
  if ("audience" in o) out.audience = canonSet(o["audience"], "caveat.audience");
  // read-once capture for each bigint (no second unvalidated read; Fable r3 latent-TOCTOU note).
  for (const k of ["notBefore", "notAfter", "maxRedemptions"] as const) if (k in o) { const v = o[k]; if (!inRangeInt(v)) throw new PermitError(`caveat.${k} must be a bounded bigint`); out[k] = v; }
  if (out.maxRedemptions !== undefined && out.maxRedemptions < 0n) throw new PermitError("caveat.maxRedemptions must be >= 0");
  return out;
}

// ── Effective authority (monotone narrowing) + strict-attenuation check ──────────────────────────────────────────
const intersect = (a: ReadonlySet<string>, b: readonly string[]): Set<string> => { const s = new Set<string>(); for (let i = 0; i < b.length; i++) { const x = b[i]!; if (P.setHas.call(a as Set<string>, x)) P.setAdd.call(s, x); } return s; };
const bmax = (a: bigint, b: bigint): bigint => (a > b ? a : b);
const bmin = (a: bigint, b: bigint): bigint => (a < b ? a : b);
interface Eff { rights: Set<string>; nb: bigint; na: bigint; aud: Set<string>; maxR: bigint; }
const applyCaveat = (e: Eff, c: Caveat): Eff => ({
  rights: c.rights !== undefined ? intersect(e.rights, c.rights) : e.rights,
  aud: c.audience !== undefined ? intersect(e.aud, c.audience) : e.aud,
  nb: c.notBefore !== undefined ? bmax(e.nb, c.notBefore) : e.nb,
  na: c.notAfter !== undefined ? bmin(e.na, c.notAfter) : e.na,
  maxR: c.maxRedemptions !== undefined ? bmin(e.maxR, c.maxRedemptions) : e.maxR,
});
/** A caveat must reduce at least ONE dimension — else it is a no-op used only to fork the permit identity (rejected). */
const strictlyNarrows = (before: Eff, after: Eff): boolean =>
  after.rights.size < before.rights.size || after.aud.size < before.aud.size || after.nb > before.nb || after.na < before.na || after.maxR < before.maxR;

/** Fold caveats into effective authority, requiring each to STRICTLY narrow. Returns null on a non-narrowing layer. */
function foldEffective(claims: PermitClaims, caveats: readonly Caveat[]): EffectiveAuthority | null {
  let e: Eff = { rights: setOf(claims.rights), aud: setOf(claims.audience), nb: claims.notBefore, na: claims.notAfter, maxR: claims.maxRedemptions };
  for (let i = 0; i < caveats.length; i++) {
    const next = applyCaveat(e, caveats[i]!);
    if (!strictlyNarrows(e, next)) return null; // a no-op caveat (identity-laundering) is invalid
    e = next;
  }
  return { rights: setToSorted(e.rights), audience: setToSorted(e.aud), notBefore: e.nb, notAfter: e.na, maxRedemptions: e.maxR };
}

const PREFIX_DOMAIN = "keep.permit.prefix/v1";
/**
 * Per-PREFIX redemption budgets. For each prefix [c1..ci] (i = 0..k) it emits {id, cap}: the id is the SUBTREE identity
 * shared by every descendant that carries that prefix (prefix 0's id IS the root claims digest), and the cap is the
 * effective redemption ceiling at that node (the running min of maxRedemptions down the chain). Redeeming a LEAF
 * consumes one from EVERY prefix, so every node's whole-subtree total is bounded by that node's cap — which closes the
 * amplification where a holder of a delegated cap-1 permit branches it into siblings to redeem up to the root budget
 * (cross-family review, GPT-5.6 r4 SEV0). Caps are monotone non-increasing down the chain.
 */
function computeBudgets(claims: PermitClaims, caveats: readonly Caveat[]): PermitBudget[] {
  const base = claimsDigest(claims);
  const cds = mapByIndex(caveats, caveatDigest);
  const out: PermitBudget[] = [];
  let cap = claims.maxRedemptions;
  out[0] = { id: base, cap };                                   // prefix 0 = the root subtree (id === rootId)
  const prefix: string[] = [];
  for (let i = 0; i < caveats.length; i++) {
    const c = caveats[i]!;
    if (c.maxRedemptions !== undefined && c.maxRedemptions < cap) cap = c.maxRedemptions;
    prefix[i] = cds[i]!;
    const slice: string[] = []; for (let j = 0; j <= i; j++) slice[j] = prefix[j]!;
    out[i + 1] = { id: eirDigest(PREFIX_DOMAIN, { claims: base, caveats: slice }), cap };
  }
  return out;
}

/** Constant-time compare over equal-length hex tags (avoids a tag-guessing timing side channel). */
function ctEq(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// ── Mint / attenuate / verify ────────────────────────────────────────────────────────────────────────────────────

/**
 * Mint a ROOT permit (monitor side; requires the secret root key). Validates the claims and tags them. The issuer in
 * the claims must match the key's issuer. (HOW a root's claims are derived from a kernel decision — the issuance policy
 * — is Increment 8; this is the unconditional primitive.)
 */
export function mintRoot(rawClaims: PermitClaims, key: PermitKey): Permit {
  if (key === null || typeof key !== "object" || !isText(key.issuer) || !isKeyMaterial(key.rootKey)) throw new PermitError("malformed permit key");
  const claims = validateClaims(rawClaims);
  if (claims.issuer !== key.issuer) throw new PermitError("claims.issuer does not match the minting key");
  const tag = mac(key.rootKey, ROOT_DOMAIN, claimsDigest(claims));
  return Object.freeze({ claims: Object.freeze({ ...claims, rights: Object.freeze([...claims.rights]), audience: Object.freeze([...claims.audience]) }), caveats: Object.freeze([]) as readonly Caveat[], tag });
}

/**
 * Attenuate a permit by appending a caveat (holder side; NO key required). The caveat must STRICTLY narrow the current
 * effective authority (a no-op is rejected here and, authoritatively, at verify). The new tag folds the caveat in.
 */
export function attenuate(permit: Permit, rawCaveat: Caveat): Permit {
  try {
    if (permit === null || typeof permit !== "object" || !isKeyMaterial(permit.tag) || !HEX64.test(permit.tag) || !Array.isArray(permit.caveats)) throw new PermitError("permit must be a well-formed envelope");
    if ((permit.caveats as { length: number }).length >= MAX_CAVEATS) throw new PermitError(`caveat chain exceeds the ${MAX_CAVEATS} layer cap`);
    const claims = validateClaims(permit.claims);
    const caveats = validateChain(permit.caveats); // indexed snapshot — never the caller's `.map`
    const caveat = validateCaveat(rawCaveat);
    if (foldEffective(claims, [...caveats, caveat]) === null) throw new PermitError("caveat does not strictly narrow the permit (no-op attenuation is not allowed)");
    const tag = mac(permit.tag, CAVEAT_DOMAIN, caveatDigest(caveat)); // fold forward from the CURRENT tag (one-way)
    return Object.freeze({ claims: permit.claims, caveats: Object.freeze([...caveats, caveat]) as readonly Caveat[], tag });
  } catch (e) {
    // Holder-side helper: normalize ANY hostile-input fault to a PermitError (no arbitrary thrown value escapes).
    let isPE = false; try { isPE = e instanceof PermitError; } catch { /* a hostile thrown value's prototype trap */ }
    throw isPE ? e : new PermitError(safeMsg(e));
  }
}

/**
 * VERIFY a presented permit against the trusted root key + a redemption context. TOTAL + fail-safe: any malformed input
 * or failing check is `valid:false` with a reason, never an exception. On success returns the per-permit id, the ROOT
 * per-PREFIX budgets (for the ledger), and the effective authority. Does NOT consume a redemption — see redeem().
 */
export function verify(permit: unknown, trust: PermitKey, ctx: RedeemContext): PermitVerdict {
  try {
    if (permit === null || typeof permit !== "object") return { valid: false, reason: "permit must be an object" };
    let p: Permit;
    try { exactKeys(permit as object, PERMIT_KEYS, "permit"); p = permit as Permit; } catch (e) { return { valid: false, reason: `malformed: ${safeMsg(e)}` }; }
    if (!isKeyMaterial(p.tag) || !HEX64.test(p.tag) || !Array.isArray(p.caveats)) return { valid: false, reason: "malformed permit envelope" };
    if (trust === null || typeof trust !== "object" || !isText(trust.issuer) || !isKeyMaterial(trust.rootKey)) return { valid: false, reason: "malformed trust" };
    let claims: PermitClaims; let caveats: readonly Caveat[];
    // Indexed validation snapshot: a hostile own `.map` / getters on the caveat array can never influence verification.
    try { claims = validateClaims(p.claims); caveats = validateChain(p.caveats); } catch (e) { return { valid: false, reason: `malformed: ${safeMsg(e)}` }; }
    // Unforgeability: recompute the tag from the SECRET root key + the full caveat chain; constant-time compare.
    if (claims.issuer !== trust.issuer) return { valid: false, reason: "issuer-untrusted" };
    if (!ctEq(recomputeTag(claims, caveats, trust.rootKey), p.tag)) return { valid: false, reason: "tag-mismatch (forged/tampered/detached caveat)" };
    // Every caveat must strictly narrow — a valid tag over a no-op caveat chain is still rejected (anti-laundering).
    const eff = foldEffective(claims, caveats);
    if (eff === null) return { valid: false, reason: "non-narrowing-caveat" };
    // Monotonic revocation: valid ONLY at the mint epoch; any revocation that advanced the epoch kills it.
    if (!inRangeInt(ctx?.currentEpoch)) return { valid: false, reason: "malformed context epoch" };
    if (claims.epoch !== ctx.currentEpoch) return { valid: false, reason: "stale-epoch (revoked or superseded)" };
    // Validity interval.
    if (!inRangeInt(ctx.now)) return { valid: false, reason: "malformed context time" };
    if (ctx.now < eff.notBefore) return { valid: false, reason: "not-yet-valid" };
    if (ctx.now > eff.notAfter) return { valid: false, reason: "expired" };
    // Non-transferable + object/effect/audience/right binding — every dimension checked against the redeemer.
    if (!isText(ctx.subject) || ctx.subject !== claims.subject) return { valid: false, reason: "subject-mismatch" };
    if (!isText(ctx.session) || ctx.session !== claims.session) return { valid: false, reason: "session-mismatch (copied across sessions)" };
    if (!isText(ctx.effectId) || ctx.effectId !== claims.effectId) return { valid: false, reason: "effect-mismatch" };
    if (!isText(ctx.objectId) || ctx.objectId !== claims.objectId) return { valid: false, reason: "object-mismatch" };
    if (!isText(ctx.audience) || !contains(eff.audience, ctx.audience)) return { valid: false, reason: "audience-mismatch" };
    if (!isText(ctx.right) || !contains(eff.rights, ctx.right)) return { valid: false, reason: "right-not-granted" };
    if (eff.maxRedemptions < 1n) return { valid: false, reason: "no-redemptions-remaining" };
    const budgets = computeBudgets(claims, caveats);
    for (let i = 0; i < budgets.length; i++) Object.freeze(budgets[i]);
    Object.freeze(budgets); Object.freeze(eff.rights); Object.freeze(eff.audience); Object.freeze(eff);
    Object.freeze(claims.rights); Object.freeze(claims.audience); Object.freeze(claims); // fully-immutable verdict (Fable r6)
    return Object.freeze({ valid: true, permitId: permitId({ claims, caveats, tag: p.tag }), rootId: claimsDigest(claims), budgets, effective: eff, claims });
  } catch (e) {
    return { valid: false, reason: `verify error: ${safeMsg(e)}` };
  }
}
