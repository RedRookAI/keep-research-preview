/**
 * Canonical encoding for the Enforcement IR (BUILD-ORDER: Mechanical-Enforcement Increment 1).
 *
 * WHY THIS AND NOT `spine/event.ts`'s `canonicalize`: that one is `JSON.stringify(sortDeep(v))`, which is NOT a sound
 * basis for a canonical IDENTITY scheme — JSON conflates 1 and 1.0, admits floats / NaN / -0, escapes Unicode
 * ambiguously, has no byte-string type, and its key order is a string sort rather than a defined byte order. An
 * Enforcement-IR obligation's identity must be derived from its canonical SEMANTIC structure (never source text /
 * line numbers), and two encodings of the same meaning MUST collide while any semantic difference MUST diverge.
 *
 * So this implements RFC 8949 §4.2.1 CORE DETERMINISTIC CBOR over a closed value model, zero-dependency (only
 * node:crypto for SHA-256). It is DETERMINISTIC (one meaning -> one byte string), INJECTIVE on the value model, and
 * FAIL-CLOSED on ambiguity: floats, non-integer numbers, NaN/Infinity, `undefined`, non-NFC text, and duplicate map
 * keys are REJECTED rather than silently coerced. `isCanonical` additionally rejects any byte string that is not the
 * canonical encoding of its own decoding (non-shortest ints, indefinite lengths, out-of-order map keys) — so a
 * "canonical" claim over bytes is checkable, not trusted.
 *
 * Grounding: RFC 8949 (deterministic CBOR), RFC 8785 (JCS canonicalization principles), domain-separated hashing.
 */
import { createHash } from "node:crypto";
import { types } from "node:util";

/** The ONLY value shapes the EIR admits. Integers are bigint (no float ambiguity); text must be Unicode NFC. */
export type CanonicalValue =
  | null
  | boolean
  | bigint
  | string
  | Uint8Array
  | readonly CanonicalValue[]
  | { readonly [k: string]: CanonicalValue };

const MAX_DEPTH = 64; // bound recursion; a deeper structure is rejected rather than blowing the stack
const enc8 = new TextEncoder();
const dec8 = new TextDecoder("utf-8", { fatal: true });

class CanonicalError extends Error {
  constructor(msg: string) { super(`EIR-canonical: ${msg}`); this.name = "CanonicalError"; }
}

/**
 * True iff `s` is well-formed UTF-16 — NO unpaired surrogates. This is a HARD injectivity requirement (frontier
 * review, GPT-5.6): `TextEncoder` maps a lone surrogate to U+FFFD, so a string with a lone \uD800 and the string
 * "�" would encode to the SAME bytes and collide to the same id. Rejecting ill-formed text closes that hole.
 */
export function isWellFormedText(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    // High surrogate MUST be followed by a low surrogate. Test with a POSITIVE range check so a missing next code
    // unit (charCodeAt past the end returns NaN — a trailing high surrogate) is rejected: `NaN < 0xdc00` is false,
    // which the old `n < 0xdc00 || n > 0xdfff` form let slip through, colliding "…\uD800" with "…�".
    if (c >= 0xd800 && c <= 0xdbff) { const n = s.charCodeAt(i + 1); if (!(n >= 0xdc00 && n <= 0xdfff)) return false; i++; }
    else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

/** Push a CBOR head: major type (0..7) + argument, in SHORTEST form (deterministic requirement). */
function pushHead(out: number[], major: number, arg: bigint): void {
  const mt = major << 5;
  if (arg < 0n) throw new CanonicalError("internal: negative head argument");
  if (arg < 24n) out.push(mt | Number(arg));
  else if (arg <= 0xffn) out.push(mt | 24, Number(arg));
  else if (arg <= 0xffffn) out.push(mt | 25, Number((arg >> 8n) & 0xffn), Number(arg & 0xffn));
  else if (arg <= 0xffffffffn) {
    out.push(mt | 26);
    for (let s = 24n; s >= 0n; s -= 8n) out.push(Number((arg >> s) & 0xffn));
  } else if (arg <= 0xffffffffffffffffn) {
    out.push(mt | 27);
    for (let s = 56n; s >= 0n; s -= 8n) out.push(Number((arg >> s) & 0xffn));
  } else throw new CanonicalError("integer exceeds 64-bit CBOR argument range");
}

function encInto(v: CanonicalValue, out: number[], depth: number): void {
  if (depth > MAX_DEPTH) throw new CanonicalError(`structure deeper than ${MAX_DEPTH} — rejected`);
  if (v === null) { out.push(0xf6); return; }                       // simple(22) = null
  const t = typeof v;
  if (t === "boolean") { out.push(v ? 0xf5 : 0xf4); return; }        // simple(21)/simple(20)
  if (t === "number") throw new CanonicalError("numbers must be bigint (floats/JS numbers are ambiguous)");
  if (t === "bigint") {                                             // major 0 unsigned / 1 negative
    const n = v as bigint;
    if (n >= 0n) pushHead(out, 0, n);
    else pushHead(out, 1, -1n - n);
    return;
  }
  if (t === "string") {                                            // major 3 text (well-formed + NFC required)
    const s = v as string;
    if (!isWellFormedText(s)) throw new CanonicalError("text has unpaired surrogates (not well-formed Unicode)");
    if (s.normalize("NFC") !== s) throw new CanonicalError("text is not Unicode NFC (normalize before encoding)");
    const bytes = enc8.encode(s);
    pushHead(out, 3, BigInt(bytes.length));
    for (const b of bytes) out.push(b);
    return;
  }
  if (v instanceof Uint8Array) {                                   // major 2 bytes
    pushHead(out, 2, BigInt(v.length));
    for (const b of v) out.push(b);
    return;
  }
  if (Array.isArray(v)) {                                          // major 4 array (ordered)
    pushHead(out, 4, BigInt(v.length));
    for (const e of v) encInto(e as CanonicalValue, out, depth + 1);
    return;
  }
  if (t === "object") {                                            // major 5 map (string keys, deterministic order)
    // FAIL-CLOSED on inadmissible objects (frontier review, GPT-5.6): only a PLAIN object (Object.prototype or null
    // proto) is a map. A Date/Map/Set/class-instance would otherwise `Object.keys()` to nothing and encode as {} —
    // colliding with a real empty map. Reject it instead.
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new CanonicalError("only plain objects are admitted as maps");
    const obj = v as { readonly [k: string]: CanonicalValue };
    const keys = Object.keys(obj);
    // Encode each key, then sort entries by the BYTES of the encoded key (RFC 8949 §4.2.1 deterministic map order).
    const entries = keys.map((k) => {
      if (!isWellFormedText(k)) throw new CanonicalError("map key has unpaired surrogates (not well-formed Unicode)");
      if (k.normalize("NFC") !== k) throw new CanonicalError("map key is not Unicode NFC");
      const kb: number[] = [];
      pushHead(kb, 3, BigInt(enc8.encode(k).length));
      for (const b of enc8.encode(k)) kb.push(b);
      return { kb, v: obj[k]! };
    });
    entries.sort((a, b) => cmpBytes(a.kb, b.kb));
    for (let i = 1; i < entries.length; i++) {
      if (cmpBytes(entries[i - 1]!.kb, entries[i]!.kb) === 0) throw new CanonicalError("duplicate map key after NFC");
    }
    pushHead(out, 5, BigInt(entries.length));
    for (const e of entries) { for (const b of e.kb) out.push(b); encInto(e.v, out, depth + 1); }
    return;
  }
  throw new CanonicalError(`non-canonical value of type ${t}`);
}

function cmpBytes(a: readonly number[], b: readonly number[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i]! !== b[i]!) return a[i]! - b[i]!; }
  return a.length - b.length;
}

/**
 * VALIDATE-AND-CAPTURE in ONE pass into an OWNED, plain-data snapshot (frontier review, GPT-5.6). This closes the
 * validation→encoding TOCTOU: a Proxy or getter could pass a separate `validate` pass and then return different
 * values during a later `encode` pass, and a SharedArrayBuffer-backed view could mutate concurrently. So we read
 * every value EXACTLY ONCE — property values from their DESCRIPTORS (a getter is rejected, never invoked), bytes
 * COPIED off their buffer — building a fresh graph the encoder then serializes. The original is never re-read, so
 * nothing it does after capture can change the encoding. Rejects: floats/JS-numbers, symbols/functions/undefined,
 * accessors, extra own properties, symbol keys, non-enumerable map props, non-plain prototypes, SharedArrayBuffer
 * bytes. The returned snapshot is owned plain data (null-proto maps), so re-reading it is deterministic.
 */
// Intrinsic %TypedArray% getters. A genuine (non-Proxy) Uint8Array can carry an OWN `length`/`buffer` data property
// that SHADOWS the prototype accessor (frontier review, GPT-5.6) — spoofing its apparent length (→ prefix truncation)
// or backing buffer (→ SAB-check bypass). Reading through these bound intrinsic getters returns the true internal
// slot regardless of any own-property shadow.
const TA_PROTO = Object.getPrototypeOf(Uint8Array.prototype) as object;
const taLength = (Object.getOwnPropertyDescriptor(TA_PROTO, "length") as PropertyDescriptor).get as (this: Uint8Array) => number;
const taBuffer = (Object.getOwnPropertyDescriptor(TA_PROTO, "buffer") as PropertyDescriptor).get as (this: Uint8Array) => ArrayBufferLike;
const taByteOffset = (Object.getOwnPropertyDescriptor(TA_PROTO, "byteOffset") as PropertyDescriptor).get as (this: Uint8Array) => number;
const abByteLength = (Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength") as PropertyDescriptor).get as (this: ArrayBuffer) => number;
const abDetached = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "detached")?.get as ((this: ArrayBuffer) => boolean) | undefined;
const abResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get as ((this: ArrayBuffer) => boolean) | undefined;

/**
 * Assert `v` is a LIVE, in-bounds, non-shared Uint8Array view and return its true length. A detached buffer (post
 * `transfer`) or an out-of-bounds length-tracking view (frontier review, GPT-5.6) reads length 0 with no indices —
 * so it would canonicalize as an EMPTY byte string, colliding with a genuine empty Uint8Array instead of failing
 * closed. A RESIZABLE-buffer view is the sharper case (GPT-5.6, 11th pass): once out-of-bounds, BOTH `length` and
 * `byteOffset` intrinsics read 0, so an offset+length bound check cannot distinguish it from a genuine empty view.
 * Therefore reject any view over a resizable OR detached OR shared buffer outright — a non-resizable, non-detached,
 * non-shared buffer can never be out-of-bounds, so its intrinsic length is always trustworthy.
 */
function assertLiveBytes(v: Uint8Array): number {
  const ab = taBuffer.call(v);
  if (typeof SharedArrayBuffer !== "undefined" && ab instanceof SharedArrayBuffer) throw new CanonicalError("SharedArrayBuffer-backed bytes not admitted (concurrently mutable)");
  // Detachment detection must not depend on the ES2024 `detached` getter alone: a runtime can detach via
  // structuredClone/Worker transfer yet lack that getter (GPT-5.6, 12th pass) -> fail-open. Fallback probe:
  // ArrayBuffer.prototype.slice throws TypeError on a detached buffer (spec IsDetachedBuffer), so it detects
  // detachment everywhere; on a live buffer slice(0,0) is a cheap empty copy that returns normally.
  let detached: boolean;
  if (abDetached) detached = abDetached.call(ab as ArrayBuffer) === true;
  else { try { ArrayBuffer.prototype.slice.call(ab as ArrayBuffer, 0, 0); detached = false; } catch { detached = true; } }
  if (detached) throw new CanonicalError("detached ArrayBuffer-backed bytes not admitted");
  if (abResizable && abResizable.call(ab as ArrayBuffer) === true) throw new CanonicalError("resizable ArrayBuffer-backed bytes not admitted (can silently go out-of-bounds)");
  const len = taLength.call(v);
  if (taByteOffset.call(v) + len > abByteLength.call(ab as ArrayBuffer)) throw new CanonicalError("out-of-bounds typed-array view not admitted");
  return len;
}

function capture(v: unknown, depth: number): CanonicalValue {
  if (depth > MAX_DEPTH) throw new CanonicalError(`structure deeper than ${MAX_DEPTH} — rejected`);
  if (v === null) return null;
  // Reject Proxies outright (frontier review, GPT-5.6): a Proxy can spoof getPrototypeOf/ownKeys/getOwnPropertyDescriptor
  // to pass the plain-data checks (e.g. present a Date/Map as an empty plain object colliding with {}). `types.isProxy`
  // (node:util builtin) is the only reliable detector; a Proxy is never admissible canonical data.
  if (types.isProxy(v)) throw new CanonicalError("Proxy values are not admitted (can spoof prototype/keys/descriptors)");
  const t = typeof v;
  if (t === "boolean" || t === "bigint") return v as boolean | bigint;
  if (t === "number") throw new CanonicalError("numbers must be bigint (floats/JS numbers are ambiguous)");
  if (t === "string") { // strings are immutable — well-formed + NFC checked here (once)
    const s = v as string;
    if (!isWellFormedText(s)) throw new CanonicalError("text has unpaired surrogates (not well-formed Unicode)");
    if (s.normalize("NFC") !== s) throw new CanonicalError("text is not Unicode NFC");
    return s;
  }
  if (t === "symbol" || t === "function" || t === "undefined") throw new CanonicalError(`inadmissible value of type ${t}`);
  if (v instanceof Uint8Array) {
    if (Object.getPrototypeOf(v) !== Uint8Array.prototype) throw new CanonicalError("only a plain Uint8Array is admitted");
    const len = assertLiveBytes(v); // TRUE length (intrinsic getter); rejects detached/out-of-bounds/SAB views
    // Own property names of a plain Uint8Array are EXACTLY its integer indices 0..len-1 — any extra name (incl. a
    // shadowing `length`) or any symbol makes it inadmissible.
    if (Object.getOwnPropertyNames(v).length !== len || Object.getOwnPropertySymbols(v).length) throw new CanonicalError("Uint8Array has extra own properties");
    const copy = new Uint8Array(len); // OWNED copy via exotic integer-index reads (unaffected by a `length` shadow)
    for (let i = 0; i < len; i++) copy[i] = v[i]!;
    return copy;
  }
  if (Array.isArray(v)) {
    if (Object.getPrototypeOf(v) !== Array.prototype) throw new CanonicalError("only a plain array is admitted");
    if (Object.getOwnPropertySymbols(v).length) throw new CanonicalError("array has symbol keys");
    if (Object.getOwnPropertyNames(v).length !== v.length + 1) throw new CanonicalError("array has extra own properties beyond its elements");
    const out: CanonicalValue[] = new Array(v.length);
    for (let i = 0; i < v.length; i++) {
      const d = Object.getOwnPropertyDescriptor(v, i);
      if (!d || d.get || d.set || !("value" in d) || !d.enumerable) throw new CanonicalError("array element is an accessor, hole, or non-enumerable");
      out[i] = capture(d.value, depth + 1);
    }
    return out;
  }
  if (t === "object") {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new CanonicalError("only plain objects are admitted as maps");
    if (Object.getOwnPropertySymbols(v as object).length) throw new CanonicalError("map has symbol keys");
    const out: Record<string, CanonicalValue> = Object.create(null); // owned, null-proto (safe for __proto__)
    for (const k of Object.getOwnPropertyNames(v as object)) {
      const d = Object.getOwnPropertyDescriptor(v as object, k)!;
      if (d.get || d.set) throw new CanonicalError("map property is an accessor (getter/setter)");
      if (!d.enumerable) throw new CanonicalError("map has a non-enumerable own property");
      Object.defineProperty(out, k, { value: capture(d.value, depth + 1), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  throw new CanonicalError(`inadmissible value of type ${t}`);
}

/** Deterministically encode a canonical value. Captures an owned snapshot first, then serializes it (no re-read of
 *  the original — TOCTOU-safe). Throws (fail-closed) on any ambiguous/inadmissible/non-faithful input. */
export function encodeCanonical(v: CanonicalValue): Uint8Array {
  const out: number[] = [];
  encInto(capture(v, 0), out, 0);
  return Uint8Array.from(out);
}

// ── Decoder — only to make "is this byte string canonical?" checkable (fail-closed on anything ambiguous) ──

function readHead(b: Uint8Array, p: number): { major: number; arg: bigint; next: number } {
  if (p >= b.length) throw new CanonicalError("truncated");
  const ib = b[p]!, major = ib >> 5, ai = ib & 0x1f;
  if (ai < 24) return { major, arg: BigInt(ai), next: p + 1 };
  if (ai === 24) { if (p + 1 >= b.length) throw new CanonicalError("truncated arg"); const a = BigInt(b[p + 1]!); if (a < 24n) throw new CanonicalError("non-shortest integer"); return { major, arg: a, next: p + 2 }; }
  const len = ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : -1;
  if (len < 0) throw new CanonicalError("indefinite length or reserved additional-info — not canonical");
  if (p + len >= b.length) throw new CanonicalError("truncated multi-byte arg");
  let a = 0n; for (let i = 1; i <= len; i++) a = (a << 8n) | BigInt(b[p + i]!);
  const min = len === 2 ? 0x100n : len === 4 ? 0x10000n : 0x100000000n;
  if (a < min) throw new CanonicalError("non-shortest integer encoding — not canonical");
  return { major, arg: a, next: p + 1 + len };
}

function decodeAt(b: Uint8Array, p: number, depth: number): { v: CanonicalValue; next: number } {
  if (depth > MAX_DEPTH) throw new CanonicalError("too deep");
  const ib = b[p];
  if (ib === 0xf4) return { v: false, next: p + 1 };
  if (ib === 0xf5) return { v: true, next: p + 1 };
  if (ib === 0xf6) return { v: null, next: p + 1 };
  const { major, arg, next } = readHead(b, p);
  switch (major) {
    case 0: return { v: arg, next };
    case 1: return { v: -1n - arg, next };
    case 2: { const end = next + Number(arg); if (end > b.length) throw new CanonicalError("truncated bytes"); return { v: b.slice(next, end), next: end }; }
    case 3: { const end = next + Number(arg); if (end > b.length) throw new CanonicalError("truncated text"); const s = dec8.decode(b.slice(next, end)); if (s.normalize("NFC") !== s) throw new CanonicalError("decoded text not NFC"); return { v: s, next: end }; }
    case 4: { const arr: CanonicalValue[] = []; let q = next; for (let i = 0n; i < arg; i++) { const r = decodeAt(b, q, depth + 1); arr.push(r.v); q = r.next; } return { v: arr, next: q }; }
    case 5: {
      // null-proto object so a "__proto__" key becomes an OWN key (not the prototype) and round-trips (frontier review).
      const obj: Record<string, CanonicalValue> = Object.create(null); let q = next; let prevKb: number[] | null = null;
      for (let i = 0n; i < arg; i++) {
        if (b[q]! >> 5 !== 3) throw new CanonicalError("map key must be a text string");
        const keyStart = q; const kr = decodeAt(b, q, depth + 1); q = kr.next;
        const kb = Array.from(b.slice(keyStart, kr.next));
        if (prevKb && cmpBytes(prevKb, kb) >= 0) throw new CanonicalError("map keys out of canonical order or duplicated");
        prevKb = kb;
        const vr = decodeAt(b, q, depth + 1); q = vr.next;
        Object.defineProperty(obj, kr.v as string, { value: vr.v, enumerable: true, writable: true, configurable: true });
      }
      return { v: obj, next: q };
    }
    default: throw new CanonicalError(`major type ${major} not admitted in the EIR value model`);
  }
}

/**
 * Decode canonical bytes to a value; throws if the bytes are not canonical (fail-closed). Copies the input bytes ONCE
 * up front and does BOTH the decode and the canonical-form verification against that single owned snapshot — so a
 * SharedArrayBuffer-backed / concurrently-mutated input cannot diverge between validation and use (frontier review).
 */
export function decodeCanonical(bytes: Uint8Array): CanonicalValue {
  // Strict input typing (frontier review, GPT-5.6): `Uint8Array.from` COERCES any iterable — from([502]) yields
  // [246] = 0xf6, so a plain array [502] would validate as canonical null (fail-open). Require a real Uint8Array
  // (Proxies rejected — they can spoof instanceof) and copy byte-by-byte through the indexed getter, which returns
  // a true 0..255 byte and cannot be diverted by an overridden `from`/`slice`/iterator.
  if (types.isProxy(bytes)) throw new CanonicalError("input must not be a Proxy");
  if (!(bytes instanceof Uint8Array)) throw new CanonicalError("input must be a Uint8Array");
  const n = assertLiveBytes(bytes); // TRUE length; rejects detached/out-of-bounds/SAB input (shadow-proof)
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = bytes[i]!; // owned copy — one consistent snapshot for decode + re-encode check
  const { v, next } = decodeAt(b, 0, 0);
  if (next !== b.length) throw new CanonicalError("trailing bytes — not canonical");
  const re = encodeCanonical(v); // re-encode the decoded value; canonical iff byte-identical to the snapshot
  if (re.length !== b.length || !re.every((x, i) => x === b[i])) throw new CanonicalError("input is not the canonical encoding of its decoding");
  return v;
}

/** True iff `bytes` is EXACTLY the canonical encoding of its own decoding — rejects every non-canonical form. */
export function isCanonical(bytes: Uint8Array): boolean {
  try { decodeCanonical(bytes); return true; } catch { return false; }
}

/**
 * Domain-separated content ID of a canonical value: SHA-256 over ("keep.eir.v1." + domain + NUL) || canonicalBytes.
 * The domain separator makes IDs of different node kinds non-colliding even when their canonical bytes coincide.
 */
export function eirDigest(domain: string, v: CanonicalValue): string {
  if (typeof domain !== "string") throw new CanonicalError("domain must be a string"); // reject spoofing objects
  if (domain.normalize("NFC") !== domain || domain.includes("\0") || !isWellFormedText(domain)) throw new CanonicalError("bad domain separator");
  const h = createHash("sha256");
  h.update(enc8.encode("keep.eir.v1." + domain + "\0"));
  h.update(encodeCanonical(v));
  return h.digest("hex");
}

/** Semantic equality: two canonical values mean the same thing iff their canonical encodings are byte-identical. */
export function canonicalEqual(a: CanonicalValue, b: CanonicalValue): boolean {
  const ea = encodeCanonical(a), eb = encodeCanonical(b);
  return ea.length === eb.length && ea.every((x, i) => x === eb[i]);
}
