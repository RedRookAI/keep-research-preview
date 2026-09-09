import { test } from "node:test";
import assert from "node:assert/strict";

import {
  encodeCanonical, decodeCanonical, isCanonical, eirDigest, canonicalEqual, isWellFormedText, type CanonicalValue,
} from "../src/eir/canonical.js";
import {
  toCanonical, eirId, guardId, effectId, nodeEqual, validateNode, encodeNode, decodeNode,
  type Guard, type Effect, type Obligation, type Principal,
} from "../src/eir/eir.js";

// BUILD-ORDER Mechanical-Enforcement Increment 1 — CANONICAL ENFORCEMENT IR. The frontier property: the canonical
// encoding is DETERMINISTIC + INJECTIVE on meaning and FAIL-CLOSED on ambiguity, and a node's id is DERIVED from its
// canonical content. Proven by disproof — the neuters live in src/eir/canonical.ts + src/eir/eir.ts:
//   sort → remove map-key sort         => Test "determinism: map key order"        RED
//   float → drop the number rejection   => Test "ambiguity: JS number rejected"      RED
//   domain → drop the domain separator  => Test "domain separation"                  RED
//   nfc → drop the NFC text rejection    => Test "ambiguity: non-NFC text rejected"    RED

const g = (predicate: string): Guard => ({ kind: "guard", predicate });
const e = (t: string, r: string, cls: Effect["cls"]): Effect => ({ kind: "effect", effectType: t, resourceSelector: r, cls });

test("determinism: map key order does NOT change the encoding or digest", () => {
  const a: CanonicalValue = { alpha: 1n, beta: 2n, gamma: 3n };
  const b: CanonicalValue = { gamma: 3n, alpha: 1n, beta: 2n };
  assert.deepEqual(Array.from(encodeCanonical(a)), Array.from(encodeCanonical(b)), "canonical map order is content-defined, not insertion order");
  assert.equal(eirDigest("t", a), eirDigest("t", b));
});

test("determinism: obligation subject/entry SET order + multiplicity do not change identity", () => {
  const o1: Obligation = { kind: "obligation", subjects: ["b", "a", "a"], entryPoints: ["y", "x"], effectId: "0".repeat(64), guardId: "1".repeat(64) };
  const o2: Obligation = { kind: "obligation", subjects: ["a", "b"], entryPoints: ["x", "y"], effectId: "0".repeat(64), guardId: "1".repeat(64) };
  assert.equal(eirId(o1), eirId(o2), "subjects/entryPoints are sets — order and duplicates are not semantic");
  assert.ok(nodeEqual(o1, o2));
});

test("injectivity: any semantic change yields a different id", () => {
  const base = g("path.within-root");
  assert.notEqual(guardId(base), guardId(g("path.within-ROOT")), "a different predicate is a different guard");
  assert.notEqual(effectId(e("fs.write", "/a", "destructive")), effectId(e("fs.write", "/a", "recoverable")), "a different class is a different effect");
  assert.notEqual(effectId(e("fs.write", "/a", "external")), effectId(e("fs.write", "/b", "external")), "a different resource is a different effect");
});

test("domain separation: identical canonical bytes under different domains give different digests", () => {
  const v: CanonicalValue = { x: 1n };
  assert.notEqual(eirDigest("guard", v), eirDigest("effect", v), "domain separator distinguishes node kinds even on colliding bytes");
});

test("ambiguity: a JS number (float-capable) is REJECTED, only bigint integers admitted", () => {
  assert.throws(() => encodeCanonical(1 as unknown as CanonicalValue), /bigint/, "JS numbers carry float ambiguity → rejected");
  assert.throws(() => encodeCanonical(1.5 as unknown as CanonicalValue), /bigint/);
  assert.doesNotThrow(() => encodeCanonical(1n));
});

test("ambiguity: non-NFC text is REJECTED (no silent normalization into a different identity)", () => {
  const nfd = "é"; // 'é' as e + combining acute (NFD); NFC form is a single codepoint
  assert.notEqual(nfd.normalize("NFC"), nfd);
  assert.throws(() => encodeCanonical(nfd), /NFC/);
  assert.throws(() => encodeCanonical({ [nfd]: 1n }), /NFC/, "non-NFC map keys rejected too");
});

test("strict form: non-canonical bytes are rejected by isCanonical (non-shortest int, trailing garbage, bad map order)", () => {
  // 0x18 0x05 = uint8 encoding of 5, but 5 fits in the 1-byte form (0x05) → non-shortest → not canonical.
  assert.equal(isCanonical(Uint8Array.from([0x18, 0x05])), false);
  assert.equal(isCanonical(Uint8Array.from([0x05])), true);
  // trailing garbage after a valid item.
  assert.equal(isCanonical(Uint8Array.from([0x05, 0x00])), false);
  // a well-formed value round-trips and is canonical.
  const bytes = encodeCanonical({ a: 1n, b: ["x", 2n] });
  assert.equal(isCanonical(bytes), true);
  assert.ok(canonicalEqual(decodeCanonical(bytes), { a: 1n, b: ["x", 2n] }));
});

test("round-trip: encode → decode preserves meaning across all admitted shapes", () => {
  const v: CanonicalValue = { n: null, t: true, f: false, i: -5n, s: "hi", bytes: Uint8Array.from([1, 2, 255]), arr: [1n, "x"], m: { z: 0n } };
  assert.ok(canonicalEqual(decodeCanonical(encodeCanonical(v)), v));
});

test("node encode/decode is fail-closed on schema violations (unknown field, wrong type)", () => {
  assert.throws(() => validateNode({ kind: "guard", predicate: "p", extra: 1 } as unknown), /unknown field/);
  assert.throws(() => validateNode({ kind: "effect", effectType: "fs", resourceSelector: "/", cls: "nope" } as unknown), /EffectClass/);
  const gd = g("p");
  assert.ok(nodeEqual(decodeNode(encodeNode(gd)), gd));
});

test("ambiguity: unpaired surrogates are REJECTED (TextEncoder would map a lone surrogate to U+FFFD -> ID collision)", () => {
  const lone = "a\uD800b"; // unpaired high surrogate (mid-string)
  assert.throws(() => encodeCanonical(lone), /surrogate/);
  assert.throws(() => encodeCanonical({ [lone]: 1n }), /surrogate/, "surrogate map keys rejected too");
  assert.throws(() => eirDigest("t", lone), /surrogate/);
});

test("ambiguity: a TRAILING high surrogate is REJECTED (regression: charCodeAt past end is NaN -> collides with U+FFFD)", () => {
  // Cross-family review (Fable) found isWellFormedText let a trailing high surrogate slip: charCodeAt(i+1)=NaN and
  // `NaN < 0xdc00 || NaN > 0xdfff` is false. TextEncoder then maps "ghost\uD800" and "ghost�" to the SAME bytes.
  const trailing = "ghost\uD800";
  const replacement = "ghost�";
  assert.equal(isWellFormedText(trailing), false, "trailing high surrogate is NOT well-formed");
  assert.equal(isWellFormedText(replacement), true, "the literal replacement char IS well-formed");
  assert.throws(() => eirDigest("t", trailing), /surrogate/, "the ill-formed string must not get an id");
  // the well-formed one still hashes — and had they both been admitted they would have COLLIDED (the bug).
  assert.match(eirDigest("t", replacement), /^[0-9a-f]{64}$/);
  // a lone LOW surrogate (leading) is still rejected.
  assert.equal(isWellFormedText("\uDC00x"), false);
});

test("fail-closed: non-plain objects (Date/Map) are REJECTED, not encoded as {} (collision)", () => {
  assert.throws(() => encodeCanonical(new Date() as unknown as CanonicalValue), /plain objects/);
  assert.throws(() => encodeCanonical(new Map() as unknown as CanonicalValue), /plain objects/);
  assert.throws(() => encodeCanonical(new Set() as unknown as CanonicalValue), /plain objects/);
});

test("__proto__ is an OWN data key that round-trips (no prototype pollution on decode)", () => {
  const v: CanonicalValue = { ["__proto__"]: 1n, a: 2n };
  const bytes = encodeCanonical(v);
  assert.equal(isCanonical(bytes), true, "a map with a __proto__ key is valid canonical and must be recognized");
  const back = decodeCanonical(bytes) as Record<string, CanonicalValue>;
  assert.equal(back["__proto__"], 1n, "__proto__ decodes to an own data property, not the prototype");
  assert.ok(canonicalEqual(back, v));
});

test("faithful: accessor properties + extra array/bytes properties are REJECTED (no silent projection)", () => {
  const withGetter: Record<string, unknown> = {}; Object.defineProperty(withGetter, "x", { get: () => 1n, enumerable: true });
  assert.throws(() => encodeCanonical(withGetter as CanonicalValue), /accessor/);
  const arr = [1n, 2n]; (arr as unknown as Record<string, unknown>)["foo"] = 3n;
  assert.throws(() => encodeCanonical(arr as unknown as CanonicalValue), /extra own properties/);
  const u = Uint8Array.from([1, 2]); (u as unknown as Record<string, unknown>)["foo"] = 3;
  assert.throws(() => encodeCanonical(u as unknown as CanonicalValue), /extra own properties/);
  const nonEnum: Record<string, unknown> = {}; Object.defineProperty(nonEnum, "y", { value: 1n, enumerable: false });
  assert.throws(() => encodeCanonical(nonEnum as CanonicalValue), /non-enumerable/);
});

test("TOCTOU-safe: SharedArrayBuffer-backed bytes are REJECTED (concurrently mutable); values captured once", () => {
  if (typeof SharedArrayBuffer !== "undefined") {
    const sab = new Uint8Array(new SharedArrayBuffer(4));
    assert.throws(() => encodeCanonical(sab as unknown as CanonicalValue), /SharedArrayBuffer/);
  }
  // decode copies its input, so a valid round-trip is stable regardless of later mutation of the source bytes.
  const bytes = encodeCanonical({ a: 1n });
  const copy = Uint8Array.from(bytes);
  const v = decodeCanonical(bytes);
  assert.ok(canonicalEqual(v, { a: 1n }));
  assert.deepEqual(Array.from(bytes), Array.from(copy), "decode did not mutate its input");
});

test("faithful: a Proxy that spoofs a plain object is REJECTED (cannot pass as {} or a fake map)", () => {
  const evil = new Proxy(new Map() as unknown as object, { getPrototypeOf: () => Object.prototype, ownKeys: () => [], getOwnPropertyDescriptor: () => undefined });
  assert.throws(() => encodeCanonical(evil as unknown as CanonicalValue), /Proxy/);
  const okObj = { a: 1n }; // a plain object is not a proxy and encodes fine
  assert.doesNotThrow(() => encodeCanonical(okObj));
});

test("eirDigest rejects a non-string domain (spoofing object with normalize/includes)", () => {
  const fake = { normalize: () => fake, includes: () => false } as unknown as string;
  assert.throws(() => eirDigest(fake, { a: 1n }), /domain must be a string/);
});

test("strict input: decodeCanonical/isCanonical reject non-Uint8Array inputs (no coercion fail-open)", () => {
  // Uint8Array.from([502]) would coerce to [246]=0xf6 (null); a plain array must NOT validate as canonical.
  assert.equal(isCanonical([502] as unknown as Uint8Array), false);
  assert.equal(isCanonical([0x05] as unknown as Uint8Array), false, "even a value-valid array is not a byte buffer");
  assert.throws(() => decodeCanonical([0x05] as unknown as Uint8Array), /Uint8Array/);
  assert.equal(isCanonical(Uint8Array.from([0x05])), true, "a real Uint8Array still validates");
});

test("shadowing: an own `length` on a Uint8Array cannot truncate decode or spoof the extra-property check", () => {
  const two = Uint8Array.from([0xf6, 0x00]); // 0xf6=null then a trailing byte -> NOT canonical (trailing garbage)
  Object.defineProperty(two, "length", { value: 1, configurable: true }); // shadow the true length with 1
  assert.equal((two as Uint8Array).length, 1, "own length shadows the getter");
  assert.equal(isCanonical(two), false, "true length is read via the intrinsic getter -> trailing byte is seen -> rejected");
  const bytes = Uint8Array.from([0x01]); // a value inside a bytes field, shadowed length
  Object.defineProperty(bytes, "length", { value: 0, configurable: true });
  assert.throws(() => encodeCanonical({ b: bytes } as unknown as CanonicalValue), /extra own properties/, "shadowing length is an extra own property");
});

test("fail-closed: a detached Uint8Array is REJECTED, not silently canonicalized as empty bytes", () => {
  const u = Uint8Array.from([1, 2, 3]);
  // Detach the backing buffer (structuredClone transfer) if supported on this runtime.
  if (typeof (u.buffer as ArrayBuffer & { transfer?: () => ArrayBuffer }).transfer === "function") {
    (u.buffer as ArrayBuffer & { transfer: () => ArrayBuffer }).transfer();
    assert.throws(() => encodeCanonical(u as unknown as CanonicalValue), /detached|out-of-bounds/, "detached view must fail closed, not collide with empty bytes");
    // and it must NOT equal a genuine empty Uint8Array's encoding
    assert.throws(() => encodeCanonical({ b: u } as unknown as CanonicalValue), /detached|out-of-bounds/);
  }
  assert.doesNotThrow(() => encodeCanonical(new Uint8Array(0)), "a genuine empty Uint8Array is still admitted");
});

test("fail-closed: a Uint8Array over a resizable ArrayBuffer is REJECTED (out-of-bounds collision surface)", () => {
  // Resizable ArrayBuffers can shrink a view out-of-bounds where length AND byteOffset both read 0 (== empty).
  const RAB = ArrayBuffer as unknown as { new (len: number, opts: { maxByteLength: number }): ArrayBuffer };
  let rab: ArrayBuffer;
  try { rab = new RAB(4, { maxByteLength: 8 }); } catch { return; } // runtime lacks resizable buffers -> skip
  if (!(rab as ArrayBuffer & { resizable?: boolean }).resizable) return;
  const view = new Uint8Array(rab, 0, 4);
  assert.throws(() => encodeCanonical(view as unknown as CanonicalValue), /resizable/, "resizable-backed bytes must fail closed even while in-bounds");
  assert.doesNotThrow(() => encodeCanonical(new Uint8Array(4)), "a normal fixed-buffer Uint8Array is still admitted");
});

test("golden vector: a pinned guard id does not silently drift", () => {
  // If the canonical encoding or domain scheme changes, this digest changes — a deliberate, reviewed break, never silent.
  assert.equal(guardId(g("path.within-root")), "f4a0dc254f16b98bfaf9283f224a5b636740108e1ef6d5e13860d8121d523e27");
});
