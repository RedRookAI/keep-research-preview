import { test } from "node:test";
import assert from "node:assert/strict";

import { validateSchema, schemaDigest, decodeAgainst, matches, SchemaError, type WireSchema } from "../src/ingress/schema.js";
import { makeAddress, parseAddress, isAddress, INGRESS_KINDS, AddressError } from "../src/ingress/address.js";
import { validateDecl, declId, declKind, declActivation, declToCanonical, IngressError, type IngressDecl } from "../src/ingress/ingress.js";
import { canonicalEqual } from "../src/eir/canonical.js";

// Increment 3 (step A) — ingress ADDRESS + TYPED DECLARATION model. Frontier property: every ingress is NAMED by a
// canonical injective address + TYPED by a content-addressed wire schema; both are deterministic + fail-closed.

// ── schema ──
const rec: WireSchema = { t: "record", fields: [
  { name: "amount", schema: { t: "int" }, optional: false },
  { name: "memo", schema: { t: "str" }, optional: true },
] };

test("schema: valid forms validate; record fields must be sorted + unique; enum values sorted", () => {
  assert.doesNotThrow(() => validateSchema(rec));
  assert.throws(() => validateSchema({ t: "record", fields: [{ name: "b", schema: { t: "int" }, optional: false }, { name: "a", schema: { t: "int" }, optional: false }] }), /sorted/);
  assert.throws(() => validateSchema({ t: "enum", values: ["b", "a"] }), /sorted/);
  assert.throws(() => validateSchema({ t: "enum", values: [] }), /non-empty/);
  assert.throws(() => validateSchema({ t: "nope" }), /unknown schema form/);
  assert.throws(() => validateSchema({ t: "int", extra: 1 }), /extra fields/);
});

test("schema digest is deterministic + injective on meaning", () => {
  assert.equal(schemaDigest(rec), schemaDigest({ t: "record", fields: [
    { name: "amount", schema: { t: "int" }, optional: false }, { name: "memo", schema: { t: "str" }, optional: true },
  ] }));
  assert.notEqual(schemaDigest(rec), schemaDigest({ t: "record", fields: [
    { name: "amount", schema: { t: "str" }, optional: false }, { name: "memo", schema: { t: "str" }, optional: true },
  ] }), "a field type change changes the ABI digest");
});

test("decodeAgainst is total + fail-closed (no coercion; unknown/missing fields rejected)", () => {
  assert.deepEqual(decodeAgainst(rec, { amount: 5n, memo: "hi" }), { amount: 5n, memo: "hi" });
  assert.deepEqual(decodeAgainst(rec, { amount: 5n }), { amount: 5n }, "optional field may be absent");
  assert.throws(() => decodeAgainst(rec, { amount: 5 }), /expected int/, "a JS number is not an int");
  assert.throws(() => decodeAgainst(rec, { memo: "hi" }), /missing required field/);
  assert.throws(() => decodeAgainst(rec, { amount: 5n, extra: 1n }), /unknown record field/);
  assert.equal(matches({ t: "enum", values: ["a", "b"] }, "c"), false);
  assert.equal(matches({ t: "bytes" }, Uint8Array.from([1])), true);
});

test("decodeAgainst is STRICT on own-properties: inherited/undefined/accessor fields are REJECTED", () => {
  // a required field satisfied only via the PROTOTYPE chain is not present (Object.hasOwn), so it's missing
  assert.throws(() => decodeAgainst(rec, Object.create({ amount: 5n }) as object), /missing required field/);
  // a present-but-undefined value is decoded (and rejected), not treated as absent
  assert.throws(() => decodeAgainst(rec, { amount: undefined }), /expected int|missing/);
  // an accessor field is rejected
  const withGetter: Record<string, unknown> = {}; Object.defineProperty(withGetter, "amount", { get: () => 5n, enumerable: true });
  assert.throws(() => decodeAgainst(rec, withGetter), /accessor/);
  // a symbol key is rejected
  const withSym: Record<string, unknown> = { amount: 5n }; (withSym as Record<symbol, unknown>)[Symbol("x")] = 1;
  assert.throws(() => decodeAgainst(rec, withSym), /symbol keys/);
});

// ── address ──
test("address: canonical make/parse round-trip; injective; malformed rejected", () => {
  const a = makeAddress("http", "orders.create");
  assert.equal(a, "keep:ingress:v1:http:orders.create");
  assert.deepEqual(parseAddress(a), { kind: "http", name: "orders.create" });
  assert.equal(isAddress(a), true);
  assert.throws(() => makeAddress("ftp", "x"), /unknown ingress kind/);
  assert.throws(() => makeAddress("http", "Orders"), /name/); // uppercase rejected
  assert.throws(() => makeAddress("http", "a:b"), /name/);     // second colon rejected
  assert.equal(isAddress("keep:ingress:v1:http:"), false);     // empty name
  assert.equal(isAddress("http:orders.create"), false);        // missing prefix
  assert.equal(isAddress("keep:ingress:v1:http:a:b"), false);  // extra colon -> non-canonical
});

test("address: all eight kinds are addressable", () => {
  for (const k of INGRESS_KINDS) assert.equal(parseAddress(makeAddress(k, "x")).kind, k);
  assert.equal(INGRESS_KINDS.length, 8);
});

// ── declaration ──
function decl(over: Partial<IngressDecl> = {}): IngressDecl {
  return { address: makeAddress("http", "orders.create"), abiVersion: 1n, input: rec, output: { t: "null" }, error: { t: "str" }, cardinality: "single", ...over };
}

test("declaration: validates, derives kind + activation, has content id", () => {
  const d = validateDecl(decl());
  assert.equal(declKind(d), "http");
  assert.equal(declActivation(d), "listener");
  assert.equal(declActivation(validateDecl(decl({ address: makeAddress("timer", "nightly") }))), "scheduled");
  assert.equal(declActivation(validateDecl(decl({ address: makeAddress("cli", "run") }))), "invoked");
  assert.match(declId(d), /^[0-9a-f]{64}$/);
});

test("declaration: identity is derived from content; any ABI change changes the id", () => {
  assert.equal(declId(decl()), declId(decl()));
  assert.notEqual(declId(decl()), declId(decl({ input: { t: "null" } })), "different input schema => different decl");
  assert.notEqual(declId(decl()), declId(decl({ cardinality: "multi" })));
  assert.ok(canonicalEqual(declToCanonical(decl()), declToCanonical(decl())));
});

test("declaration: fail-closed on unknown field, bad abiVersion, non-canonical address", () => {
  assert.throws(() => validateDecl({ ...decl(), sneaky: 1 }), /unknown field/);
  assert.throws(() => validateDecl(decl({ abiVersion: 0n })), /abiVersion/);
  assert.throws(() => validateDecl({ ...decl(), address: "not-canonical" }), /address/);
  assert.throws(() => validateDecl(decl({ cardinality: "lots" as "single" })), /cardinality/);
});
