import { test } from "node:test";
import assert from "node:assert/strict";

import { parsePolicyJson, JsonError } from "../src/policy/json.js";
import { encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";

// Mechanical-Enforcement Increment 2 (step A) — STRICT JSON FRONTEND. The frontier property: an accepted document has
// exactly ONE unambiguous reading; every silent-fail-open of JSON.parse is rejected fail-closed. Proven by disproof —
// neutering any rejection in src/policy/json.ts reddens the matching test below:
//   dup-key check    => "duplicate object key REJECTED"
//   float check      => "non-integer numbers REJECTED"
//   trailing check   => "trailing data REJECTED"
//   surrogate check  => "unpaired \\u surrogate REJECTED"

test("duplicate object key is REJECTED (JSON.parse would silently keep the last)", () => {
  assert.throws(() => parsePolicyJson('{"decision":"permit","decision":"deny"}'), /duplicate object key/);
  // sanity: the platform parser silently accepts it (the exact fail-open we defend against)
  assert.equal((JSON.parse('{"decision":"permit","decision":"deny"}') as { decision: string }).decision, "deny");
});

test("non-integer numbers (fraction/exponent/-0) are REJECTED; integers decode to bigint", () => {
  assert.throws(() => parsePolicyJson("1.5"), /non-integer/);
  assert.throws(() => parsePolicyJson("1e3"), /non-integer/);
  assert.throws(() => parsePolicyJson("-0"), /negative zero/);
  assert.throws(() => parsePolicyJson("01"), /(expected|trailing|invalid)/); // leading zero -> 0 then trailing "1"
  assert.equal(parsePolicyJson("42"), 42n);
  assert.equal(parsePolicyJson("-7"), -7n);
  assert.equal(parsePolicyJson("0"), 0n);
});

test("trailing data after the top-level value is REJECTED", () => {
  assert.throws(() => parsePolicyJson("{}  garbage"), /trailing data/);
  assert.throws(() => parsePolicyJson("[1,2] [3]"), /trailing data/);
});

test("unpaired \\u surrogate escapes are REJECTED (no silent U+FFFD)", () => {
  assert.throws(() => parsePolicyJson('"\\uD800"'), /surrogate/);
  assert.throws(() => parsePolicyJson('"\\uDC00"'), /surrogate/);
  assert.throws(() => parsePolicyJson('"\\uD800x"'), /surrogate/);
  // a valid surrogate PAIR is accepted
  assert.equal(parsePolicyJson('"\\uD83D\\uDE00"'), "\u{1F600}");
});

test("well-formedness, BOM, control chars, and bad escapes are rejected", () => {
  assert.throws(() => parsePolicyJson("a\uD800b"), /well-formed/); // lone surrogate in the raw source string
  assert.throws(() => parsePolicyJson("﻿{}"), /byte-order mark/);
  assert.throws(() => parsePolicyJson('"raw\ttab"'), /control character/);
  assert.throws(() => parsePolicyJson('"\\x41"'), /invalid escape/);
});

test("valid nested structures parse to an owned canonical-admissible tree", () => {
  const v = parsePolicyJson('{"a":[true,false,null,"s",3],"b":{"z":-1}}') as Record<string, unknown>;
  assert.deepEqual((v.a as unknown[]), [true, false, null, "s", 3n]);
  assert.deepEqual((v.b as Record<string, unknown>).z, -1n);
  // it is directly encodable by the canonical encoder (bigints, strings, plain shapes)
  assert.doesNotThrow(() => encodeCanonical(v as CanonicalValue));
});

test("a __proto__ key becomes own data, not prototype pollution", () => {
  const v = parsePolicyJson('{"__proto__":1,"ok":2}') as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(v), null);
  assert.equal(v["__proto__"], 1n);
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
});

test("JsonError carries an offset and is the thrown type", () => {
  try { parsePolicyJson("[1,"); assert.fail("should throw"); }
  catch (e) { assert.ok(e instanceof JsonError); assert.equal(typeof e.at, "number"); }
});
