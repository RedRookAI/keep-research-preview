/**
 * Canonical WIRE SCHEMA for ingress ABIs (Mechanical-Enforcement Increment 3, "typed" leg).
 *
 * "Typed" in "no executable entrypoint exists unless it is named, TYPED, and policy-addressable" must be a canonical,
 * runtime-checkable, content-addressable ABI — NOT erased TypeScript annotations (which vanish at runtime and cannot
 * be signed). This is a small CLOSED schema algebra: every ingress declaration carries input/output/error schemas as
 * values of this type, each has a stable digest that binds the ABI into the signed manifest, and the registry decodes
 * a live request against the declared input schema BEFORE the handler runs (a mistyped request fails closed).
 *
 * The algebra is deliberately minimal + total: null, bool, int (bigint — floats are ambiguous, per canonical.ts),
 * str (NFC well-formed), bytes, enum (closed value set), list, record (named optional/required fields). It composes
 * the Increment-1 canonical encoder for determinism + identity; it interprets NO field meanings (that is the handler's
 * job). Extending the algebra is a reviewed, digest-breaking change — never silent.
 *
 * Grounding: canonical wire schemas with digest-bound ABI identity (vs erased types); RFC 8949 deterministic CBOR;
 * closed-world / total parsers (a value either matches exactly or is rejected — no coercion).
 */
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";

export type WireSchema =
  | { readonly t: "null" }
  | { readonly t: "bool" }
  | { readonly t: "int" }
  | { readonly t: "str" }
  | { readonly t: "bytes" }
  | { readonly t: "enum"; readonly values: readonly string[] }
  | { readonly t: "list"; readonly elem: WireSchema }
  | { readonly t: "record"; readonly fields: readonly WireField[] };
export interface WireField { readonly name: string; readonly schema: WireSchema; readonly optional: boolean; }

export class SchemaError extends Error { constructor(m: string) { super(`ingress schema: ${m}`); this.name = "SchemaError"; } }

const MAX_DEPTH = 32;
const isNfc = (x: unknown): x is string => typeof x === "string" && x.length > 0 && isWellFormedText(x) && x.normalize("NFC") === x;

/** Validate a schema is well-formed (closed forms; NFC + sorted + unique enum values and record field names). Throws. */
export function validateSchema(s: unknown, depth = 0): WireSchema {
  if (depth > MAX_DEPTH) throw new SchemaError(`schema nested deeper than ${MAX_DEPTH}`);
  if (s === null || typeof s !== "object" || Array.isArray(s)) throw new SchemaError("schema must be an object");
  const o = s as Record<string, unknown>;
  const nkeys = Object.keys(o).length;
  switch (o.t) {
    case "null": case "bool": case "int": case "str": case "bytes":
      if (nkeys !== 1) throw new SchemaError(`scalar schema "${o.t}" has extra fields`);
      return { t: o.t };
    case "enum": {
      if (nkeys !== 2 || !Array.isArray(o.values) || o.values.length === 0) throw new SchemaError("enum needs a non-empty values[]");
      const seen = new Set<string>();
      for (const v of o.values) { if (!isNfc(v)) throw new SchemaError("enum value must be non-empty NFC text"); if (seen.has(v)) throw new SchemaError("enum has duplicate values"); seen.add(v); }
      if (o.values.some((v, i) => i > 0 && (v as string) < (o.values as string[])[i - 1]!)) throw new SchemaError("enum values must be sorted");
      return { t: "enum", values: [...o.values as string[]] };
    }
    case "list":
      if (nkeys !== 2) throw new SchemaError("list has extra fields");
      return { t: "list", elem: validateSchema(o.elem, depth + 1) };
    case "record": {
      if (nkeys !== 2 || !Array.isArray(o.fields)) throw new SchemaError("record needs fields[]");
      const seen = new Set<string>();
      const fields: WireField[] = [];
      for (const f of o.fields) {
        if (f === null || typeof f !== "object" || Array.isArray(f)) throw new SchemaError("record field must be an object");
        const fo = f as Record<string, unknown>;
        if (Object.keys(fo).length !== 3 || !isNfc(fo.name) || typeof fo.optional !== "boolean") throw new SchemaError("record field must be {name, schema, optional}");
        if (seen.has(fo.name)) throw new SchemaError(`record has duplicate field "${fo.name}"`);
        seen.add(fo.name);
        fields.push({ name: fo.name, schema: validateSchema(fo.schema, depth + 1), optional: fo.optional });
      }
      if (fields.some((f, i) => i > 0 && f.name < fields[i - 1]!.name)) throw new SchemaError("record fields must be sorted by name");
      return { t: "record", fields };
    }
    default:
      throw new SchemaError(`unknown schema form ${JSON.stringify(o.t)}`);
  }
}

/** Canonical value of a schema (record fields already sorted by validateSchema) — the basis of its digest. */
export function schemaToCanonical(s: WireSchema): CanonicalValue {
  switch (s.t) {
    case "null": case "bool": case "int": case "str": case "bytes": return { t: s.t };
    case "enum": return { t: "enum", values: [...s.values] };
    case "list": return { t: "list", elem: schemaToCanonical(s.elem) };
    case "record": return { t: "record", fields: s.fields.map((f) => ({ name: f.name, schema: schemaToCanonical(f.schema), optional: f.optional })) };
  }
}

/** Domain-separated content id of a schema — binds the ABI identity into the signed manifest. */
export function schemaDigest(s: WireSchema): string { return eirDigest("keep.ingress.schema.v1", schemaToCanonical(validateSchema(s))); }

/**
 * Decode a runtime value against a schema, TOTAL + fail-closed: returns the value (narrowed) or throws SchemaError.
 * No coercion — an int must be a bigint, bytes a Uint8Array, etc. Records reject unknown + missing-required fields.
 * This is the registry's "input decoded against type(d)" gate before a handler runs.
 */
export function decodeAgainst(s: WireSchema, v: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new SchemaError(`value nested deeper than ${MAX_DEPTH}`);
  switch (s.t) {
    case "null": if (v !== null) throw new SchemaError("expected null"); return null;
    case "bool": if (typeof v !== "boolean") throw new SchemaError("expected bool"); return v;
    case "int": if (typeof v !== "bigint") throw new SchemaError("expected int (bigint)"); return v;
    case "str": if (!isNfc(v)) throw new SchemaError("expected non-empty NFC str"); return v;
    case "bytes": if (!(v instanceof Uint8Array)) throw new SchemaError("expected bytes"); return v;
    case "enum": if (typeof v !== "string" || !s.values.includes(v)) throw new SchemaError("value not in enum"); return v;
    case "list": {
      if (!Array.isArray(v)) throw new SchemaError("expected list");
      return v.map((e) => decodeAgainst(s.elem, e, depth + 1));
    }
    case "record": {
      if (v === null || typeof v !== "object" || Array.isArray(v)) throw new SchemaError("expected record");
      const o = v as Record<string, unknown>;
      // Strict OWN-property decoding: presence is Object.hasOwn (never inherited via the prototype chain), every own
      // property must be a declared, enumerable DATA field (reject accessors, symbols, and undeclared own keys), and a
      // present-but-`undefined` value is decoded (and rejected) — not silently treated as absent. No coercion anywhere.
      if (Object.getOwnPropertySymbols(o).length) throw new SchemaError("record has symbol keys");
      const allowed = new Set(s.fields.map((f) => f.name));
      for (const k of Object.getOwnPropertyNames(o)) {
        if (!allowed.has(k)) throw new SchemaError(`unknown record field "${k}"`);
        const d = Object.getOwnPropertyDescriptor(o, k)!;
        if (d.get || d.set || !d.enumerable) throw new SchemaError(`record field "${k}" is an accessor or non-enumerable`);
      }
      const out: Record<string, unknown> = {};
      for (const f of s.fields) {
        if (!Object.hasOwn(o, f.name)) { if (!f.optional) throw new SchemaError(`missing required field "${f.name}"`); continue; }
        out[f.name] = decodeAgainst(f.schema, o[f.name], depth + 1);
      }
      return out;
    }
  }
}

/** True iff `v` decodes cleanly against `s`. */
export function matches(s: WireSchema, v: unknown): boolean {
  try { decodeAgainst(s, v); return true; } catch { return false; }
}
