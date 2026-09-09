/**
 * Ingress DECLARATION model (Mechanical-Enforcement Increment 3).
 *
 * A declaration is the signed, content-addressed ABI of ONE executable entrypoint: its canonical address (Increment-3
 * `address.ts`), ABI version, and input/output/error wire schemas (`schema.ts`), plus cardinality. Identity is DERIVED
 * from the canonical content — a declaration cannot lie about its own id, and the manifest binds the exact set.
 *
 * SCOPE (honest seams): the declaration is ABI METADATA only. The concrete handler CODE is bound in-process by the
 * registry at collection time; binding a handler-artifact DIGEST + measured boundary is Increment 5 (attested monitor
 * boundary). Runtime activation-witness reconciliation (that the live listeners equal the declared set) is the adapter
 * layer. Principal establishment + permits are Increment 8. This increment fixes the INVENTORY + its ABI + identity.
 */
import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import { parseAddress, type IngressKind } from "./address.js";
import { validateSchema, schemaToCanonical, type WireSchema } from "./schema.js";

/** How an ingress is activated — DERIVED from its kind. Kinds that hold a live listener/scheduler need an activation
 * witness at startup (reconciliation is the deferred adapter-layer seam); `invoked`/`lifecycle`/`loaded` do not. */
export type ActivationMode = "listener" | "scheduled" | "invoked" | "lifecycle" | "loaded";
const ACTIVATION_OF: Readonly<Record<IngressKind, ActivationMode>> = {
  http: "listener", ipc: "listener", queue: "listener", signal: "listener",
  timer: "scheduled", cli: "invoked", lifecycle: "lifecycle", plugin: "loaded",
};
export const activationOf = (kind: IngressKind): ActivationMode => ACTIVATION_OF[kind];

export type Cardinality = "single" | "multi";
const CARDINALITIES: readonly Cardinality[] = ["single", "multi"];

export interface IngressDecl {
  readonly address: string;
  readonly abiVersion: bigint;
  readonly input: WireSchema;
  readonly output: WireSchema;
  readonly error: WireSchema;
  readonly cardinality: Cardinality;
}

export class IngressError extends Error { constructor(m: string) { super(`ingress decl: ${m}`); this.name = "IngressError"; } }

/** Validate a declaration against its closed schema (address canonical, schemas well-formed, no extra fields). Throws. */
export function validateDecl(d: unknown): IngressDecl {
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw new IngressError("declaration must be an object");
  const o = d as Record<string, unknown>;
  const allowed = ["address", "abiVersion", "input", "output", "error", "cardinality"];
  for (const k of Object.keys(o)) if (!allowed.includes(k)) throw new IngressError(`unknown field "${k}"`);
  parseAddress(o.address); // throws unless a canonical address
  if (typeof o.abiVersion !== "bigint" || o.abiVersion < 1n) throw new IngressError("abiVersion must be an int >= 1");
  if (typeof o.cardinality !== "string" || !CARDINALITIES.includes(o.cardinality as Cardinality)) throw new IngressError("cardinality must be 'single' or 'multi'");
  const input = validateSchema(o.input);
  const output = validateSchema(o.output);
  const error = validateSchema(o.error);
  return { address: o.address as string, abiVersion: o.abiVersion, input, output, error, cardinality: o.cardinality as Cardinality };
}

/** The kind of a (validated) declaration, from its address. */
export const declKind = (d: IngressDecl): IngressKind => parseAddress(d.address).kind;
/** The activation mode of a declaration (derived from its kind). */
export const declActivation = (d: IngressDecl): ActivationMode => activationOf(declKind(d));

/** Canonical value of a declaration — explicit field mapping (no stray field can leak into identity). */
export function declToCanonical(d: IngressDecl): CanonicalValue {
  const v = validateDecl(d);
  return {
    address: v.address,
    abiVersion: v.abiVersion,
    input: schemaToCanonical(v.input),
    output: schemaToCanonical(v.output),
    error: schemaToCanonical(v.error),
    cardinality: v.cardinality,
  };
}

/** Content-derived id of a declaration (domain-separated). */
export function declId(d: IngressDecl): string { return eirDigest("keep.ingress.decl.v1", declToCanonical(d)); }
