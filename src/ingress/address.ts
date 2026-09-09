/**
 * Canonical ingress ADDRESS (Mechanical-Enforcement Increment 3, "named + policy-addressable" leg).
 *
 * Every executable entrypoint has ONE canonical, versioned, kind-qualified address — `keep:ingress:v1:<kind>:<name>`
 * — never a route string, display name, wildcard, alias, or deployment-specific port. The address is the STABLE
 * policy identity: a policy rule's `entryPoints[]` (Increment 2) reference these strings, and the manifest requires
 * exact set-equality between the addresses it declares and the entryPoints a compiled policy references (closed-world
 * coverage). Addresses are INJECTIVE: one declaration ⇄ one address.
 *
 * Grounding: canonical versioned identifiers over free-form route strings; deny-by-default naming; the closed-world
 * assumption (an address that is not declared does not exist).
 */
import { isWellFormedText } from "../eir/canonical.js";

export const ADDRESS_PREFIX = "keep:ingress:v1:";

/** The closed set of ingress kinds (the minimal-complete taxonomy). Adding a kind is a reviewed, digest-breaking change. */
export const INGRESS_KINDS = ["http", "cli", "ipc", "timer", "queue", "lifecycle", "plugin", "signal"] as const;
export type IngressKind = typeof INGRESS_KINDS[number];
export const isIngressKind = (x: unknown): x is IngressKind => typeof x === "string" && (INGRESS_KINDS as readonly string[]).includes(x);

export class AddressError extends Error { constructor(m: string) { super(`ingress address: ${m}`); this.name = "AddressError"; } }

// A name segment: NFC, well-formed, non-empty, no ':' (the separator) and no whitespace/control — so an address parses
// unambiguously back into (kind, name) and cannot smuggle a second colon-delimited field.
const NAME_RE = /^[a-z0-9]+([._-][a-z0-9]+)*$/;

/** Build a canonical address from a kind + name, validating both. */
export function makeAddress(kind: string, name: string): string {
  if (!isIngressKind(kind)) throw new AddressError(`unknown ingress kind "${kind}"`);
  if (typeof name !== "string" || !isWellFormedText(name) || name.normalize("NFC") !== name || !NAME_RE.test(name)) {
    throw new AddressError(`name "${name}" must match ${NAME_RE} (lowercase dotted/dashed segments)`);
  }
  return `${ADDRESS_PREFIX}${kind}:${name}`;
}

export interface ParsedAddress { readonly kind: IngressKind; readonly name: string; }

/** Parse + validate a canonical address, or throw. Round-trips with makeAddress. */
export function parseAddress(address: unknown): ParsedAddress {
  if (typeof address !== "string" || !address.startsWith(ADDRESS_PREFIX)) throw new AddressError("address must start with the canonical prefix");
  const rest = address.slice(ADDRESS_PREFIX.length);
  const colon = rest.indexOf(":");
  if (colon < 0) throw new AddressError("address missing kind:name separator");
  const kind = rest.slice(0, colon);
  const name = rest.slice(colon + 1);
  if (!isIngressKind(kind)) throw new AddressError(`unknown ingress kind "${kind}"`);
  if (!NAME_RE.test(name) || name.normalize("NFC") !== name || !isWellFormedText(name)) throw new AddressError(`malformed name "${name}"`);
  // reconstruct to guarantee the input was EXACTLY canonical (no extra colons, no non-canonical spelling).
  if (makeAddress(kind, name) !== address) throw new AddressError("address is not in canonical form");
  return { kind, name };
}

/** True iff `address` is a syntactically-valid canonical ingress address. */
export function isAddress(address: unknown): address is string {
  try { parseAddress(address); return true; } catch { return false; }
}
