/**
 * Sealed INGRESS REGISTRY (Mechanical-Enforcement Increment 3, the runtime kernel).
 *
 * A one-way state machine — COLLECTING → SEALED → ACTIVE — that makes the closed-world property load-bearing at
 * runtime:
 *   - COLLECTING: declarations + their in-process handlers are registered. Duplicate addresses are rejected.
 *   - seal(manifest, policyBundle): the collected set must EXACTLY equal the signed manifest's declaration set (BOOT
 *     CLOSURE), the manifest must verify and cover the policy (E_M = E_P), then a closure-private dispatch table is
 *     built and the registry is frozen. There is NO unseal/reseal (TEMPORAL CLOSURE) — registering after COLLECTING
 *     throws.
 *   - activate(): SEALED → ACTIVE. (Reconciling that the live listeners equal the declared activation set — the
 *     "activation closure" obligation — is the deferred adapter-layer seam; this increment gates DISPATCH on ACTIVE.)
 *   - dispatch(address, input): ACTIVE only. Unknown address, pre-active dispatch, or an input that fails to decode
 *     against the declared schema fails CLOSED before any handler runs; the handler's output is decoded against the
 *     declared output schema too (the typed contract is bidirectional).
 *
 * The security boundary is the private state + the phase gate (Object.freeze is defense-in-depth): no method exposes
 * the dispatch table, and no path adds an entry after seal. STATIC closure (no listener exists OUTSIDE this registry)
 * is the build-time scanner's job — without it this registry would be bypassable.
 */
import { validateDecl, declId, type IngressDecl } from "./ingress.js";
import { decodeAgainst } from "./schema.js";
import { verifyManifest, type SignedManifest } from "./ingress_manifest.js";
import type { SignedBundle } from "../policy/compiler.js";
import type { TrustPolicy } from "../bom/bom_signing.js";

export type IngressHandler = (input: unknown) => unknown | Promise<unknown>;
export type RegistryPhase = "collecting" | "sealed" | "active";

interface Entry { readonly decl: IngressDecl; readonly handler: IngressHandler; }

export class RegistryError extends Error { constructor(m: string) { super(`ingress registry: ${m}`); this.name = "RegistryError"; } }

export class IngressRegistry {
  // ES #private fields are truly private at runtime — unreachable via `(reg as any).#table` or reflection — so the
  // sealed dispatch table and phase cannot be mutated/replaced from outside (TS `private` is erased and would not
  // hold). The table is additionally a FROZEN null-proto object (its entries cannot be added/replaced), belt-and-braces.
  #phaseState: RegistryPhase = "collecting";
  #collecting = new Map<string, Entry>();
  #table: Readonly<Record<string, Entry>> | null = null; // built at seal; never exposed

  phase(): RegistryPhase { return this.#phaseState; }

  /** Register one ingress + its handler. COLLECTING only; duplicate address rejected. */
  register(decl: IngressDecl, handler: IngressHandler): void {
    if (this.#phaseState !== "collecting") throw new RegistryError(`cannot register in phase "${this.#phaseState}" (the registry is sealed — temporal closure)`);
    const d = validateDecl(decl);
    if (typeof handler !== "function") throw new RegistryError(`handler for "${d.address}" must be a function`);
    if (this.#collecting.has(d.address)) throw new RegistryError(`duplicate ingress address "${d.address}"`);
    this.#collecting.set(d.address, { decl: Object.freeze({ ...d }), handler });
  }

  /**
   * Seal the registry against a signed manifest + the policy bundle it binds. Requires: the manifest verifies + covers
   * the policy; and the collected declaration set EXACTLY equals the manifest's (boot closure). Fail-closed on any
   * mismatch; on success no further registration is possible and the dispatch table is frozen + private.
   */
  seal(manifest: SignedManifest, policyBundle: SignedBundle, trust: { manifestTrust: TrustPolicy; policyTrust?: TrustPolicy }): void {
    if (this.#phaseState !== "collecting") throw new RegistryError(`cannot seal in phase "${this.#phaseState}"`);
    const v = verifyManifest(manifest, policyBundle, trust);
    if (!v.valid) throw new RegistryError(`manifest does not verify: ${v.reason}`);
    // Use the OWNED, verified snapshot returned by verifyManifest — NEVER the caller's `manifest` (which may be
    // getter/Proxy-backed and present different data on a re-read: a verify/seal TOCTOU).
    const snap = v.manifest;
    // BOOT CLOSURE: the set of collected declaration ids must equal the snapshot's, exactly.
    const manifestIds = new Set(snap.payload.declarations.map((d) => declId(d)));
    const collectedIds = new Set([...this.#collecting.values()].map((e) => declId(e.decl)));
    if (manifestIds.size !== collectedIds.size || [...manifestIds].some((id) => !collectedIds.has(id))) {
      throw new RegistryError("collected declarations do not exactly match the signed manifest (boot closure violated)");
    }
    // build the closure-private dispatch table keyed by address (addresses are 1:1 with declarations).
    const table: Record<string, Entry> = Object.create(null);
    for (const d of snap.payload.declarations) {
      const entry = this.#collecting.get(d.address);
      if (entry === undefined) throw new RegistryError("internal: manifest declaration missing a collected handler");
      Object.defineProperty(table, d.address, { value: entry, enumerable: true, writable: false, configurable: false });
    }
    this.#table = Object.freeze(table);
    this.#collecting = new Map(); // drop retained handlers reference
    this.#phaseState = "sealed";
  }

  /** SEALED → ACTIVE. Dispatch is refused until active. */
  activate(): void {
    if (this.#phaseState !== "sealed") throw new RegistryError(`cannot activate in phase "${this.#phaseState}"`);
    this.#phaseState = "active";
  }

  /** True iff `address` is a sealed, declared ingress. */
  has(address: string): boolean { return this.#table !== null && Object.hasOwn(this.#table, address); }

  /**
   * Dispatch a request to a declared ingress. ACTIVE only. The input is decoded against the declared input schema and
   * the output against the declared output schema — both fail closed. An unknown address is a deny-by-default reject.
   */
  async dispatch(address: string, input: unknown): Promise<unknown> {
    if (this.#phaseState !== "active") throw new RegistryError(`dispatch refused in phase "${this.#phaseState}" (registry not active)`);
    const table = this.#table!;
    if (typeof address !== "string" || !Object.hasOwn(table, address)) throw new RegistryError(`no declared ingress at address "${address}" (deny-by-default)`);
    const entry = table[address]!;
    const decoded = decodeAgainst(entry.decl.input, input); // typed ingress: mistyped input fails closed
    const out = await entry.handler(decoded);
    return decodeAgainst(entry.decl.output, out); // handler must honour its declared output contract
  }
}
