/**
 * INGRESS ADMISSION GATE (Mechanical-Enforcement Increment 8).
 *
 * The frontier property (one sentence): NO application handler for a declared ingress obtains ANY authority until the
 * request has been ADMITTED — channel-authenticated for THAT ingress, size-bounded, schema-decoded, authorized by the
 * monitor's decision kernel, and issued a monitor-minted, request-bound, single-use root permit — so the only thing a
 * handler can use to cause an effect is a genuine admission-minted permit, and a handler reached OUTSIDE admission holds
 * no such permit and is therefore inert.
 *
 * The authority boundary is the PERMIT, not function invocation. JavaScript has no membrane that stops application code
 * from calling its own function; the gate does not pretend to. Instead it applies the object-capability rule: authority
 * is conveyed ONLY by an unforgeable reference — here, the request-bound single-use permit (Increment 7) delivered in
 * the admission view. A handler invoked directly (or handed a fabricated view) has no genuine permit; the Effect Broker
 * (Increment 9) redeems ONLY genuine permits, so no effect occurs. Thus "no effect without admission" is the mechanical
 * guarantee — completed at Increment 9 — and this gate is the sole ADMISSION minter: it holds a RESTRICTED mint
 * capability (PermitMinter), never the root key, and the workload holds neither, so it can forge no permit.
 *
 * This is the INITIAL AUTHORITY ISSUANCE deferred from Increment 7: a kernel `allow` (Increment 6) is turned into a root
 * permit (Increment 7 `mintRoot`) under an explicit per-ingress ISSUANCE POLICY (a TRUSTED, sealed part of the deployment
 * — not attacker input). It composes the closed-world ingress inventory (Increment 3): the gate is SEALED against the
 * signed manifest and admits only the exact declared ingress set (an undeclared address is deny-by-default), decoding
 * every body against the declared input schema.
 *
 * Admission pipeline (all fail-closed; read-once; the permit is minted and the handler reached ONLY on allow):
 *   1. ACTIVE + CLOSED-WORLD: the gate must be active and the address a sealed, declared ingress — else reject.
 *   2. CHANNEL AUTH bound to THE INGRESS: the ChannelAuthenticator verifies the channel credential FOR THIS declaration
 *      and returns the principal + channel id (read once) — never from the body — so a credential valid for one channel
 *      cannot be cross-routed to another ingress, and a body cannot assert a principal.
 *   3. BODY, READ ONCE: the body is read once; its canonical encoding must be within the byte cap; it is re-decoded from
 *      those canonical bytes into an OWNED inert value used for BOTH the schema decode AND the content-addressed digest —
 *      so the size-checked, decoded, and committed values are the same one (no getter/proxy TOCTOU).
 *   4. REQUEST ID: content-addressed over a per-gate nonce + the sealed manifest digest + a monotonic sequence + the
 *      request identity — unique per admission AND across gate instances/restarts; it becomes the permit session + nonce.
 *   5. DECISION: subject = authenticated principal; the reserved `admission.*` context attributes (principal, channel,
 *      address) are always present so a policy guard can bind them; deny short-circuits — the handler is never reached.
 *      The decision is checked to actually concern this subject + effect (fail-closed).
 *   6. MINT: subject, epoch, and the granting guard come from the DECISION; effect/object/rights/audience/validity from
 *      the sealed issuance policy for the DECIDED effect. Validity is capped. (Resolver-bound exact-object is Increment 11.)
 *   7. DELIVER: a frozen AdmissionView carrying the permit is handed to the handler. A handler exception is reported as
 *      admitted:true with a handlerError (the request WAS admitted and a permit minted — the caller must not re-admit).
 *
 * Every activation mode routes through `admit` (a timer/scheduled ingress is admitted exactly like a listener), so there
 * is no unadmitted path.
 *
 * Defers (honest): enforcement AT the effect (redeeming the permit) is Increment 9 (Effect Broker Kernel); independent
 * ingress→effect causality is Increment 12 (Causal Witness); resolver-bound exact-object authorization is Increment 11.
 * The channel authentication itself, a TRUSTED clock for `now`, and a per-BOOT unique `gateNonce` (the same class of
 * seam as the Increment-5 boot descriptor — the deployment supplies a fresh unique value per instance/restart, which
 * makes request ids — and thus permit session/nonce — unique across instances) are documented seams supplied by the
 * monitor. Where those seams are honored, request ids do not collide across instances/restarts.
 *
 * Grounding: zero-trust request admission; channel binding; confused-deputy prevention; complete mediation at the trust
 * boundary; object-capability authority (conveyed only by an unforgeable reference, never ambient).
 */
import { eirDigest, encodeCanonical, decodeCanonical, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { DecisionKernel, type Decision, type DecisionRequest } from "../kernel/decision.js";
import type { PredicateContext, ContextValue } from "../kernel/predicate.js";
import { mintRoot, type Permit, type PermitClaims, type PermitKey } from "../permit/permit.js";
import { validateDecl, declId, type IngressDecl } from "../ingress/ingress.js";
import { decodeAgainst } from "../ingress/schema.js";
import { verifyManifest, type SignedManifest } from "../ingress/ingress_manifest.js";
import type { SignedBundle } from "../policy/compiler.js";
import type { TrustPolicy } from "../bom/bom_signing.js";

export const ADMISSION = { name: "keep.admission.gate", version: "8.0.0" } as const;
/** Cap on the canonical-encoded body size — bounds pre-decision work at the trust boundary (fail-closed). */
export const MAX_BODY_BYTES = 1 << 20;
/** Cap on a minted permit's validity window — no ingress permit is effectively permanent (fail-closed). ~30 days. */
export const MAX_VALIDITY_MS = 2592000000n;

export class AdmissionError extends Error {
  constructor(m: string) { super(`admission: ${m}`); this.name = "AdmissionError"; }
}
/** Extract a message from an arbitrary thrown value without letting a hostile getter/proxy escape (totality). */
function safeMsg(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; } }

/**
 * A RESTRICTED mint capability (least authority): the gate is given only this — the ability to mint under the monitor's
 * root key — NEVER the raw key. A compromised gate can therefore mint (its job) but cannot exfiltrate the root key. The
 * monitor (the party that holds the key) constructs it with `permitMinter(key)`; the workload holds neither the key nor
 * this capability, so it can forge no permit. "The gate is the sole ADMISSION minter" is scoped to this capability —
 * the key stays inside the monitor's TCB, out of the workload's reach (cross-family review, GPT-5.6 r2 SEV0).
 */
export interface PermitMinter { readonly issuer: string; mint(claims: PermitClaims): Permit; }
/** Wrap a root key into a mint capability the gate can hold WITHOUT holding the key (closure-captured). */
export function permitMinter(key: PermitKey): PermitMinter {
  if (key === null || typeof key !== "object" || typeof key.issuer !== "string" || typeof key.rootKey !== "string") throw new AdmissionError("a permit key is required");
  return Object.freeze({ issuer: key.issuer, mint: (claims: PermitClaims): Permit => mintRoot(claims, key) });
}

/** Recursively freeze an object graph (used to make a sealed declaration deeply immutable). */
function deepFreeze<T>(o: T): T {
  if (o !== null && typeof o === "object") { for (const k of Object.keys(o)) deepFreeze((o as Record<string, unknown>)[k]); Object.freeze(o); }
  return o;
}

type Phase = "collecting" | "sealed" | "active";

/** The authenticated identity a ChannelAuthenticator establishes from a channel credential for a SPECIFIC ingress. */
export interface AuthenticatedPrincipal { readonly principal: string; readonly channelId: string; }
/** The channel-authentication SEAM: verify the channel credential FOR THIS declaration → an authenticated principal,
 * or null to reject. Binding to `decl` prevents a valid credential for one channel from being cross-routed to another. */
export interface ChannelAuthenticator { authenticate(channel: unknown, decl: IngressDecl): AuthenticatedPrincipal | null; }

/** A raw ingress event arriving at the gate. `channel` carries the credential the authenticator checks. */
export interface IngressEvent { readonly address: string; readonly channel: unknown; readonly body: unknown; }
/** The decoded, authenticated event handed to the issuance policy's context builder. */
export interface DecodedEvent { readonly address: string; readonly principal: string; readonly channelId: string; readonly input: unknown; }

/** Per-ingress ISSUANCE POLICY: what effect the ingress performs + the permit shape to mint on allow (TRUSTED config). */
export interface AdmissionSpec {
  readonly effectId: string;                 // the declared effect this ingress is authorized to perform
  readonly entryPoint: string;               // the kernel decision entry point (typically the ingress address/kind)
  readonly objectId: string;                 // the object the permit is for (resolver-bound exact identity is Incr 11)
  readonly rights: readonly string[];        // permit rights to grant on allow
  readonly audience: readonly string[];      // permit audience (which broker/effect-family may redeem)
  readonly validityMs: bigint;               // permit validity window length (notAfter = now + this; capped)
  readonly contextOf: (event: DecodedEvent) => PredicateContext; // EXTRA decision attributes from the decoded event
}
export type AdmissionPolicy = (decl: IngressDecl) => AdmissionSpec;

/** The authority + inputs delivered to a handler. The permit is the unforgeable admission credential. */
export interface AdmissionView {
  readonly principal: string;
  readonly channelId: string;
  readonly requestId: string;
  readonly input: unknown;
  readonly permit: Permit;
  readonly decision: Decision;
}
/** A handler runs with an admission view. Its authority to cause effects is the view's permit (redeemed at Incr 9). */
export type AdmissionHandler = (view: AdmissionView) => unknown | Promise<unknown>;

export type AdmitResult =
  | { readonly admitted: true; readonly requestId: string; readonly decision: Decision; readonly output?: unknown; readonly handlerError?: string }
  | { readonly admitted: false; readonly reason: string; readonly requestId: string | null; readonly decision: Decision | null };

const isText = (s: unknown): s is string => typeof s === "string" && s.length > 0 && s.length <= (1 << 16) && isWellFormedText(s) && s.normalize("NFC") === s;
const RESERVED = "admission."; // reserved decision-context attribute prefix the policy cannot override

interface Slot { readonly decl: IngressDecl; readonly handler: AdmissionHandler; readonly spec: AdmissionSpec; }

/**
 * The Admission Gate. Register (decl, handler) while COLLECTING; SEAL against the signed manifest (closed-world boot
 * closure); ACTIVATE; then `admit` events. Construct with a per-instance `gateNonce` unique across instances/restarts.
 */
export class AdmissionGate {
  #phase: Phase = "collecting";
  #collecting = new Map<string, Slot>();
  #table: Readonly<Record<string, Slot>> | null = null;
  #manifestDigest = "";
  #seq = 0n;
  readonly #kernel: DecisionKernel;
  readonly #auth: ChannelAuthenticator;
  readonly #minter: PermitMinter;
  readonly #policy: AdmissionPolicy;
  readonly #gateNonce: string;

  constructor(kernel: DecisionKernel, auth: ChannelAuthenticator, minter: PermitMinter, policy: AdmissionPolicy, gateNonce: string) {
    if (!(kernel instanceof DecisionKernel)) throw new AdmissionError("a DecisionKernel is required");
    if (auth === null || typeof auth !== "object" || typeof auth.authenticate !== "function") throw new AdmissionError("a ChannelAuthenticator is required");
    if (minter === null || typeof minter !== "object" || !isText(minter.issuer) || typeof minter.mint !== "function") throw new AdmissionError("a permit mint capability is required");
    if (typeof policy !== "function") throw new AdmissionError("an issuance policy is required");
    if (!isText(gateNonce)) throw new AdmissionError("a per-instance gateNonce (unique across instances/restarts) is required");
    this.#kernel = kernel; this.#auth = auth; this.#minter = minter; this.#policy = policy; this.#gateNonce = gateNonce;
  }

  phase(): Phase { return this.#phase; }

  /** Register one ingress + its admission handler. COLLECTING only; duplicate address rejected. The issuance spec is
   * derived from the policy and validated up front so a malformed spec is caught before sealing. */
  register(decl: IngressDecl, handler: AdmissionHandler): void {
    if (this.#phase !== "collecting") throw new AdmissionError(`cannot register in phase "${this.#phase}"`);
    const d = validateDecl(decl);
    if (typeof handler !== "function") throw new AdmissionError(`handler for "${d.address}" must be a function`);
    if (this.#collecting.has(d.address)) throw new AdmissionError(`duplicate ingress address "${d.address}"`);
    const spec = validateSpec(this.#policy(Object.freeze({ ...d })));
    this.#collecting.set(d.address, { decl: Object.freeze({ ...d }), handler, spec });
  }

  /** Seal against the signed manifest + policy bundle (Increment 3): the collected ingress set must EXACTLY equal the
   * manifest's (boot closure). Fail-closed on any mismatch. Binds the sealed manifest digest into every request id. */
  seal(manifest: SignedManifest, policyBundle: SignedBundle, trust: { manifestTrust: TrustPolicy; policyTrust?: TrustPolicy }): void {
    if (this.#phase !== "collecting") throw new AdmissionError(`cannot seal in phase "${this.#phase}"`);
    const v = verifyManifest(manifest, policyBundle, trust);
    if (!v.valid) throw new AdmissionError(`manifest does not verify: ${v.reason}`);
    const decls = v.manifest.payload.declarations; // OWNED verified snapshot (never the caller's manifest)
    const manifestIds = new Set(decls.map((d) => declId(d)));
    const collectedIds = new Set([...this.#collecting.values()].map((s) => declId(s.decl)));
    if (manifestIds.size !== collectedIds.size || [...manifestIds].some((id) => !collectedIds.has(id))) throw new AdmissionError("collected ingresses do not exactly match the signed manifest (boot closure violated)");
    const table: Record<string, Slot> = Object.create(null);
    for (const d of decls) {
      const collected = this.#collecting.get(d.address);
      if (collected === undefined) throw new AdmissionError("internal: manifest declaration missing a collected handler");
      // Build the active slot from the VERIFIED manifest declaration, deeply-owned + deep-frozen (a fresh validated
      // tree, never a caller reference), so no post-seal mutation can change the schema decodeAgainst evaluates.
      const slot: Slot = Object.freeze({ decl: deepFreeze(validateDecl(d)), handler: collected.handler, spec: collected.spec });
      Object.defineProperty(table, d.address, { value: slot, enumerable: true, writable: false, configurable: false });
    }
    this.#table = Object.freeze(table);
    this.#manifestDigest = v.manifest.payloadDigest;
    this.#collecting = new Map();
    this.#phase = "sealed";
  }

  /** SEALED → ACTIVE. Admission is refused until active. */
  activate(): void {
    if (this.#phase !== "sealed") throw new AdmissionError(`cannot activate in phase "${this.#phase}"`);
    this.#phase = "active";
  }

  /**
   * ADMIT an event: run the full pipeline and, only on allow, deliver a permit-carrying view to the handler. The
   * pre-handler pipeline is TOTAL — any failure is `{admitted:false, reason}` and the handler is never reached. A
   * handler EXCEPTION is reported as `admitted:true` with a handlerError (the request WAS admitted + a permit minted).
   */
  async admit(event: IngressEvent, now: bigint): Promise<AdmitResult> {
    const deny = (reason: string, requestId: string | null = null, decision: Decision | null = null): AdmitResult => ({ admitted: false, reason, requestId, decision });
    let slot: Slot; let principal: string; let channelId: string; let requestId: string; let decision: Decision; let view: AdmissionView;
    try {
      if (this.#phase !== "active") return deny(`gate not active (phase "${this.#phase}")`);
      if (event === null || typeof event !== "object") return deny("event must be an object");
      const address = event.address; const channel = event.channel; const rawBody = event.body; // read each field ONCE
      if (!isText(address)) return deny("event.address must be non-empty NFC text");
      if (typeof now !== "bigint" || now < 0n) return deny("now must be a non-negative bigint");
      const table = this.#table!;
      if (!Object.hasOwn(table, address)) return deny(`no declared ingress at "${address}" (closed-world deny-by-default)`);
      slot = table[address]!;

      // [2] channel authentication bound to THIS ingress; read the result ONCE into locals.
      let authed: AuthenticatedPrincipal | null;
      try { authed = this.#auth.authenticate(channel, slot.decl); } catch { return deny("channel authentication threw"); }
      if (authed === null || typeof authed !== "object") return deny("channel authentication failed");
      const p = authed.principal, c = authed.channelId; // read once
      if (!isText(p) || !isText(c)) return deny("channel authentication returned a malformed principal/channelId");
      principal = p; channelId = c;

      // [3] body: read once → canonical bytes (size-bound) → owned inert re-decode used for BOTH decode and digest.
      // A raw string is length-checked BEFORE encoding (a coarse pre-encode guard for the common case). For a structured
      // body the encoder work is bounded by the Increment-5 authenticated-frame size limit — the outer transport bound
      // on any body that reaches the gate (documented seam) (cross-family review, GPT-5.6 r2 SEV2).
      if (typeof rawBody === "string" && rawBody.length > MAX_BODY_BYTES) return deny(`body exceeds ${MAX_BODY_BYTES} bytes`);
      let bytes: Uint8Array;
      try { bytes = encodeCanonical(rawBody as CanonicalValue); } catch { return deny("body is not canonical-encodable"); }
      if (bytes.length > MAX_BODY_BYTES) return deny(`body exceeds ${MAX_BODY_BYTES} bytes`);
      let owned: CanonicalValue;
      try { owned = decodeCanonical(bytes); } catch { return deny("body canonical re-decode failed"); }
      let input: unknown;
      try { input = decodeAgainst(slot.decl.input, owned); } catch (e) { return deny(`body does not match the declared input schema: ${safeMsg(e)}`); }

      // [4] request id — per-gate nonce + sealed manifest digest + monotonic seq + identity + body digest.
      const seq = this.#seq; this.#seq += 1n;
      requestId = eirDigest("keep.admission.request/v1", { gate: this.#gateNonce, manifest: this.#manifestDigest, seq, address, principal, channelId, body: eirDigest("keep.admission.body/v1", owned) });

      // [5] decision — subject = authenticated principal; reserved admission.* attributes always present for policy binding.
      const spec = slot.spec;
      const ctxAttrs = new Map<string, ContextValue>([[`${RESERVED}principal`, principal], [`${RESERVED}channel`, channelId], [`${RESERVED}address`, address]]);
      let extra: PredicateContext;
      try { extra = spec.contextOf(Object.freeze({ address, principal, channelId, input })); } catch { return deny("issuance policy context builder threw", requestId); }
      if (extra instanceof Map) for (const [k, val] of extra) if (typeof k === "string" && !k.startsWith(RESERVED)) ctxAttrs.set(k, val as ContextValue);
      const req: DecisionRequest = { atEpoch: this.#kernel.epoch, subject: principal, entryPoint: spec.entryPoint, effectId: spec.effectId, context: ctxAttrs };
      decision = this.#kernel.decide(req);
      if (decision.verdict !== "allow") return deny(`denied by the decision kernel (${decision.reason})`, requestId, decision);
      if (decision.subject !== principal || decision.effectId !== spec.effectId) return deny("decision does not concern this request's subject/effect", requestId, decision);
      const gp = decision.proof.grantingPermit;
      if (gp === null) return deny("allow decision carried no granting permit", requestId, decision);

      // [6] mint — subject/epoch/guard from the DECISION; effect/object/rights/audience/validity from the sealed policy.
      const claims: PermitClaims = {
        issuer: this.#minter.issuer, subject: decision.subject, session: requestId, effectId: decision.effectId, objectId: spec.objectId,
        rights: spec.rights, guardDigest: gp.guardId, epoch: decision.epoch,
        notBefore: now, notAfter: now + spec.validityMs, nonce: requestId, maxRedemptions: 1n, audience: spec.audience,
      };
      let permit: Permit;
      try { permit = this.#minter.mint(claims); } catch (e) { return deny(`permit issuance failed: ${safeMsg(e)}`, requestId, decision); }
      view = Object.freeze({ principal, channelId, requestId, input, permit, decision });
    } catch (e) {
      // Total fail-closed backstop for the PRE-HANDLER pipeline.
      return deny(`internal error: ${safeMsg(e)}`);
    }
    // [7] handler is POST-admission: the request is admitted + the permit minted. A handler throw is not an admission
    // failure — report admitted:true with the error so the caller does NOT re-admit (and re-mint) the same request.
    try {
      const output = await slot.handler(view);
      return { admitted: true, requestId, decision, output };
    } catch (e) {
      return { admitted: true, requestId, decision, handlerError: safeMsg(e) };
    }
  }
}

// ── issuance-spec validation ─────────────────────────────────────────────────────────────────────────────────────
function validateSpec(s: unknown): AdmissionSpec {
  if (s === null || typeof s !== "object") throw new AdmissionError("issuance spec must be an object");
  const o = s as Record<string, unknown>;
  for (const k of ["effectId", "entryPoint", "objectId"]) if (!isText(o[k])) throw new AdmissionError(`spec.${k} must be non-empty NFC text`);
  const rights = validateStrArray(o["rights"], "spec.rights");
  const audience = validateStrArray(o["audience"], "spec.audience");
  const validityMs = o["validityMs"];
  if (typeof validityMs !== "bigint" || validityMs < 0n) throw new AdmissionError("spec.validityMs must be a non-negative bigint");
  if (validityMs > MAX_VALIDITY_MS) throw new AdmissionError(`spec.validityMs exceeds the ${MAX_VALIDITY_MS}ms cap`);
  if (typeof o["contextOf"] !== "function") throw new AdmissionError("spec.contextOf must be a function");
  return Object.freeze({ effectId: o["effectId"] as string, entryPoint: o["entryPoint"] as string, objectId: o["objectId"] as string, rights: Object.freeze(rights), audience: Object.freeze(audience), validityMs, contextOf: o["contextOf"] as (e: DecodedEvent) => PredicateContext });
}
function validateStrArray(xs: unknown, where: string): readonly string[] {
  if (!Array.isArray(xs) || xs.length === 0) throw new AdmissionError(`${where} must be a non-empty array`);
  const seen = new Set<string>();
  for (const x of xs) { if (!isText(x)) throw new AdmissionError(`${where} has a non-text member`); if (seen.has(x)) throw new AdmissionError(`${where} has a duplicate`); seen.add(x); }
  return [...seen].sort();
}
