/**
 * BROKERED EGRESS PROVIDER (Mechanical-Enforcement Increment 10b — Ambient-Authority Closure, the WIRE).
 *
 * The frontier property this facet makes NON-VACUOUS + LOAD-BEARING (one sentence): a REMOTE provider request (the `net`
 * effect family) reaches the raw transport ONLY as the second half of a real admission→permit→broker→owner transaction —
 * per outbound call the kernel DECIDES (Increment 6) whether egress is permitted, on ALLOW a one-shot `net` permit is
 * MINTED (Increment 7) bound to this subject/session/effect/object/right + the broker-net audience, and the Increment-9
 * broker REDEEMS it before the sole net OWNER executor performs the transport. A denied decision mints NOTHING; a broker
 * or permit failure yields NO send (no fallback to a direct transport). This is the acceptance test that makes Increment
 * 10's sentence — "the workload physically lacks every effect path NOT EXPOSED BY THE BROKER" — non-vacuous for the closed
 * `net` family (it is meaningless while the broker is an unwired island). It also makes the Incr 6→9 stack load-bearing on
 * a LIVE path — the pre-review audit's meta-finding was "safety logic not load-bearing on the live path".
 *
 * DESIGN. `BrokeredEgressProvider` wraps an inner ModelProvider. A LOCAL provider (isLocal) needs no egress and is called
 * directly (no permit, no broker). A REMOTE provider's generate/embed/generateStream go: decide → (allow?) mintRoot →
 * broker.dispatch({family:"net", operation:"send", args: the canonicalized request}) → the bound net EXECUTOR (the OWNER,
 * the ONLY module that invokes the raw transport — here, the inner provider's real send) runs, and its INERT canonical
 * result is decoded back to a GenerateResult. The executor is bound ONCE at construction and acts on the broker-validated
 * ARGS — never a caller-supplied callback (a caller must not smuggle ambient behaviour through an authorized dispatch).
 *
 * WHAT IS PROVEN (in test/brokered_egress.test.ts, over the REAL policy→kernel→manifest→broker→wrapper chain):
 *  (1) BROKER load-bearing — a broker that will not redeem (wrong audience) → the send fails closed, the owner/transport
 *      is never reached, and there is NO direct fallback; (2) DECISION gate — a denied egress mints NOTHING and never
 *      dispatches (neuter-verified); (3) PERMIT signature — a permit the broker cannot verify (wrong root key = a foreign/
 *      tampered permit) → no transport (expired/replayed single-use is the broker's redeem, proven in the Increment-9
 *      suite); (4) real # privacy — the inner transport / permit key / broker are not reachable from the wrapper object
 *      (no `(x as any).inner` bypass); (5) captured isLocal — a post-construction `isLocal` flip cannot re-route a remote
 *      send. The closed-world sweep (Increment 10a) additionally confines the raw `net` primitive to the declared owner.
 *      Streaming is dispatched as one authorized send (not retried mid-flight).
 *
 * HONEST SCOPE. This closes ONE production `net` egress family through real issuance+broker+owner. It does NOT yet close:
 * the synchronous witness-log fs writes, solve/apply fs writes, subprocess/env/clock/random families, or other net
 * mechanisms — later increments. The global frontier sentence stays QUALIFIED until every family is closed; the honest
 * 10b claim is that it is non-vacuous and load-bearing FOR `net`. The kernel/permitKey/manifest/ledger/audit are the
 * trusted sealed config (as in Increments 6–9); `now`/`epoch` are the trusted monitor's clock.
 *
 * Grounding: capability invocation (authority = the redeemed permit, never ambient); complete mediation of the outbound
 * boundary; structured effect systems (one owner per family).
 */
import { randomBytes } from "node:crypto";
import { eirDigest, encodeCanonical, decodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { mintRoot, type Permit, type PermitKey } from "../permit/permit.js";
import { DecisionKernel } from "../kernel/decision.js";
import { EffectBroker, MapIdempotencyStore, type AuditSink } from "../broker/broker.js";
import type { BrokerRequest, BrokerResult } from "../broker/broker.js";
import { AuthorityActuatorClient, SacrificialActuator } from "../boundary/sacrificial_actuator.js";
import { issueRoleCredential } from "../boundary/role_channel.js";
import type { DurableWitness } from "../witness/pre_effect_witness.js";
import { RedemptionLedger } from "../permit/ledger.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import type { BoundedEmbeddingOptions, BoundedEmbeddingResult } from "./http_provider.js";
import { verifyRestrictedReleaseAdmission, verifyRestrictedReleaseRuntime, type RestrictedReleaseAdmission, type RestrictedReleaseRuntime } from "../graph/release_boot.js";
import { constructedRemoteProviderIdentity } from "./provider_descriptor.js";
import { installedEffectAdmission, INSTALLED_EFFECT_OWNERS, type InstalledEffectAdmission } from "../control/installed_effect_admission.js";
import { compilePolicy } from "../policy/compiler.js";
import { compileEffectManifest } from "../effect/effect_manifest.js";
import { validateEffectDecl } from "../effect/effect.js";
import { StubSigner, type TrustPolicy } from "../bom/bom_signing.js";
import type { JsonValue } from "../policy/json.js";
import type { ExternalRoutingPolicy } from "./wire_dialect.js";

export const NET_AUDIENCE = "keep.broker.net" as const;

export class EgressDeniedError extends Error {
  constructor(readonly reason: string) { super(`egress denied: ${reason}`); this.name = "EgressDeniedError"; }
}
class LocalOnlyProvider implements ModelProvider {
  readonly name: string; readonly isLocal = true; readonly #inner: ModelProvider;
  constructor(inner: ModelProvider) { this.#inner = inner; this.name = `local-only(${inner.name})`; }
  generate(req: GenerateRequest): Promise<GenerateResult> { return this.#inner.generate(req); }
  embed(texts: readonly string[]): Promise<Embedding[]> { return this.#inner.embed(texts); }
  embedBounded(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult> {
    if (!this.#inner.embedBounded) throw new EgressDeniedError("bounded embedding unavailable; no unmetered fallback");
    return this.#inner.embedBounded(texts, options);
  }
}
type EmbeddingInvocation = { readonly objectId: string; readonly options: BoundedEmbeddingOptions };
/** Extract a bounded message from ANY thrown value without itself throwing (a hostile Proxy `message` getter can throw). */
function safeMsg(e: unknown): string { try { const s = String((e as { message?: unknown })?.message ?? e); return s.length > 200 ? s.slice(0, 200) : s; } catch { return "unknown"; } }

/** Everything the wrapper needs — all TRUSTED, constructed once at the composition root (never caller-supplied per call). */
interface BrokeredEgressDeps {
  /** Present on the production composition path; lower-level broker unit tests exercise this class beneath A4. */
  readonly releaseAdmission?: RestrictedReleaseAdmission;
  readonly ownerAuthority?: true;
  /** Composition-owned classification; never derived from the provider's self-reported `isLocal`. */
  readonly transportClass: "local" | "remote";
  /** D2's role-bound endpoint onto D3; D3 owns the broker and the sole transport executor. */
  readonly actuator: { dispatch(request: BrokerRequest): Promise<BrokerResult> };
  /** The Increment-6 decision kernel over the deployment's signed policy — the egress authorizer. */
  readonly kernel: DecisionKernel;
  /** The content id of the net effect the policy declares (what `decide` and the permit are bound to). */
  readonly netEffectId: string;
  /** The entry point the egress decision is evaluated on (matched against the policy's rule entryPoints). */
  readonly entryPoint: string;
  /** The subject identity the workload presents for egress (matched against rule subjects). */
  readonly subject: string;
  /** The monitor's permit root key (Increment 7 issuance). */
  readonly permitKey: PermitKey;
  /** Trusted monitor clock (ms) + policy epoch — NOT workload-controlled. */
  readonly now: () => bigint;
  readonly epoch: () => bigint;
  /** Permit validity window (ms) from mint time. */
  readonly validityMs: bigint;
  /** A per-request unique id source (session/nonce/idempotency); MUST be unique per outbound call (single-use). */
  readonly requestId: () => string;
  readonly effectAdmission: InstalledEffectAdmission;
  readonly externalRouting?: ExternalRoutingPolicy;
}

/** Canonicalize a generate request to the INERT args the permit binds and the owner acts on (no callbacks, no ambient).
 * Inputs are DEFENSIVELY coerced (a runtime-hostile req cannot throw a raw RangeError before the authorization try). */
function routingArgs(policy: ExternalRoutingPolicy | undefined): CanonicalValue | undefined {
  return policy === undefined ? undefined : { zeroDataRetention: true, dataCollection: "deny", allowFallbacks: false, providers: [...policy.providers] };
}
function reqToArgs(req: GenerateRequest, cancellationId?: string, routing?: ExternalRoutingPolicy): CanonicalValue {
  const r = (req ?? {}) as { prompt?: unknown; maxTokens?: unknown; hints?: unknown };
  const structuredOutput = r.hints !== null && typeof r.hints === "object" && (r.hints as Record<string, unknown>)["structuredOutput"] === true;
  return { kind: "generate", prompt: String(r.prompt ?? ""), maxTokens: toCount(Number(r.maxTokens ?? 0)), structuredOutput, ...(routing === undefined ? {} : { routing: routingArgs(routing)! }), ...(cancellationId === undefined ? {} : { cancellationId }) };
}
function embedToArgs(texts: readonly string[]): CanonicalValue {
  return { kind: "embed", texts: (Array.isArray(texts) ? texts : []).map((t) => String(t)) };
}
/** The stable object id the permit is bound to: a digest of the exact outbound request (endpoint identity is the model). */
const objectIdOf = (args: CanonicalValue): string => eirDigest("keep.egress.object/v1", args);
/** A non-negative integer token count as a bigint (NaN/fractional/negative/∞ → clamped) — so BigInt() never throws. */
const toCount = (n: number): bigint => BigInt(Number.isFinite(n) ? Math.max(0, Math.min(Math.trunc(n), Number.MAX_SAFE_INTEGER)) : 0);
/** Decode a bigint token count back to a safe JS number (clamped to the safe-integer range — never Infinity/rounded). */
const fromCount = (b: bigint): number => (b < 0n ? 0 : b > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(b));

/** Decode the broker's inert canonical output back to a GenerateResult; throws on a malformed shape (fail-closed). */
function resultFromOutput(v: CanonicalValue): GenerateResult {
  const o = v as Record<string, unknown>;
  if (o === null || typeof o !== "object" || typeof o.text !== "string" || typeof o.model !== "string" || typeof o.tokensIn !== "bigint" || typeof o.tokensOut !== "bigint") {
    throw new EgressDeniedError("brokered egress returned a malformed result");
  }
  return { text: o.text, model: o.model, tokensIn: fromCount(o.tokensIn), tokensOut: fromCount(o.tokensOut) };
}

/** The net EXECUTOR (the OWNER) — the ONLY place the real transport is invoked. Bound to the inner provider ONCE at
 * construction; acts on the broker-validated ARGS, never a caller callback. Returns INERT canonical data. Pass this to
 * the broker's net FamilyBinding when constructing it in compose. */
function makeNetExecutor(inner: ModelProvider, cancellations: ReadonlyMap<string, AbortSignal>, routing?: ExternalRoutingPolicy, embeddings?: Map<string, EmbeddingInvocation>) {
  return async (_authz: unknown, args: CanonicalValue): Promise<CanonicalValue> => {
    const a = decodeCanonical(encodeCanonical(args)) as Record<string, unknown>; // read-once, inert
    if (a.kind === "embed-bounded") {
      const id = typeof a.invocationId === "string" ? a.invocationId : "", invocation = embeddings?.get(id);
      if (!invocation || invocation.objectId !== objectIdOf(args) || !Array.isArray(a.texts) || !inner.embedBounded) throw new EgressDeniedError("bounded embedding invocation is absent or mismatched");
      embeddings!.delete(id); // Single-use host capability, never a callable serialized in broker args.
      const result = await inner.embedBounded(a.texts as string[], invocation.options);
      return { kind: "embed-bounded", resultJson: JSON.stringify(result) };
    }
    if (a.kind === "embed" && Array.isArray(a.texts)) {
      const vectors = await inner.embed(a.texts as string[]);
      // Embeddings are FLOAT vectors (non-integer) — not directly canonical; pass them through as a canonical-safe
      // JSON string so the broker's inert-canonical sanitize accepts them (the vectors are opaque pass-through data).
      return { kind: "embed", vectorsJson: JSON.stringify(vectors) };
    }
    const cancellationId = typeof a.cancellationId === "string" ? a.cancellationId : undefined;
    if (routing !== undefined) {
      const admitted = a.routing as Record<string, unknown> | undefined;
      if (!admitted || admitted.zeroDataRetention !== true || admitted.dataCollection !== "deny" || admitted.allowFallbacks !== false || !Array.isArray(admitted.providers) || admitted.providers.length !== routing.providers.length || admitted.providers.some((value, index) => value !== routing.providers[index])) throw new Error("external routing policy is absent or differs from the admitted broker object");
    }
    const signal = cancellationId === undefined ? undefined : cancellations.get(cancellationId);
    const req: GenerateRequest = { prompt: String(a.prompt ?? ""), ...(a.maxTokens !== undefined && a.maxTokens !== 0n ? { maxTokens: Number(a.maxTokens) } : {}), ...(a.structuredOutput === true ? { hints: { structuredOutput: true } } : {}), ...(signal === undefined ? {} : { signal }) };
    const r = await inner.generate(req);
    if (routing !== undefined && (typeof r.providerRoute !== "string" || !routing.providers.includes(r.providerRoute))) throw new Error("external provider route was absent or outside the admitted allowlist");
    return { text: String(r.text ?? ""), model: String(r.model ?? ""), tokensIn: toCount(r.tokensIn), tokensOut: toCount(r.tokensOut), ...(r.providerRoute === undefined ? {} : { providerRoute: r.providerRoute }) };
  };
}

/** The default egress policy: the `agent` subject may egress on entryPoint "egress.net" (an operator supplies a stricter
 * signed policy to gate egress by context). The SECURITY VALUE even at this permissive default: egress is now a MECHANICAL
 * decide→mint→broker→owner transaction — a code path that is not the agent subject / not on the egress entryPoint is
 * denied, every send is an audited permit redemption, and the closed-world sweep (10a) confines the raw net primitive to
 * the owner. NET effect = http.post (classifies to the `net` family; owner = the sole transport module). */
/**
 * Construct a live BrokeredEgressProvider for the composition root: build the signed policy + decision kernel + signed
 * effect manifest (net owner) + broker over ephemeral per-boot keys (the same stub-HMAC signing SEAM as the rest of Keep;
 * a deployment supplies asymmetric/HSM keys + its own signed policy), bind the net owner to the inner transport, and wrap.
 * A LOCAL inner needs no egress and is returned unwrapped. `audit` is the broker's sink (compose passes a spine adapter).
 */
export function buildDefaultBrokeredEgress(inner: ModelProvider, audit: AuditSink, opts: { transportClass: "local" | "remote"; ownerAuthority?: boolean; subject?: string; validityMs?: bigint; permitRootKey?: string; now?: () => bigint; epoch?: () => bigint; witness?: DurableWitness; releaseRuntime?: RestrictedReleaseRuntime; effectAdmission?: InstalledEffectAdmission; externalRouting?: ExternalRoutingPolicy }): ModelProvider {
  // NOTE: the wrapper is ALWAYS constructed (the factory never returns the raw provider) and it CAPTURES the injected
  // provider's `isLocal` ONCE at construction (immutable thereafter — a later flip/stateful-getter cannot re-route a
  // remote send). The injected provider is trusted COMPOSITION-ROOT config; a provider that MISREPORTS isLocal is a
  // trusted-config error, not an attacker (the operator chose it). A local provider bypasses brokering (no net egress);
  // everything else is brokered. A self-hosting deployment that wants stronger local/remote separation supplies its
  // own classification via config.
  if (opts.transportClass === "local") return new LocalOnlyProvider(inner);
  if (opts.ownerAuthority !== true && (opts.releaseRuntime === undefined || !verifyRestrictedReleaseRuntime(opts.releaseRuntime))) throw new EgressDeniedError("remote provider construction requires owner or current installed-release runtime authority");
  if (opts.releaseRuntime !== undefined && constructedRemoteProviderIdentity(inner) !== opts.releaseRuntime.providerDescriptorDigest) throw new EgressDeniedError("remote provider does not match the signed built-in descriptor identity");
  if (opts.ownerAuthority === true && opts.releaseRuntime !== undefined) throw new EgressDeniedError("owner and organization release authority are mutually exclusive");
  const releaseAdmission = opts.releaseRuntime?.admission;
  const ownerPolicy: JsonValue = { version: 1n, combiningAlgorithm: "deny-overrides", principals: [{ name: "agent", labels: [] }], effects: [{ id: "e-net", effectType: "http.post", resourceSelector: "*" }], guards: [], rules: [{ id: "owner-egress", decision: "permit", subjects: ["agent"], entryPoints: ["egress.net"], effect: "e-net" }] };
  const ownerKey = opts.ownerAuthority === true ? randomBytes(32).toString("hex") : undefined;
  const ownerSigner = ownerKey === undefined ? undefined : { signer: new StubSigner(ownerKey, "keep.owner.egress"), keyid: "keep.owner.egress", verifyKey: ownerKey };
  const ownerBundle = ownerSigner === undefined ? undefined : compilePolicy(ownerPolicy, [ownerSigner]);
  const ownerTrust: TrustPolicy | undefined = ownerKey === undefined ? undefined : { trustedKeys: new Map([["keep.owner.egress", ownerKey]]), threshold: 1 };
  const bundle = opts.releaseRuntime?.authority.policyBundle ?? ownerBundle!;
  const trust = opts.releaseRuntime?.authority.trust ?? { manifestTrust: ownerTrust!, policyTrust: ownerTrust! };
  const manifest = opts.releaseRuntime?.authority.manifest ?? compileEffectManifest([validateEffectDecl({ family: "net", owner: "src/gateway/http_provider.ts" })], bundle, { artifactGraphDigest: "0".repeat(64), scannerToolDigest: "0".repeat(64) }, [ownerSigner!]);
  const rootKey = opts.permitRootKey ?? randomBytes(32).toString("hex");
  const kernel = new DecisionKernel(bundle, trust.policyTrust);
  const netEffect = bundle.payload.effects.find((e) => e.effectType.split(".")[0] === "http" || e.effectType.split(".")[0] === "net" || e.effectType.split(".")[0] === "https");
  if (netEffect === undefined) throw new Error("brokered egress: the egress policy declares no net effect");
  const permitKey: PermitKey = { issuer: "keep.egress", rootKey };
  const cancellations = new Map<string, AbortSignal>();
  const embeddings = new Map<string, EmbeddingInvocation>();
  const broker = new EffectBroker(
    manifest, bundle, trust, permitKey,
    new RedemptionLedger(), new MapIdempotencyStore(),
    new Map([["net", { executor: makeNetExecutor(inner, cancellations, opts.externalRouting, embeddings), audience: NET_AUDIENCE, operations: new Map([["send", "send"]]) }]]),
    audit, randomBytes(8).toString("hex"),
    // WIRE-BATCH A2: the pre-effect witness interlock (Incr 12a). Default-ON in compose — a remote model send is now
    // structurally unreachable unless a durable witnessed intent was sealed first. Undefined ⇒ legacy (unwitnessed).
    opts.witness,
  );
  let n = 0n;
  let tick = 0n; // default monotonic clock: advances on authority mint and actuator redemption
  const now = opts.now ?? (() => tick++);
  const epoch = opts.epoch ?? (() => 0n);
  const authorityCredential = issueRoleCredential("authority", `egress-authority-${randomBytes(8).toString("hex")}`, `boot-${randomBytes(8).toString("hex")}`);
  const actuator = new SacrificialActuator(authorityCredential, broker, { now, epoch });
  const actuatorClient = new AuthorityActuatorClient(authorityCredential, (message) => actuator.receive(message));
  const deps: BrokeredEgressDeps = {
    actuator: actuatorClient, kernel, netEffectId: netEffect.id, entryPoint: "egress.net", subject: opts.subject ?? "agent", permitKey, transportClass: opts.transportClass, ...(opts.ownerAuthority === true ? { ownerAuthority: true as const } : {}), ...(releaseAdmission === undefined ? {} : { releaseAdmission }),
    // now/epoch are the TRUSTED MONITOR's clock/epoch — an injectable SEAM (a deployment passes the real monitor clock).
    // The DEFAULT is a MONOTONIC COUNTER (not a frozen 0), so a permit's validity window is well-formed and a HELD permit
    // would expire after `validityMs` ticks. NOTE: this wrapper mints and redeems in ONE call, so the permit is never held
    // past its mint tick — expiry is moot for THIS flow; the single-use ledger + per-request nonce + audience/subject/object
    // binding are the operative fences. (Expiry itself is proven load-bearing at the broker in the Increment-9 suite.)
    now, epoch, validityMs: opts.validityMs ?? 1_000n, requestId: () => `egress-${++n}`,
    effectAdmission: opts.effectAdmission ?? installedEffectAdmission, ...(opts.externalRouting === undefined ? {} : { externalRouting: opts.externalRouting }),
  };
  return new BrokeredEgressProvider(inner, deps, cancellations, embeddings);
}

class BrokeredEgressProvider implements ModelProvider {
  readonly name: string;
  readonly isLocal: boolean;
  // REAL (ECMAScript) private fields — NOT reachable via `(x as any).inner`/`.deps` from the emitted JS, so the inner
  // transport, the permit key, and the broker are not reachable outside this object's own methods. (A same-isolate attacker
  // with prototype-pollution / reflection is the documented TOPOLOGY residual — the real closure is the workload in its OWN
  // isolate whose sole channel is the Increment-5 vsock; that is not fixable in a shared isolate.)
  readonly #inner: ModelProvider;
  readonly #deps: BrokeredEgressDeps;
  readonly #cancellations: Map<string, AbortSignal>;
  readonly #embeddings: Map<string, EmbeddingInvocation>;
  readonly #innerIsLocal: boolean; // CAPTURED ONCE from the trusted-config provider — a later mutation cannot re-route a remote send.
  constructor(inner: ModelProvider, deps: BrokeredEgressDeps, cancellations: Map<string, AbortSignal>, embeddings: Map<string, EmbeddingInvocation>) {
    this.#inner = inner;
    this.#deps = deps;
    this.#cancellations = cancellations;
    this.#embeddings = embeddings;
    if (deps.transportClass === "remote" && deps.ownerAuthority !== true && (deps.releaseAdmission === undefined || !verifyRestrictedReleaseAdmission(deps.releaseAdmission))) throw new EgressDeniedError("remote provider construction requires owner or current installed-release admission");
    this.#innerIsLocal = deps.transportClass === "local";
    this.name = `brokered-egress(${inner.name})`;
    this.isLocal = this.#innerIsLocal;
  }

  /** Decide egress, mint a one-shot net permit on ALLOW, and dispatch through the broker. Throws EgressDeniedError on any
   * deny/failure (arg-build coercion + broker/executor faults are ALL normalized here) — there is NO direct fallback. */
  async #authorizeAndDispatch(makeArgs: () => CanonicalValue): Promise<CanonicalValue> {
    try {
      this.#deps.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.modelNetwork.id);
      const args = makeArgs(); // build the inert args INSIDE the try — a hostile prompt/maxTokens coercion is normalized
      if (this.#deps.releaseAdmission !== undefined && !verifyRestrictedReleaseAdmission(this.#deps.releaseAdmission)) throw new EgressDeniedError("release admission stale or mismatched immediately before dispatch");
      const now = this.#deps.now();
      const epoch = this.#deps.epoch();
      const objectId = objectIdOf(args);
      // [1] DECIDE — a denied egress mints NOTHING and never dispatches (admission alone does not authorize).
      const decision = this.#deps.kernel.decide({ atEpoch: epoch, subject: this.#deps.subject, entryPoint: this.#deps.entryPoint, effectId: this.#deps.netEffectId, context: new Map() });
      if (decision.verdict !== "allow") throw new EgressDeniedError(`decision: ${decision.reason}`);
      // [2] MINT — a one-shot net permit bound to THIS subject/session/effect/object + the "send" right + the broker-net audience.
      const session = this.#deps.requestId();
      const permit: Permit = mintRoot({
        issuer: this.#deps.permitKey.issuer, subject: this.#deps.subject, session, effectId: this.#deps.netEffectId, objectId,
        rights: ["send"], guardDigest: decision.digest, epoch: decision.epoch,
        notBefore: now, notAfter: now + this.#deps.validityMs, nonce: session, maxRedemptions: 1n, audience: [NET_AUDIENCE],
      }, this.#deps.permitKey);
      // [3] DISPATCH — the broker redeems the permit then invokes the sole net owner; a broker/permit failure => no send.
      const res = await this.#deps.actuator.dispatch({ permit, subject: this.#deps.subject, session, effectId: this.#deps.netEffectId, objectId, family: "net", operation: "send", args, idempotencyKey: session });
      if (!res.ok) throw new EgressDeniedError(`broker: ${res.reason}`);
      return res.output;
    } catch (e) {
      if (e instanceof EgressDeniedError) throw e;
      throw new EgressDeniedError(`egress error: ${safeMsg(e)}`); // normalize any fault (safeMsg cannot itself throw)
    }
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    if (this.#innerIsLocal) return this.#inner.generate(req); // on-box (trusted-config) provider: no net egress, no permit
    const cancellationId = req.signal === undefined ? undefined : this.#deps.requestId();
    if (cancellationId !== undefined) this.#cancellations.set(cancellationId, req.signal!);
    try { return resultFromOutput(await this.#authorizeAndDispatch(() => reqToArgs(req, cancellationId, this.#deps.externalRouting))); }
    finally { if (cancellationId !== undefined) this.#cancellations.delete(cancellationId); }
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    if (this.#innerIsLocal) return this.#inner.embed(texts);
    // The array/length guard is defensive (a revoked/throwing Proxy must not escape as a raw error).
    let empty: boolean;
    try { empty = !Array.isArray(texts) || texts.length === 0; } catch { throw new EgressDeniedError("malformed embed input"); }
    if (empty) return [];
    const out = decodeCanonical(encodeCanonical(await this.#authorizeAndDispatch(() => embedToArgs(texts)))) as Record<string, unknown>;
    if (typeof out.vectorsJson !== "string") throw new EgressDeniedError("brokered embed returned a malformed result");
    let parsed: unknown;
    try { parsed = JSON.parse(out.vectorsJson); } catch { throw new EgressDeniedError("brokered embed returned unparseable vectors"); }
    if (!Array.isArray(parsed) || !parsed.every((v) => Array.isArray(v) && v.every((x) => typeof x === "number" && Number.isFinite(x)))) {
      throw new EgressDeniedError("brokered embed returned a malformed vector (not finite-number arrays)");
    }
    return (parsed as number[][]).map((v) => v);
  }

  async embedBounded(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult> {
    if (!this.#inner.embedBounded) throw new EgressDeniedError("bounded embedding unavailable; no unmetered fallback");
    if (this.#innerIsLocal) return this.#inner.embedBounded(texts, options);
    if (!Array.isArray(texts) || texts.length > 65_536) throw new EgressDeniedError("invalid bounded embedding inputs");
    let bytes = 0;
    const captured = texts.map(text => {
      if (typeof text !== "string" || !text || (bytes += Buffer.byteLength(text)) > 4_194_304) throw new EgressDeniedError("invalid bounded embedding windows");
      return text;
    });
    const bounds = { maxBatchWindows: options.maxBatchWindows ?? 64, maxBatchBytes: options.maxBatchBytes ?? 65_536, maxResponseBytes: options.maxResponseBytes ?? 4_194_304 };
    if (!Object.values(bounds).every(n => Number.isSafeInteger(n) && n > 0) || (options.role !== undefined && options.role !== "query" && options.role !== "document")) throw new EgressDeniedError("invalid bounded embedding declaration");
    const invocationId = this.#deps.requestId();
    const args: CanonicalValue = { kind: "embed-bounded", invocationId, texts: captured, boundsJson: JSON.stringify(bounds),
      role: options.role ?? "unspecified", ...(this.#deps.externalRouting === undefined ? {} : { routing: routingArgs(this.#deps.externalRouting)! }) };
    const assertCallerAuthority = options.assertAuthority;
    const capturedOptions = Object.freeze({ ...bounds, reserve: options.reserve,
      ...(options.role === undefined ? {} : { role: options.role }), ...(options.signal === undefined ? {} : { signal: options.signal }),
      assertAuthority: () => {
        this.#deps.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.modelNetwork.id);
        if (this.#deps.releaseAdmission && !verifyRestrictedReleaseAdmission(this.#deps.releaseAdmission)) throw new EgressDeniedError("embedding release admission expired before HTTP dispatch");
        const decision = this.#deps.kernel.decide({ atEpoch: this.#deps.epoch(), subject: this.#deps.subject, entryPoint: this.#deps.entryPoint, effectId: this.#deps.netEffectId, context: new Map() });
        if (decision.verdict !== "allow") throw new EgressDeniedError("embedding policy withdrew dispatch authority");
        assertCallerAuthority?.();
      },
    });
    this.#embeddings.set(invocationId, { objectId: objectIdOf(args), options: capturedOptions });
    try {
      const out = decodeCanonical(encodeCanonical(await this.#authorizeAndDispatch(() => args))) as Record<string, unknown>;
      if (out.kind !== "embed-bounded" || typeof out.resultJson !== "string") throw new EgressDeniedError("malformed bounded embedding result");
      const result = JSON.parse(out.resultJson) as BoundedEmbeddingResult;
      if (!Array.isArray(result.vectors) || result.vectors.length !== captured.length || !result.vectors.every(v => Array.isArray(v) && v.length > 0 && v.every(n => typeof n === "number" && Number.isFinite(n))) ||
          !result.reserved || !result.dispatched || !(["requests", "inputBytes", "windows"] as const).every(k =>
            Number.isSafeInteger(result.reserved[k]) && Number.isSafeInteger(result.dispatched[k]) && result.dispatched[k] >= 0 && result.reserved[k] >= result.dispatched[k])) throw new EgressDeniedError("malformed bounded embedding accounting or vectors");
      return result;
    } finally { this.#embeddings.delete(invocationId); }
  }

  // NOTE: `generateStream` is intentionally NOT implemented — brokering the raw stream (delta pass-through through the
  // inert-canonical broker boundary) is a follow-on. Since ModelProvider.generateStream is OPTIONAL, a caller wanting a
  // stream falls back to the (brokered) non-streaming `generate`; the wrapper never offers a broken/unmediated stream path.
}
