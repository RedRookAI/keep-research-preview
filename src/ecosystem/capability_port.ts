/**
 * Capability port (Phase 6) — the unifying ecosystem abstraction.
 *
 * The convergence insight (OASF, 2026): MCP servers (agent->tool) and A2A agents
 * (agent->agent) are EQUIVALENT capability sources. That maps exactly onto Keep's
 * port pattern — both are adapters behind ONE capability port. Keep doesn't pick a
 * protocol; it exposes both behind this seam.
 *
 * SECURITY IS INHERITED, NOT RE-SOLVED. Per the port-security model + NSA/CISA MCP
 * guidance (Jun 2026) and the 2026 unauthenticated-server crisis (>8,000 of >10,000
 * MCP servers found unauthenticated), every capability adapter is HOSTILE:
 *   - scoped, credential-isolated identity (Phase 0),
 *   - confined below the trust boundary,
 *   - a trust tier (untrusted by default; verified only after the intake gauntlet),
 *   - every invocation inspected + logged to the spine (no unmonitored side-channel).
 *
 * Keep is the STAR-topology orchestration hub: agents delegate THROUGH Keep, which
 * avoids A2A peer-to-peer's N-squared overhead.
 */

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { canonicalize } from "../spine/event.js";
import type { Spine } from "../spine/spine.js";
import {
  resolveCapabilityEffect,
  type CapabilityIdentity,
  type CapabilityEffect,
} from "../reference/reference_registry.js";

export type CapabilityKind = "mcp-server" | "a2a-agent" | "connector";

export type CapabilityTrust = "untrusted" | "verified";

export interface CapabilityDescriptor {
  readonly id: string;
  readonly kind: CapabilityKind;
  readonly name: string;
  /** The scoped credential id this adapter holds (isolated, revocable — Phase 0). */
  readonly credentialId: string;
  /** Untrusted by default; only "verified" after the hostile-intake gauntlet. */
  readonly trust: CapabilityTrust;
  /** Exact tenant owning the adapter credential. Omitted is the private n=1 namespace only. */
  readonly tenant?: string;
  /** Server-owned admission facts used by the fleet barrier; callers cannot supply these values. */
  readonly fleet?: {
    readonly admissionUnits: number;
    readonly resourceDomain: string;
    readonly targetArgument?: string;
  };
}

export interface CapabilityInvocation {
  readonly capabilityId: string;
  /** The tool/skill/method being invoked. */
  readonly operation: string;
  readonly args: Readonly<Record<string, unknown>>;
  /** W3C Trace Context (MCP 2026-07-28 carries this in _meta) to thread tracing. */
  readonly traceparent?: string;
  /** Exact cancellation signal for adapters that support bounded execution; never serialized. */
  readonly signal?: AbortSignal;
  /** Digest mode keeps sensitive arguments out of the spine while retaining their hub-computed identity. */
  readonly auditArgs?: "full" | "digest";
}

export interface CapabilityResult {
  readonly ok: boolean;
  readonly output?: unknown;
  readonly error?: string;
  /** On hub results, true ONLY when the hub never entered the adapter. Adapter claims are overwritten.
   * False/absent does not establish external success or failure and cannot justify releasing uncertain capacity. */
  readonly held?: boolean;
}

/** Universal hostile-result bound for every non-HTTP capability transport. */
export function boundedCapabilityOutput(value: unknown, maxBytes = 1024 * 1024): unknown {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 16 * 1024 * 1024) throw new Error("capability result bound is invalid");
  let encoded: string;
  try { encoded = JSON.stringify(value); } catch { throw new Error("capability result is not JSON-serializable"); }
  if (encoded === undefined || Buffer.byteLength(encoded, "utf8") > maxBytes) throw new Error("capability result exceeded configured byte bound");
  return value;
}

export interface CapabilityFleetPermit {
  readonly operationId: string;
  readonly tenant: string;
  readonly agent: string;
  readonly admissionDigest: string;
  readonly effectDigest: string;
}

/** Exact, payload-bound authority for one consequential capability call. */
export interface CapabilityAuthorization {
  readonly id: string;
  readonly actor: string;
  readonly capabilityId: string;
  readonly operation: string;
  readonly consequence: "external" | "destructive";
  readonly idempotencyKey: string;
  readonly argsDigest: string;
}
export type CapabilityAuthorizationVerifier = (authorization: CapabilityAuthorization) => boolean;
export function capabilityArgsDigest(args: Readonly<Record<string, unknown>>): string {
  return createHash("sha256").update("keep.capability-args/v1\0").update(canonicalize(args)).digest("hex");
}

export function capabilityInvocationDigest(inv: CapabilityInvocation, descriptor: CapabilityDescriptor, tenant?: string): string {
  return createHash("sha256").update("keep.capability-invocation/v2\0").update(canonicalize({
    capabilityId: inv.capabilityId, operation: inv.operation, args: inv.args,
    tenant: tenant ?? "keep.n1.default", fleet: descriptor.fleet ?? null,
  })).digest("hex");
}

// ── BUILD-ORDER 8.43 — the UNIVERSAL EXTERNAL-EFFECT WRAPPER (the Policy Enforcement Point) ──
//
// Saltzer & Schroeder's COMPLETE MEDIATION: every access to an externally-effectful capability is checked, at
// ONE chokepoint, against the RESOLVED capability class (8.44B `resolveCapabilityEffect`) — never a caller-supplied
// prose flag (a flag is attacker/caller-controlled; only the resolved identity is trustworthy). The reference-monitor
// decision over the resolved class:
//   - recoverable            → ALLOW  (local, revert-safe — no reach outside the workspace)
//   - external | destructive → HOLD   unless the operator EXPLICITLY confirmed (so it cannot slip past confirmation)
//   - unknown / unclassified → HOLD   fail-closed (deny-by-default; an unenumerated capability is NEVER waved through,
//                                      and no confirmation can certify a class the allowlist has never classified)
// The identity classified is the OPERATION actually being invoked (the callee the adapter forwards to callTool/
// sendTask) — the true resolved tool, not a description of it.

export type EffectMediationRoute = "allow" | "hold";

export interface EffectMediationDecision {
  readonly route: EffectMediationRoute;
  /** The resolved effect class the decision was derived from (audit trail). */
  readonly effect: CapabilityEffect | "unknown";
  /** true only when the identity matched the 8.44B allowlist. */
  readonly known: boolean;
  /** The resolved identity key the verdict was derived from. */
  readonly id: string;
  readonly reason: string;
}

/**
 * The reference-monitor decision for one externally-effectful capability call. Deterministic, offline, pure. The
 * effect CLASS is always derived from the resolved identity (8.44B), never from a caller flag; `confirmed` only
 * authorizes a KNOWN external/destructive effect to proceed — it can never wave through an UNKNOWN capability.
 */
export function decideEffectMediation(
  identity: CapabilityIdentity,
  opts: { readonly confirmed?: boolean } = {},
): EffectMediationDecision {
  const cap = resolveCapabilityEffect(identity);
  // Fail-closed FIRST: an unknown/unclassified capability is HELD regardless of any confirmation.
  if (!cap.known) {
    return {
      route: "hold", effect: "unknown", known: false, id: cap.id,
      reason: `unknown capability "${cap.id}" — held for review (deny-by-default); not in the 8.44B allowlist`,
    };
  }
  if (cap.effect === "recoverable") {
    return {
      route: "allow", effect: cap.effect, known: true, id: cap.id,
      reason: `recoverable capability "${cap.id}" — local/revert-safe; allowed`,
    };
  }
  // external | destructive: reaches the world / destroys work — HOLD unless the operator confirmed.
  if (opts.confirmed === true) {
    return {
      route: "allow", effect: cap.effect, known: true, id: cap.id,
      reason: `${cap.effect} capability "${cap.id}" — operator-confirmed; allowed`,
    };
  }
  return {
    route: "hold", effect: cap.effect, known: true, id: cap.id,
    reason: `${cap.effect} capability "${cap.id}" — held for operator confirmation (cannot auto-proceed)`,
  };
}

// ── Enumerated-surface COARSE TRIPWIRE (NOT a complete-mediation proof) ──
//
// HONEST SCOPE (corrected after the cross-family veto + mutation gate, 2026-08-17): `scanForBypasses` is a COARSE
// enumerated tripwire — it fails only if an ENUMERATED entry file drops the `GATE_MARKER` SUBSTRING. It is NOT a
// completeness proof and must never be claimed as one: (a) it is a substring scan, so removing the actual gate CALL
// while the marker text survives elsewhere in the file leaves it GREEN (the mutation gate proved this — the
// completeness assertion SURVIVED neutering the real enforcement); (b) it cannot see an effectful entry point the
// hand-written `EFFECTFUL_ENTRY_POINTS` inventory omits. What IS load-bearing here is the BEHAVIOR mediation in
// `decideEffectMediation` (mutation-gate-verified: neutering unknown-HELD / external-HELD reddens its test). REAL
// complete mediation — every effectful path proven to route through the gate, verified by removing the real CALL —
// is the METHOD/PATH REACHABILITY GATE (deferred; the honest completeness enforcement, not this tripwire).

export interface EffectfulEntryPoint {
  /** Human id for the audit trail, e.g. "CapabilityHub.invoke". */
  readonly id: string;
  /** Repo-relative source file the entry point lives in. */
  readonly file: string;
  /** The world-reaching thing it forwards to (documentation of WHY it is effectful). */
  readonly reaches: string;
}

/** The marker every effectful entry point MUST contain to prove it consults the gate. */
export const GATE_MARKER = "decideEffectMediation";

/**
 * The enumerated effectful surface. Adding a new externally-effectful entry point WITHOUT routing it through
 * `decideEffectMediation` makes `scanForBypasses` (and the CI test) RED — so the enumeration cannot silently drift
 * out of coverage. Today there is exactly ONE route to an external capability: `CapabilityHub.invoke`.
 */
export const EFFECTFUL_ENTRY_POINTS: readonly EffectfulEntryPoint[] = [
  {
    id: "CapabilityHub.invoke",
    file: "src/ecosystem/capability_port.ts",
    reaches: "adapter.invoke → transport.callTool / transport.sendTask (MCP/A2A/connector — reaches the world)",
  },
];

export interface MediationBypass {
  readonly entry: string;
  readonly file: string;
  readonly reason: string;
}

export interface MediationScanResult {
  readonly complete: boolean;
  readonly bypasses: readonly MediationBypass[];
  /** The entry-point files actually consulted (for the audit trail). */
  readonly checked: readonly string[];
}

/**
 * PURE, injectable core (so a test can feed a synthetic bypass fixture): an enumerated entry point is a BYPASS if
 * its source is absent (unaccounted-for) or does not consult the effect gate (`GATE_MARKER`). Complete iff none.
 */
export function scanForBypasses(
  entries: readonly EffectfulEntryPoint[],
  sources: ReadonlyMap<string, string>,
): MediationScanResult {
  const bypasses: MediationBypass[] = [];
  const checked: string[] = [];
  for (const e of entries) {
    const src = sources.get(e.file);
    if (src === undefined) {
      bypasses.push({ entry: e.id, file: e.file, reason: "entry-point source not found — coverage unaccounted for" });
      continue;
    }
    checked.push(e.file);
    if (!src.includes(GATE_MARKER)) {
      bypasses.push({
        entry: e.id, file: e.file,
        reason: `reaches an external capability without consulting the effect gate (${GATE_MARKER}() absent)`,
      });
    }
  }
  return { complete: bypasses.length === 0, bypasses, checked };
}

/**
 * The MEASURED completeness property over the real source tree: read every enumerated entry point's source under
 * `srcRoot` and run `scanForBypasses`. Deterministic, offline (reads local files only).
 */
export function verifyCompleteMediation(
  srcRoot: string,
  entries: readonly EffectfulEntryPoint[] = EFFECTFUL_ENTRY_POINTS,
): MediationScanResult {
  const sources = new Map<string, string>();
  for (const e of entries) {
    try {
      sources.set(e.file, readFileSync(join(srcRoot, e.file), "utf8"));
    } catch {
      // absent → scanForBypasses records it as an unaccounted-for bypass (fail-closed).
    }
  }
  return scanForBypasses(entries, sources);
}

/** An adapter behind the capability port (MCP server, A2A agent, connector). */
export interface CapabilityAdapter {
  readonly descriptor: CapabilityDescriptor;
  invoke(inv: CapabilityInvocation, context?: { readonly effect: CapabilityEffect | "unknown"; readonly authorized: boolean;
    readonly fleetOperation?: { readonly tenant: string; readonly operationId: string; readonly effectDigest: string };
  }): Promise<CapabilityResult>;
}

/**
 * The capability registry + invocation mediator. All capability calls flow through
 * here so every one is (a) identity/trust-checked and (b) logged to the spine.
 */
export class CapabilityHub {
  private readonly adapters = new Map<string, CapabilityAdapter>();
  private fleetGate?: { readonly kind: "verify" | "claim"; readonly check: (permit: CapabilityFleetPermit, effectDigest: string) => Promise<boolean> };

  constructor(
    private readonly spine: Spine,
    private readonly clock: () => number = () => Date.now(),
    private readonly verifyAuthorization?: CapabilityAuthorizationVerifier,
  ) {}

  register(adapter: CapabilityAdapter): void {
    const tenant = adapter.descriptor.tenant;
    if (tenant !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(tenant)) throw new Error("invalid capability tenant");
    const fleet = adapter.descriptor.fleet;
    if (fleet !== undefined && (!Number.isSafeInteger(fleet.admissionUnits) || fleet.admissionUnits < 1 || fleet.admissionUnits > 1_000_000
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(fleet.resourceDomain)
      || (fleet.targetArgument !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(fleet.targetArgument)))) throw new Error("invalid capability fleet profile");
    const key = this.adapterKey(adapter.descriptor.id, tenant);
    if (this.adapters.has(key)) throw new Error("duplicate capability identity in tenant namespace");
    this.adapters.set(key, adapter);
    this.spine.stage({
      type: "identity.action",
      actor: "capability-hub",
      payload: {
        event: "capability.registered",
        id: adapter.descriptor.id,
        kind: adapter.descriptor.kind,
        trust: adapter.descriptor.trust,
        tenant: tenant ?? null,
      },
    });
  }

  list(tenant?: string): CapabilityDescriptor[] {
    return [...this.adapters.values()].filter((a) => a.descriptor.tenant === tenant).map((a) => a.descriptor);
  }

  /** Resolve only the exact tenant credential namespace; enterprise never falls back to n=1 credentials. */
  describe(capabilityId: string, tenant?: string): CapabilityDescriptor | undefined {
    return this.adapters.get(this.adapterKey(capabilityId, tenant))?.descriptor;
  }

  /** When installed, every adapter dispatch requires an exact active fleet permit. */
  installFleetPermitVerifier(verifier: (permit: CapabilityFleetPermit, effectDigest: string) => Promise<boolean>): void {
    if (this.fleetGate !== undefined) throw new Error("fleet permit verifier already installed");
    this.fleetGate = { kind: "verify", check: verifier };
  }

  /** Composed fleet execution uses this one-use durable gate, not the legacy read-only verifier. */
  installFleetDispatchClaimer(claimer: (permit: CapabilityFleetPermit, effectDigest: string) => Promise<boolean>): void {
    if (this.fleetGate !== undefined) throw new Error("fleet permit verifier already installed");
    this.fleetGate = { kind: "claim", check: claimer };
  }

  /**
   * Invoke a capability through the hub. Application-layer inspection: the full
   * request/response is logged to the spine (MCP/A2A traffic is auditable, not a
   * side-channel). An untrusted capability may be invoked, but callers can require
   * `verified` for authority-bearing operations via `requireVerified`.
   */
  async invoke(inv: CapabilityInvocation, opts: { requireVerified?: boolean; confirm?: boolean; authorization?: CapabilityAuthorization; tenant?: string; fleetPermit?: CapabilityFleetPermit } = {}): Promise<CapabilityResult> {
    let started = false;
    try {
      // Snapshot caller-owned JSON and scalars before any asynchronous authority check.
      // The same bounded immutable value reaches hashing, audit and the adapter.
      inv = Object.freeze({ ...inv, args: captureInvocationArgs(inv.args) });
      opts = Object.freeze({ ...opts, ...(opts.fleetPermit === undefined ? {} : { fleetPermit: Object.freeze({ ...opts.fleetPermit }) }) });
      const adapter = this.adapters.get(this.adapterKey(inv.capabilityId, opts.tenant));
      if (!adapter) {
        return { ok: false, held: true, error: `no capability "${inv.capabilityId}" registered` };
      }
      if (opts.requireVerified && adapter.descriptor.trust !== "verified") {
        const denied: CapabilityResult = { ok: false, held: true, error: `capability "${inv.capabilityId}" is untrusted; verified required` };
        this.logTraffic(inv, denied, adapter.descriptor.trust, "denied-untrusted", opts.tenant);
        return denied;
      }
      // COMPLETE MEDIATION (8.43): consult the RESOLVED effect class BEFORE reaching the world. This is the ONE route
      // to the adapter — the adapters map is private and no accessor returns an adapter, so nothing invokes an adapter
      // without passing here. Unknown → HOLD (fail-closed); external/destructive → HOLD unless operator-confirmed;
      // recoverable → allow. A HELD call NEVER invokes the adapter; the hold is logged so the decision is auditable.
      let exactAuthorized = false;
      if (opts.authorization && this.verifyAuthorization) {
        try {
          const resolved = resolveCapabilityEffect(inv.operation);
          exactAuthorized = resolved.known && resolved.effect !== "recoverable"
            && opts.authorization.capabilityId === inv.capabilityId
            && opts.authorization.operation === inv.operation
            && opts.authorization.consequence === resolved.effect
            && opts.authorization.argsDigest === capabilityArgsDigest(inv.args)
            && this.verifyAuthorization(opts.authorization) === true;
        } catch { exactAuthorized = false; }
      }
      const confirmed = exactAuthorized || opts.confirm === true;
      const decision = decideEffectMediation(inv.operation, { confirmed });
      if (decision.route === "hold") {
        const held: CapabilityResult = { ok: false, held: true, error: `capability effect held: ${decision.reason}` };
        this.logTraffic(inv, held, adapter.descriptor.trust, `held-${decision.effect}`, opts.tenant);
        return held;
      }
      // Persist request evidence with the subsequent durable claim before adapter entry.
      this.logTraffic(inv, undefined, adapter.descriptor.trust, "request", opts.tenant);
      let fleetOperation: { readonly tenant: string; readonly operationId: string; readonly effectDigest: string } | undefined;
      if (this.fleetGate !== undefined) {
        const effectDigest = capabilityInvocationDigest(inv, adapter.descriptor, opts.tenant);
        // A rejected/throwing claim cannot establish that another invocation has not begun.
        if (this.fleetGate.kind === "claim" && opts.fleetPermit !== undefined) started = true;
        if (opts.fleetPermit === undefined || !await this.fleetGate.check(opts.fleetPermit, effectDigest)) {
          const held: CapabilityResult = { ok: false, held: !started, ...(started ? { output: { indeterminate: true } } : {}), error: "capability effect held: exact active fleet permit required" };
          this.logTraffic(inv, held, adapter.descriptor.trust, "held-fleet-permit", opts.tenant);
          return held;
        }
        fleetOperation = Object.freeze({ tenant: opts.fleetPermit.tenant, operationId: opts.fleetPermit.operationId, effectDigest });
      }
      let result: CapabilityResult;
      try {
        started = true;
        const returned = await adapter.invoke(inv, Object.freeze({ effect: decision.effect, authorized: confirmed, ...(fleetOperation === undefined ? {} : { fleetOperation }) }));
        result = { ...returned, ok: returned.ok === true, held: false };
      } catch (err) {
        result = { ok: false, held: false, output: { indeterminate: true },
          error: `capability threw after dispatch; outcome unknown: ${err instanceof Error ? err.message : "non-Error throw"}` };
      }
      this.logTraffic(inv, result, adapter.descriptor.trust, "response", opts.tenant);
      return result;
    } catch {
      // Includes a response-audit failure AFTER the effect. Never turn that into
      // evidence of non-execution. No retry or best-effort second audit write here.
      return { ok: false, held: !started, ...(started ? { output: { indeterminate: true } } : {}), error: started
        ? "capability failed after dispatch; outcome unknown"
        : "capability failed before dispatch" };
    }
  }

  private adapterKey(capabilityId: string, tenant: string | undefined): string {
    return `${tenant ?? "keep.n1.default"}\0${capabilityId}`;
  }

  private logTraffic(inv: CapabilityInvocation, result: CapabilityResult | undefined, trust: CapabilityTrust, phase: string, tenant?: string): void {
    this.spine.stage({
      type: "identity.action",
      actor: "capability-hub",
      payload: {
        event: "capability.traffic",
        phase,
        capabilityId: inv.capabilityId,
        operation: inv.operation,
        trust,
        tenant: tenant ?? null,
        // Arguments/results captured for the audit trail (application-layer inspection).
        args: inv.auditArgs === "digest"
          ? { sha256: createHash("sha256").update("keep.capability-args/v1\0").update(canonicalize(inv.args)).digest("hex") }
          : inv.args,
        ...(result !== undefined ? { ok: result.ok, error: result.error ?? null } : {}),
        ...(inv.traceparent !== undefined ? { traceparent: inv.traceparent } : {}),
        ts: this.clock(),
      },
    });
  }
}

function captureInvocationArgs(args: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> {
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new Error("capability arguments must be a JSON object");
  const encoded = JSON.stringify(args);
  if (encoded === undefined || Buffer.byteLength(encoded, "utf8") > 1024 * 1024) throw new Error("capability argument byte bound");
  const copy: unknown = JSON.parse(encoded);
  if (copy === null || typeof copy !== "object" || Array.isArray(copy)) throw new Error("capability arguments must encode a JSON object");
  const freeze = (value: unknown, depth: number): void => {
    if (value === null || typeof value !== "object") return;
    if (depth > 128) throw new Error("capability argument depth bound");
    for (const child of Object.values(value)) freeze(child, depth + 1);
    Object.freeze(value);
  };
  freeze(copy, 0);
  return copy as Readonly<Record<string, unknown>>;
}
