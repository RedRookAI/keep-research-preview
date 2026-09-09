import { createHash } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import { canonicalize } from "../spine/event.js";
import { checkSharedCapacity } from "./shared_resource.js";
import { jointReversibilityReasons, type Effect } from "./joint_reversibility.js";
import { checkCrossAgentFlow } from "./cross_agent_taint.js";
import { checkExplicitCorrelation, FLEET_BASIS_DIMENSIONS, type ExplicitCorrelationBasis, type FleetBasisDimension } from "./fleet_correlation.js";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
export type { FleetBasisDimension } from "./fleet_correlation.js";
export type FleetBasis = ExplicitCorrelationBasis;

export interface FleetLifecyclePolicy {
  readonly cap: number;
  readonly maxPerBasis: number;
  readonly perTenantCap?: number;
  readonly maxActive?: number;
  readonly maxActivePerTenant?: number;
  readonly maxPerTenantBasis?: number;
}

interface NormalizedFleetPolicy { readonly cap: number; readonly maxPerBasis: number; readonly perTenantCap: number; readonly maxActive: number; readonly maxActivePerTenant: number; readonly maxPerTenantBasis: number }

export interface FleetProvenanceHop {
  readonly agent: string;
  readonly taint: "trusted" | "untrusted";
  readonly source: string;
  /** Present when a human authority explicitly changed an untrusted hop's effective label. */
  readonly declassifiedBy?: string;
}

export interface FleetAdmissionRequest {
  readonly operationId: string;
  readonly tenant: string;
  readonly agent: string;
  readonly amount: number;
  readonly gateAutoProceed: boolean;
  readonly writeSet: readonly string[];
  readonly inverseDependsOn: readonly string[];
  readonly externalSink: boolean;
  readonly provenance: readonly FleetProvenanceHop[];
  readonly basis: FleetBasis;
  /** Exact canonical invocation identity when this admission authorizes a CapabilityHub effect. */
  readonly effectDigest?: string;
}

export interface FleetAdmissionHandle {
  readonly operationId: string;
  readonly tenant: string;
  readonly agent: string;
  readonly admissionDigest: string;
  readonly effectDigest: string;
}

export type FleetLifecycleAdmission =
  | { readonly proceed: false; readonly reasons: readonly string[] }
  | { readonly proceed: true; readonly reasons: readonly []; readonly handle: FleetAdmissionHandle };

interface CapturedAdmission extends Omit<FleetAdmissionRequest, "gateAutoProceed" | "effectDigest"> {
  readonly schema: "keep.fleet-admission/v1";
  readonly policyDigest: string;
  readonly admissionDigest: string;
  readonly effectDigest: string;
}

interface Projection {
  readonly claims: Set<string>;
  readonly terminals: Map<string, "committed" | "released">;
  readonly active: Map<string, CapturedAdmission>;
  readonly admissions: Map<string, CapturedAdmission>;
  readonly consumed: Set<string>;
  readonly quarantined: Map<string, string>;
  readonly policyDigest?: string;
  readonly committedByTenant: Map<string, number>;
  committed: number;
}

/**
 * One crash-reconstructible fleet transaction over the canonical Spine. Capacity, rollback dependencies,
 * provenance and every common-cause dimension are fields of one admission event, so they cannot tear apart.
 */
export class FleetAdmissionLifecycle {
  private policy: NormalizedFleetPolicy;
  private policyDigest: string;

  constructor(private readonly spine: Spine, policy: FleetLifecyclePolicy, opts: { readonly sharedTenancy?: boolean } = {}) {
    if (!spine.durableStorage()) throw new Error("fleet admission requires the durable canonical Spine");
    this.policy = normalizePolicy(policy);
    if (opts.sharedTenancy === true && (policy.perTenantCap === undefined || policy.maxActivePerTenant === undefined || policy.maxPerTenantBasis === undefined
      || this.policy.perTenantCap >= this.policy.cap || this.policy.maxActivePerTenant >= this.policy.maxActive || this.policy.maxPerTenantBasis >= this.policy.maxPerBasis)) {
      throw new Error("shared fleet policy requires explicit tenant shares below deployment-wide ceilings");
    }
    this.policyDigest = digest({ schema: "keep.fleet-policy/v1", ...this.policy });
    this.project();
  }

  async admit(input: FleetAdmissionRequest): Promise<FleetLifecycleAdmission> {
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      const reasons: string[] = [];
      if (!input.gateAutoProceed) reasons.push("per-decision-gate-hold");
      let captured: CapturedAdmission | undefined;
      try { captured = captureAdmission(input, this.policyDigest); }
      catch { reasons.push("invalid-fleet-admission"); }
      if (captured === undefined) return Object.freeze({ proceed: false, reasons: Object.freeze([...new Set(reasons)]) });
      const state = this.project();
      if (state.policyDigest !== undefined && state.policyDigest !== this.policyDigest) reasons.push("fleet-policy-mismatch");
      if (captured !== undefined) {
        if (state.consumed.has(operationKey(captured.tenant, captured.operationId))) reasons.push("duplicate-operation-id");
        const active = [...state.active.values()], outstanding = active.reduce((sum, row) => sum + row.amount, 0);
        const capacity = checkSharedCapacity(this.policy.cap, state.committed, outstanding, captured.amount);
        if (!capacity.granted) reasons.push(reasonClass(capacity.reason));
        const tenantActive = active.filter((row) => row.tenant === captured!.tenant), tenantOutstanding = tenantActive.reduce((sum, row) => sum + row.amount, 0);
        const tenantCommitted = state.committedByTenant.get(captured.tenant) ?? 0;
        const tenantCapacity = checkSharedCapacity(this.policy.perTenantCap, tenantCommitted, tenantOutstanding, captured.amount);
        if (!tenantCapacity.granted) reasons.push(`tenant-${reasonClass(tenantCapacity.reason)}`);
        if (active.length >= this.policy.maxActive) reasons.push("fleet-active-limit");
        if (tenantActive.length >= this.policy.maxActivePerTenant) reasons.push("tenant-active-limit");
        reasons.push(...jointReversibilityReasons(
          { id: captured.operationId, agent: captured.agent, writeSet: captured.writeSet, inverseDependsOn: captured.inverseDependsOn },
          active.map((row): Effect => ({ id: row.operationId, agent: row.agent, writeSet: row.writeSet, inverseDependsOn: row.inverseDependsOn })),
        ).map(reasonClass));
        const flow = checkCrossAgentFlow({ agent: captured.agent, externalSink: captured.externalSink, chain: { hops: captured.provenance } });
        if (!flow.clean) reasons.push(reasonClass(flow.reason));
        reasons.push(...checkExplicitCorrelation(captured.basis, active.map((row) => row.basis), this.policy.maxPerBasis).map(redactCorrelation));
        if (this.policy.maxPerTenantBasis < this.policy.maxPerBasis) reasons.push(...checkExplicitCorrelation(captured.basis, tenantActive.map((row) => row.basis), this.policy.maxPerTenantBasis).map((reason) => `tenant-${redactCorrelation(reason)}`));
      }
      if (reasons.length > 0) return Object.freeze({ proceed: false, reasons: Object.freeze([...new Set(reasons)]) });
      this.spine.stage({ type: "effect.intent", actor: "fleet-lifecycle", payload: { event: "fleet.admitted", ...captured } });
      try { await this.spine.seal(); }
      catch (error) { throw new Error(`fleet admission indeterminate:${captured.operationId}`, { cause: error }); }
      if (!this.project().active.has(operationKey(captured.tenant, captured.operationId))) throw new Error(`fleet admission indeterminate:${captured.operationId}`);
      return Object.freeze({ proceed: true, reasons: [] as const, handle: handleFor(captured) });
    });
  }

  async commit(handle: FleetAdmissionHandle): Promise<boolean> { return await this.settle(handle, "committed"); }
  async release(handle: FleetAdmissionHandle): Promise<boolean> { return await this.settle(handle, "released"); }
  async reconcile(handle: FleetAdmissionHandle, outcome: "commit" | "release"): Promise<boolean> {
    // Explicit operator disposition is not proof of sink finality. Unlike automatic
    // release, this existing trusted recovery operation may settle a claimed effect.
    return await this.settle(handle, outcome === "commit" ? "committed" : "released", true);
  }

  /** Human/operator recovery uses the same exact content-bound handle after gateway tenant authorization. */
  async reconcileAsOperator(handle: FleetAdmissionHandle, outcome: "commit" | "release"): Promise<boolean> {
    return await this.reconcile(handle, outcome);
  }

  async authorizesPermit(handle: FleetAdmissionHandle, effectDigest: string): Promise<boolean> {
    if (!/^[a-f0-9]{64}$/u.test(effectDigest)) return false;
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      let captured: FleetAdmissionHandle;
      try { captured = captureHandle(handle); } catch { return false; }
      const row = this.project().active.get(operationKey(captured.tenant, captured.operationId));
      return row !== undefined && sameHandle(captured, handleFor(row)) && row.effectDigest === effectDigest;
    });
  }

  /** Claim entry once, before entering the adapter. A claim is NOT evidence of an external effect. */
  async claimDispatch(handle: FleetAdmissionHandle, effectDigest: string): Promise<boolean> {
    let captured: FleetAdmissionHandle;
    try { captured = captureHandle(handle); } catch { return false; }
    if (captured.effectDigest !== effectDigest) return false;
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      // An earlier attempt may have staged its claim then lost the seal acknowledgment.
      // Never examine only the sealed prefix and thereby issue another claim.
      await this.spine.seal();
      const state = this.project(), key = operationKey(captured.tenant, captured.operationId);
      const row = state.active.get(key);
      if (state.quarantined.has(key) || state.claims.has(key) || row === undefined || !sameHandle(captured, handleFor(row))) return false;
      this.spine.stage({ type: "effect.intent", actor: "fleet-lifecycle", payload: {
        event: "fleet.dispatch-claimed", schema: "keep.fleet-dispatch/v1", ...captured,
      } });
      await this.spine.seal();
      const after = this.project();
      if (!after.claims.has(key) || after.quarantined.has(key)) throw new Error("fleet dispatch claim indeterminate");
      return true;
    });
  }

  /** Non-executing inspection; caller supplies current authorization and tenant/actor scope. */
  async inspect(operationId: string, tenant: string, agent?: string): Promise<{
    readonly operationId: string;
    readonly accounting: "active" | "committed" | "released";
    readonly dispatch: "claimed" | "no-sealed-claim" | "unknown-pending" | "quarantined";
    readonly effect: "unverified";
  } | undefined> {
    if (!SAFE_ID.test(operationId) || !SAFE_ID.test(tenant) || (agent !== undefined && !SAFE_ID.test(agent))) return undefined;
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () =>
      await this.spine.withStableEventView(events => {
        const state = this.project(), key = operationKey(tenant, operationId), row = state.admissions.get(key);
        if (row === undefined || (agent !== undefined && row.agent !== agent)) return undefined;
        const sealedIds = new Set(this.spine.verifiedReplay().events.map(event => event.id));
        const pending = events.some(event => !sealedIds.has(event.id) && event.actor === "fleet-lifecycle"
          && event.payload["tenant"] === tenant && event.payload["operationId"] === operationId);
        return Object.freeze({ operationId,
          accounting: state.active.has(key) ? "active" as const : state.terminals.get(key)!,
          dispatch: state.quarantined.has(key) ? "quarantined" as const : pending ? "unknown-pending" as const
            : state.claims.has(key) ? "claimed" as const : "no-sealed-claim" as const,
          effect: "unverified" as const,
        });
      }));
  }

  /** Seal an interrupted staged transition, then report its authoritative sealed disposition. */
  async recover(operationId: string, tenant: string, agent: string): Promise<{ readonly status: "absent" | "terminal" } | { readonly status: "active"; readonly handle: FleetAdmissionHandle }> {
    if (!SAFE_ID.test(operationId) || !SAFE_ID.test(tenant) || !SAFE_ID.test(agent)) return { status: "absent" };
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      await this.spine.seal();
      const state = this.project(), key = operationKey(tenant, operationId), admission = state.admissions.get(key);
      if (admission === undefined || admission.agent !== agent) return Object.freeze({ status: "absent" as const });
      const active = state.active.get(key);
      return active === undefined ? Object.freeze({ status: "terminal" as const }) : Object.freeze({ status: "active" as const, handle: handleFor(active) });
    });
  }

  active(tenant?: string): readonly FleetAdmissionHandle[] {
    if (tenant !== undefined && !SAFE_ID.test(tenant)) throw new Error("invalid fleet tenant");
    return Object.freeze([...this.project().active.values()]
      .filter((row) => tenant === undefined || row.tenant === tenant)
      .map(handleFor));
  }

  async activeCoordinated(tenant?: string): Promise<readonly FleetAdmissionHandle[]> {
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => this.active(tenant));
  }

  async integrityStatus(tenant?: string): Promise<{ readonly quarantined: number; readonly identities: readonly string[] }> {
    if (tenant !== undefined && !SAFE_ID.test(tenant)) throw new Error("invalid fleet tenant");
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      const quarantined = this.project().quarantined;
      const visible = [...quarantined.keys()].filter((key) => tenant === undefined || key.startsWith(`${tenant}\0`));
      return Object.freeze({ quarantined: visible.length, identities: Object.freeze(visible.map((key) => digest({ schema: "keep.fleet-quarantine-identity/v1", key })).sort()) });
    });
  }

  policyIdentity(): string { return this.policyDigest; }
  configurationStatus(): { readonly ready: boolean; readonly configuredPolicyDigest: string; readonly durablePolicyDigest?: string } {
    const durablePolicyDigest = this.project().policyDigest;
    return Object.freeze({ ready: durablePolicyDigest === undefined || durablePolicyDigest === this.policyDigest, configuredPolicyDigest: this.policyDigest, ...(durablePolicyDigest === undefined ? {} : { durablePolicyDigest }) });
  }

  async rotatePolicy(policy: FleetLifecyclePolicy): Promise<void> {
    const next = normalizePolicy(policy), nextDigest = digest({ schema: "keep.fleet-policy/v1", ...next });
    await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      const state = this.project();
      if (state.active.size !== 0) throw new Error("fleet policy rotation requires no active operations");
      if (next.cap < state.committed || [...state.committedByTenant.values()].some((amount) => amount > next.perTenantCap)) throw new Error("fleet policy rotation cannot strand committed capacity");
      const fromPolicyDigest = state.policyDigest ?? this.policyDigest;
      if (nextDigest === fromPolicyDigest) { this.policy = next; this.policyDigest = nextDigest; return; }
      this.spine.stage({ type: "identity.action", actor: "fleet-lifecycle", payload: { event: "fleet.policy-rotated", schema: "keep.fleet-policy-transition/v1", fromPolicyDigest, toPolicyDigest: nextDigest, policy: next } });
      try { await this.spine.seal(); } catch (error) { throw new Error("fleet policy rotation indeterminate", { cause: error }); }
      this.policy = next; this.policyDigest = nextDigest;
      if (this.project().policyDigest !== nextDigest) throw new Error("fleet policy rotation indeterminate");
    });
  }

  /** Reconstruct upstream provenance only from exact durable handles, never caller-authored hop objects. */
  provenanceFor(handles: readonly FleetAdmissionHandle[], tenant: string): readonly FleetProvenanceHop[] {
    if (!Array.isArray(handles) || handles.length > 32 || !SAFE_ID.test(tenant)) throw new Error("invalid fleet provenance handles");
    const state = this.project(), hops: FleetProvenanceHop[] = [];
    for (const candidate of handles) {
      const handle = captureHandle(candidate);
      if (handle.tenant !== tenant) throw new Error("fleet provenance handle not found");
      const row = state.admissions.get(operationKey(tenant, handle.operationId));
      if (row === undefined || !sameHandle(handle, handleFor(row))) throw new Error("fleet provenance handle not found");
      hops.push(...row.provenance);
      if (hops.length > 63) throw new Error("fleet provenance exceeds bounded chain");
    }
    return Object.freeze(hops.map((hop) => Object.freeze({ ...hop })));
  }


  async provenanceForCoordinated(handles: readonly FleetAdmissionHandle[], tenant: string): Promise<readonly FleetProvenanceHop[]> {
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => this.provenanceFor(handles, tenant));
  }

  committedTotal(): number { return this.project().committed; }

  private async settle(handle: FleetAdmissionHandle, outcome: "committed" | "released", operatorDisposition = false): Promise<boolean> {
    return await this.spine.withCoordinationLock("fleet.admission-lifecycle", async () => {
      let capturedHandle: FleetAdmissionHandle;
      try { capturedHandle = captureHandle(handle); } catch { return false; }
      await this.spine.seal();
      const state = this.project(), key = operationKey(capturedHandle.tenant, capturedHandle.operationId);
      const row = state.active.get(key);
      if (row === undefined || !sameHandle(capturedHandle, handleFor(row))) return false;
      if (!operatorDisposition && (state.quarantined.has(key) || (outcome === "released" && state.claims.has(key)))) return false;
      this.spine.stage({ type: "effect.terminal", actor: "fleet-lifecycle", payload: {
        event: "fleet.terminal", schema: "keep.fleet-terminal/v1", operationId: row.operationId,
        admissionDigest: row.admissionDigest, outcome, tenant: row.tenant, agent: row.agent,
      } });
      try { await this.spine.seal(); }
      catch (error) { throw new Error(`fleet settlement indeterminate:${row.operationId}`, { cause: error }); }
      if (this.project().active.has(operationKey(row.tenant, row.operationId))) throw new Error(`fleet settlement indeterminate:${row.operationId}`);
      return true;
    });
  }

  private project(): Projection {
    const snapshot = this.spine.verifiedReplay();
    if (!snapshot.verification.ok) throw new Error("fleet admission refuses an unverifiable Spine");
    const state: Projection = { claims: new Set(), terminals: new Map(), active: new Map(), admissions: new Map(), consumed: new Set(), quarantined: new Map(), committedByTenant: new Map(), committed: 0 };
    let durablePolicyDigest: string | undefined;
    for (const row of snapshot.events) {
      if (row.actor !== "fleet-lifecycle") continue;
      if (row.type === "effect.intent" && row.payload["event"] === "fleet.admitted") {
        let admission: CapturedAdmission;
        try { admission = parseAdmission(row.payload); }
        catch (error) { quarantineOwned(state, row.payload, (error as Error).message); continue; }
        const key = operationKey(admission.tenant, admission.operationId);
        if (durablePolicyDigest === undefined) durablePolicyDigest = admission.policyDigest;
        if (admission.policyDigest !== durablePolicyDigest || state.consumed.has(key)) { quarantineKey(state, key, "duplicate or wrong-policy fleet admission"); continue; }
        state.consumed.add(key); state.admissions.set(key, admission); state.active.set(key, admission);
      } else if (row.type === "effect.intent" && row.payload["event"] === "fleet.dispatch-claimed") {
        try {
          const { event, schema, ...body } = row.payload;
          if (event !== "fleet.dispatch-claimed" || schema !== "keep.fleet-dispatch/v1") throw new Error("invalid fleet claim schema");
          const claim = captureHandle(body as unknown as FleetAdmissionHandle), key = operationKey(claim.tenant, claim.operationId);
          const admission = state.active.get(key);
          if (state.quarantined.has(key) || state.claims.has(key) || admission === undefined || !sameHandle(claim, handleFor(admission))) throw new Error("invalid or repeated fleet claim");
          state.claims.add(key);
        } catch { quarantineOwned(state, row.payload, "invalid fleet dispatch claim"); }
      } else if (row.type === "effect.terminal" && row.payload["event"] === "fleet.terminal") {
        let terminal: ReturnType<typeof parseTerminal>;
        try { terminal = parseTerminal(row.payload); }
        catch (error) { quarantineOwned(state, row.payload, (error as Error).message); continue; }
        const key = operationKey(terminal.tenant, terminal.operationId), admission = state.active.get(key);
        if (admission === undefined || admission.admissionDigest !== terminal.admissionDigest || admission.agent !== terminal.agent) { quarantineKey(state, key, "invalid fleet terminal evidence"); continue; }
        if (terminal.outcome === "committed") { state.committed += admission.amount; state.committedByTenant.set(admission.tenant, (state.committedByTenant.get(admission.tenant) ?? 0) + admission.amount); }
        state.active.delete(key);
        state.terminals.set(key, terminal.outcome);
      } else if (row.type === "identity.action" && row.payload["event"] === "fleet.policy-rotated") {
        try {
          const transition = parsePolicyTransition(row.payload);
          if (durablePolicyDigest === undefined) durablePolicyDigest = transition.fromPolicyDigest;
          if (transition.fromPolicyDigest !== durablePolicyDigest) throw new Error("fleet policy transition lineage mismatch");
          durablePolicyDigest = transition.toPolicyDigest;
        } catch { /* invalid fleet policy evidence grants no authority and does not poison unrelated operations */ }
      } else if (row.type === "effect.intent" || row.type === "effect.terminal" || row.type === "identity.action") {
        quarantineOwned(state, row.payload, "unrecognized fleet-owned evidence");
      }
    }
    return { ...state, ...(durablePolicyDigest === undefined ? {} : { policyDigest: durablePolicyDigest }) };
  }
}

function captureAdmission(input: FleetAdmissionRequest, policyDigest: string): CapturedAdmission {
  if (input === null || typeof input !== "object" || !SAFE_ID.test(input.operationId) || !SAFE_ID.test(input.tenant) || !SAFE_ID.test(input.agent) || !Number.isSafeInteger(input.amount) || input.amount < 1 || typeof input.externalSink !== "boolean") throw new Error("invalid fleet admission");
  const writeSet = captureSet(input.writeSet), inverseDependsOn = captureSet(input.inverseDependsOn);
  if (writeSet.length === 0 || inverseDependsOn.length === 0) throw new Error("fleet resource declarations may not be empty");
  if (!Array.isArray(input.provenance) || input.provenance.length < 1 || input.provenance.length > 64) throw new Error("invalid fleet provenance");
  const provenance = Object.freeze(input.provenance.map((hop) => {
    if (hop === null || typeof hop !== "object" || !SAFE_ID.test(hop.agent) || (hop.taint !== "trusted" && hop.taint !== "untrusted") || typeof hop.source !== "string" || hop.source.length < 1 || hop.source.length > 512) throw new Error("invalid fleet provenance hop");
    const declassifiedBy = (hop as FleetProvenanceHop).declassifiedBy;
    if (declassifiedBy !== undefined && (!SAFE_ID.test(declassifiedBy) || hop.taint !== "trusted")) throw new Error("invalid fleet declassification provenance");
    return Object.freeze({ agent: hop.agent, taint: hop.taint, source: hop.source, ...(declassifiedBy === undefined ? {} : { declassifiedBy }) });
  }));
  if (provenance.at(-1)!.agent !== input.agent) throw new Error("fleet provenance does not terminate at acting agent");
  const basis = captureBasis(input.basis);
  const effectDigest = input.effectDigest ?? digest({ schema: "keep.fleet-direct-effect/v1", tenant: input.tenant, agent: input.agent, writeSet, inverseDependsOn, basis });
  if (!/^[a-f0-9]{64}$/u.test(effectDigest)) throw new Error("invalid fleet effect identity");
  const body = { schema: "keep.fleet-admission/v1" as const, policyDigest, operationId: input.operationId, tenant: input.tenant, agent: input.agent, amount: input.amount, writeSet, inverseDependsOn, externalSink: input.externalSink, provenance, basis, effectDigest };
  return Object.freeze({ ...body, admissionDigest: digest(body) });
}

function parseAdmission(payload: Readonly<Record<string, unknown>>): CapturedAdmission {
  const keys = Object.keys(payload).sort().join(",");
  const policyDigest = String(payload["policyDigest"] ?? "");
  const currentKeys = "admissionDigest,agent,amount,basis,effectDigest,event,externalSink,inverseDependsOn,operationId,policyDigest,provenance,schema,tenant,writeSet";
  const legacyKeys = "admissionDigest,agent,amount,basis,event,externalSink,inverseDependsOn,operationId,policyDigest,provenance,schema,tenant,writeSet";
  if ((keys !== currentKeys && keys !== legacyKeys) || payload["event"] !== "fleet.admitted" || payload["schema"] !== "keep.fleet-admission/v1" || !/^[a-f0-9]{64}$/u.test(policyDigest)) throw new Error("invalid fleet admission policy evidence");
  const captured = captureAdmission({ operationId: payload["operationId"], tenant: payload["tenant"], agent: payload["agent"], amount: payload["amount"], gateAutoProceed: true, writeSet: payload["writeSet"], inverseDependsOn: payload["inverseDependsOn"], externalSink: payload["externalSink"], provenance: payload["provenance"], basis: payload["basis"], ...(keys === currentKeys ? { effectDigest: payload["effectDigest"] } : {}) } as FleetAdmissionRequest, policyDigest);
  if (keys === legacyKeys) {
    const legacyBody = { schema: captured.schema, policyDigest, operationId: captured.operationId, tenant: captured.tenant, agent: captured.agent, amount: captured.amount, writeSet: captured.writeSet, inverseDependsOn: captured.inverseDependsOn, externalSink: captured.externalSink, provenance: captured.provenance, basis: captured.basis };
    const legacyDigest = digest(legacyBody);
    if (payload["admissionDigest"] !== legacyDigest) throw new Error("fleet admission digest mismatch");
    return Object.freeze({ ...legacyBody, effectDigest: digest({ schema: "keep.fleet-legacy-effect/v1", admissionDigest: legacyDigest }), admissionDigest: legacyDigest });
  }
  if (payload["admissionDigest"] !== captured.admissionDigest) throw new Error("fleet admission digest mismatch");
  return captured;
}

function parseTerminal(payload: Readonly<Record<string, unknown>>): { operationId: string; admissionDigest: string; outcome: "committed" | "released"; tenant: string; agent: string } {
  if (Object.keys(payload).sort().join(",") !== "admissionDigest,agent,event,operationId,outcome,schema,tenant" || payload["event"] !== "fleet.terminal" || payload["schema"] !== "keep.fleet-terminal/v1" || !SAFE_ID.test(String(payload["operationId"] ?? "")) || !SAFE_ID.test(String(payload["tenant"] ?? "")) || !SAFE_ID.test(String(payload["agent"] ?? "")) || !/^[a-f0-9]{64}$/u.test(String(payload["admissionDigest"] ?? "")) || (payload["outcome"] !== "committed" && payload["outcome"] !== "released")) throw new Error("invalid fleet terminal evidence");
  return { operationId: payload["operationId"] as string, admissionDigest: payload["admissionDigest"] as string, outcome: payload["outcome"], tenant: payload["tenant"] as string, agent: payload["agent"] as string };
}

function captureSet(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length > 64) throw new Error("invalid fleet resource set");
  const out = [...value];
  if (out.some((item) => typeof item !== "string" || item.length < 1 || item.length > 256) || new Set(out).size !== out.length) throw new Error("invalid fleet resource set");
  return Object.freeze(out.sort());
}

function captureBasis(value: FleetBasis): FleetBasis {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== FLEET_BASIS_DIMENSIONS.join(",")) throw new Error("invalid fleet basis schema");
  const out = {} as Record<FleetBasisDimension, string>;
  for (const key of FLEET_BASIS_DIMENSIONS) { const item = value[key]; if (typeof item !== "string" || item.length < 1 || item.length > 512) throw new Error("invalid fleet basis"); out[key] = item; }
  return Object.freeze(out);
}

function captureHandle(handle: FleetAdmissionHandle): FleetAdmissionHandle {
  if (handle === null || typeof handle !== "object" || Object.keys(handle).sort().join(",") !== "admissionDigest,agent,effectDigest,operationId,tenant" || !SAFE_ID.test(handle.operationId) || !SAFE_ID.test(handle.tenant) || !SAFE_ID.test(handle.agent) || !/^[a-f0-9]{64}$/u.test(handle.admissionDigest) || !/^[a-f0-9]{64}$/u.test(handle.effectDigest)) throw new Error("invalid fleet handle");
  return Object.freeze({ operationId: handle.operationId, tenant: handle.tenant, agent: handle.agent, admissionDigest: handle.admissionDigest, effectDigest: handle.effectDigest });
}

function handleFor(row: CapturedAdmission): FleetAdmissionHandle { return Object.freeze({ operationId: row.operationId, tenant: row.tenant, agent: row.agent, admissionDigest: row.admissionDigest, effectDigest: row.effectDigest }); }
function sameHandle(a: FleetAdmissionHandle, b: FleetAdmissionHandle): boolean { return a.operationId === b.operationId && a.tenant === b.tenant && a.agent === b.agent && a.admissionDigest === b.admissionDigest && a.effectDigest === b.effectDigest; }
function operationKey(tenant: string, operationId: string): string { return `${tenant}\0${operationId}`; }
function reasonClass(reason: string): string { return reason.split(":", 1)[0]!; }
function redactCorrelation(reason: string): string { const [kind, dimension] = reason.split(":"); return dimension === undefined ? kind! : `${kind}:${dimension}`; }
function digest(value: unknown): string { return createHash("sha256").update(canonicalize(value)).digest("hex"); }

function normalizePolicy(policy: FleetLifecyclePolicy): NormalizedFleetPolicy {
  const cap = policy.cap, perTenantCap = policy.perTenantCap ?? cap, maxActive = policy.maxActive ?? 10_000, maxActivePerTenant = policy.maxActivePerTenant ?? 1_000, maxPerTenantBasis = policy.maxPerTenantBasis ?? policy.maxPerBasis;
  if (!Number.isSafeInteger(cap) || cap < 0 || !Number.isSafeInteger(perTenantCap) || perTenantCap < 0 || perTenantCap > cap || !Number.isSafeInteger(policy.maxPerBasis) || policy.maxPerBasis < 1 || policy.maxPerBasis > 10_000 || !Number.isSafeInteger(maxPerTenantBasis) || maxPerTenantBasis < 1 || maxPerTenantBasis > policy.maxPerBasis || !Number.isSafeInteger(maxActive) || maxActive < 1 || maxActive > 100_000 || !Number.isSafeInteger(maxActivePerTenant) || maxActivePerTenant < 1 || maxActivePerTenant > maxActive) throw new Error("invalid fleet lifecycle policy");
  return Object.freeze({ cap, maxPerBasis: policy.maxPerBasis, perTenantCap, maxActive, maxActivePerTenant, maxPerTenantBasis });
}

function quarantineKey(state: Projection, key: string, reason: string): void {
  state.quarantined.set(key, reason); state.consumed.add(key);
}

function quarantineOwned(state: Projection, payload: Readonly<Record<string, unknown>>, reason: string): void {
  const tenant = payload["tenant"], operationId = payload["operationId"];
  if (typeof tenant === "string" && SAFE_ID.test(tenant) && typeof operationId === "string" && SAFE_ID.test(operationId)) quarantineKey(state, operationKey(tenant, operationId), reason);
  else state.quarantined.set(`unbound:${digest({ schema: "keep.fleet-quarantine/v1", payload })}`, reason);
}

function parsePolicyTransition(payload: Readonly<Record<string, unknown>>): { fromPolicyDigest: string; toPolicyDigest: string } {
  if (Object.keys(payload).sort().join(",") !== "event,fromPolicyDigest,policy,schema,toPolicyDigest" || payload["event"] !== "fleet.policy-rotated" || payload["schema"] !== "keep.fleet-policy-transition/v1" || !/^[a-f0-9]{64}$/u.test(String(payload["fromPolicyDigest"] ?? "")) || !/^[a-f0-9]{64}$/u.test(String(payload["toPolicyDigest"] ?? ""))) throw new Error("invalid fleet policy transition");
  const policy = normalizePolicy(payload["policy"] as FleetLifecyclePolicy), observed = digest({ schema: "keep.fleet-policy/v1", ...policy });
  if (observed !== payload["toPolicyDigest"]) throw new Error("fleet policy transition digest mismatch");
  return { fromPolicyDigest: payload["fromPolicyDigest"] as string, toPolicyDigest: payload["toPolicyDigest"] as string };
}
