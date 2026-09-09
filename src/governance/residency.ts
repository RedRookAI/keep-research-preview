/**
 * Data-residency + egress allowlist (Phase 5, #34) — makes residency/air-gap REAL.
 *
 * Two enforced controls, both hard-DENY:
 *  - Residency: a request may only be processed in an allowed region; a destination
 *    in a disallowed region is denied.
 *  - Egress allowlist (derived from policy, per the port-security vetting): a request
 *    to a host not on the allowlist is denied. In air-gapped mode (#33) the allowlist
 *    is empty, so ALL egress denies — air-gap is enforced, not just asserted.
 */

export interface ResidencyPolicy {
  /** Regions where processing is permitted, e.g. ["eu"]. Empty => none allowed. */
  readonly allowedRegions: readonly string[];
  /** Hostnames permitted for egress. Empty => air-gapped (deny all egress). */
  readonly egressAllowlist: readonly string[];
  /** True to run fully air-gapped: forces egress denial regardless of allowlist. */
  readonly airGapped?: boolean;
  readonly allowedPurposes?: readonly string[];
}

export type ResidencyDecision = { allowed: true } | { allowed: false; reason: string };

export class ResidencyEnforcer {
  readonly #policy: ResidencyPolicy;
  constructor(policy: ResidencyPolicy) {
    this.#policy = Object.freeze({ allowedRegions: Object.freeze([...policy.allowedRegions]), egressAllowlist: Object.freeze([...policy.egressAllowlist]), ...(policy.allowedPurposes === undefined ? {} : { allowedPurposes: Object.freeze([...policy.allowedPurposes]) }), ...(policy.airGapped === undefined ? {} : { airGapped: policy.airGapped }) });
  }

  /** Check whether processing in `region` is permitted. */
  checkRegion(region: string): ResidencyDecision {
    if (!this.#policy.allowedRegions.includes(region)) {
      return { allowed: false, reason: `region "${region}" not in allowed residency set [${this.#policy.allowedRegions.join(", ")}]` };
    }
    return { allowed: true };
  }

  /** Check whether egress to `host` is permitted. Air-gap forces denial. */
  checkEgress(host: string): ResidencyDecision {
    if (this.#policy.airGapped) {
      return { allowed: false, reason: `air-gapped: egress to "${host}" denied (no network egress permitted)` };
    }
    if (!this.#policy.egressAllowlist.includes(host)) {
      return { allowed: false, reason: `egress to "${host}" denied (not on allowlist)` };
    }
    return { allowed: true };
  }

  checkPurpose(purpose: string): ResidencyDecision {
    if (!purpose.trim()) return { allowed: false, reason: "remote processing purpose is not declared" };
    if (!(this.#policy.allowedPurposes ?? []).includes(purpose)) return { allowed: false, reason: `purpose "${purpose}" not in allowed remote-purpose set` };
    return { allowed: true };
  }

  checkRemoteRequest(purpose: string, region: string, host: string): ResidencyDecision {
    const decision = this.checkPurpose(purpose);
    return decision.allowed ? this.checkRequest(region, host) : decision;
  }

  /** Combined check for a request that processes in a region and egresses to a host. */
  checkRequest(region: string, host: string | undefined): ResidencyDecision {
    const r = this.checkRegion(region);
    if (!r.allowed) return r;
    if (host !== undefined) {
      const e = this.checkEgress(host);
      if (!e.allowed) return e;
    }
    return { allowed: true };
  }

  get isAirGapped(): boolean {
    return this.#policy.airGapped === true || this.#policy.egressAllowlist.length === 0;
  }
}
