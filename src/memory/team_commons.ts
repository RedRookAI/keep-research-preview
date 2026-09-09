/**
 * TEAM MEMORY COMMONS — Teams/Enterprise arc, T2. Governed promotion of a personal lesson into the shared scope,
 * as an Ostrom GOVERNED KNOWLEDGE COMMONS.
 *
 * A shared team knowledge base is informational, non-rivalrous, but it DECAYS without governance. Shared memory
 * also changes the problem qualitatively: "a fact written by one may act for another," so authority and scope must
 * be enforced ACROSS principals, not within one. And its distinctive failure mode is PROPAGATION / memory
 * contagion — a poisoned or biased entry spreads through the team with no safe contamination threshold — so a
 * retracted entry must be CONTAINED, not left to propagate.
 *
 * Promotion instantiates the commons design principles by REUSE:
 *   - authorized ACROSS principals (T1 `may(who, "promote", resource)`);
 *   - clearly-defined boundaries (special-category context stays out of the shared scope — CI-respect);
 *   - graduated ratification (the promoted entry enters at PROBATION, never confirmed — no authority laundering);
 *   - monitoring / provenance (lineage to the origin lesson; supersede-not-delete);
 *   - containment (`retractFromShared` retires + tombstones a retracted entry — propagation stopped).
 *
 * STANDING PRINCIPLE — two tracks sharing primitives, never collapse to N=1:
 *   - N=1 FLOOR: promotion to a personal `global` scope is frictionless (the sole owner is authorized; no team id
 *     required). A solo user still has a shared library.
 *   - org CEILING: promotion to a `team` scope is a ratified commons gated by T1 relationship authority.
 *
 * BUILT + proven in-env: authorize + CI-respect + graduated ratification + containment. SEAM: the team-directory /
 * membership source (the relationship tuples that back T1's `rebacResolver`).
 */

import { may, type AuthzPrincipal, type AuthzResolver, type Resource } from "../authz/authorization.js";
import { classifySpecialCategory } from "../privacy/contextual_integrity.js";
import type { MemoryStore } from "./store.js";

export interface PromotionRequest {
  readonly content: string;
  readonly originId?: string | undefined; // the personal lesson this is promoted from (lineage)
  readonly targetScope: "team" | "global"; // team = org commons (needs a target id); global = personal shared lib
  readonly targetId?: string | undefined; // the team/library id (the T1 resource object) — required for team
}

export interface PromotionDeps {
  readonly resolver: AuthzResolver;
  readonly store: MemoryStore;
  readonly classify?: ((content: string) => string | undefined) | undefined; // CI detector (default = special-category)
}

export type PromotionResult =
  | { readonly status: "promoted"; readonly sharedId: string }
  | { readonly status: "denied"; readonly reason: string }
  | { readonly status: "blocked-sensitive"; readonly reason: string };

/**
 * Promote a personal lesson into the shared scope, governed. Authorize (T1, across principals) → CI-respect
 * (special-category context stays out of the shared scope) → enter at PROBATION with lineage (graduated
 * ratification, no authority laundering).
 */
export async function promoteToShared(req: PromotionRequest, who: AuthzPrincipal, deps: PromotionDeps): Promise<PromotionResult> {
  // A promotion to a TEAM scope must name the team (the ReBAC object); a personal GLOBAL scope needs no team id.
  if (req.targetScope === "team" && req.targetId === undefined) {
    return { status: "denied", reason: "a team promotion must name the team" };
  }

  // 1. AUTHORIZE across principals (T1).
  const resource: Resource = { surface: "memory", scope: req.targetScope, ...(req.targetId !== undefined ? { id: req.targetId } : {}) };
  const decision = may(who, "promote", resource, deps.resolver);
  if (!decision.allow) return { status: "denied", reason: decision.reason };

  // 2. CI-RESPECT: special-category context does not belong in a shared commons — it stays vaulted.
  const classify = deps.classify ?? classifySpecialCategory;
  if (classify(req.content) !== undefined) {
    return { status: "blocked-sensitive", reason: "special-category context cannot be published to a shared scope" };
  }

  // 3. GRADUATED RATIFICATION + LINEAGE: enter the shared library at PROBATION (origin `seeded`), never confirmed;
  //    cite the origin lesson for provenance.
  const lesson = await deps.store.ingest(req.content, {
    origin: "seeded", // seeded ⇒ probation tier (ratifiable, not durable common truth yet)
    scope: "global", // the shared library scope in the memory model
    ...(req.originId !== undefined ? { citation: `promoted-from:${req.originId}` } : {}),
  });

  return lesson !== undefined
    ? { status: "promoted", sharedId: lesson.id }
    : { status: "denied", reason: "shared ingest rejected by the memory gate" };
}

export type RetractionResult = { readonly retracted: boolean; readonly reason: string };

/**
 * Retract a shared entry — CONTAIN it. Retire it (tier→retired + a spine event; supersede-not-delete) so its
 * propagation through the team is stopped. Idempotent (H1's `retire`). This is the answer to memory contagion: a
 * poisoned or corrected common entry is contained, not silently deleted and not left to spread.
 */
export function retractFromShared(sharedId: string, deps: Pick<PromotionDeps, "store">, reason = "retracted"): RetractionResult {
  const retired = deps.store.retire(sharedId, `shared-retraction: ${reason}`);
  return retired
    ? { retracted: true, reason: `contained: ${sharedId} retired, propagation stopped` }
    : { retracted: false, reason: `no live shared entry ${sharedId}` };
}
