/**
 * CONNECTOR-SAFETY FRAMEWORK — Round 6 of the personalization moat. Wire Keep to many external services safely by
 * treating EVERY connector as hostile until proven, composing Keep's existing safety primitives.
 *
 * The core agentic-connector risk is the "lethal trifecta": untrusted input + sensitive-data access + the ability
 * to act. The 2026 MCP threat model adds confused-deputy, tool-poisoning, tool-shadowing, credential-aggregation,
 * and over-broad scopes. The single highest-ROI control is "not connecting the wrong server in the first place"
 * (an approved, signed allowlist); after that, least-privilege scoped credentials (no god-token), tainting every
 * connector's output, breaking the trifecta structurally (force a gate between an untrusted read and a
 * consequential act), and an immutable audit trail.
 *
 * This framework provides those controls by REUSE, not reinvention:
 *   - `registerConnector` — allowlist + signature gate (reuses the signing primitive); refuses an unlisted or
 *     unsigned connector; clamps requested scopes to the least-privilege granted set (intersection — never more
 *     than granted).
 *   - connector output is TAINTED (taint-tracer): every value a connector returns is `untrusted`.
 *   - `mayAct` — BREAKS THE TRIFECTA: a consequential action driven by any tainted input is GATED (never
 *     auto-done); an untainted low-consequence action proceeds.
 *   - `mayFlowToConnector` — a connector is a CI RECIPIENT: sensitive context flows to it only if the vault's
 *     `mayFlow` permits.
 *
 * BUILT + proven in-env: the allowlist/signature gate, the least-privilege clamp, the trifecta-breaking `mayAct`,
 * and the CI-recipient gate. SEAM: the crypto (`stubSign` stands in for an HSM signature) and the individual
 * service adapters (Slack/Telegram/Notion/Linear/OpenRouter — the actual API clients).
 */

import { tainted, type Labeled } from "../provenance/taint_tracer.js";
import { stubSign, type Signature } from "../bom/bom_signing.js";
import type { SensitiveContextVault, VaultEntry } from "../privacy/contextual_integrity.js";
import type { Purpose } from "../ingest/data_governance.js";

export type ConnectorScope = string; // e.g. "slack:read:channel-eng", "notion:read:db-x"

export interface ConnectorDescriptor {
  readonly id: string;
  readonly requestedScopes: readonly ConnectorScope[];
  readonly signature: Signature; // { keyid, sig } — reuses the signing primitive
}

export interface ConnectorPolicy {
  /** the approved-connector allowlist — the highest-ROI control. */
  readonly approvedIds: ReadonlySet<string>;
  /** keyid → key, for signature verification (the crypto is the SEAM). */
  readonly trustedKeys: ReadonlyMap<string, string>;
  /** id → the scopes actually granted (least-privilege); a connector can never exceed these. */
  readonly grantedScopes: ReadonlyMap<string, readonly ConnectorScope[]>;
}

export interface RegisteredConnector {
  readonly id: string;
  /** the scopes the connector may use — CLAMPED to the intersection of requested and granted (least-privilege). */
  readonly grantedScopes: readonly ConnectorScope[];
}

export type Registration =
  | { readonly ok: true; readonly connector: RegisteredConnector }
  | { readonly ok: false; readonly reason: string };

/** The content a connector's signature covers (id + sorted scopes). */
function connectorContent(desc: ConnectorDescriptor): string {
  return `${desc.id}|${[...desc.requestedScopes].sort().join(",")}`;
}

/** Verify a connector's signature: the keyid must be trusted AND the signature valid over the content. Reuses the
 *  signing stub (the crypto is the SEAM; the trusted-key gate is BUILT). Fail-safe: any shortfall ⇒ false. */
function verifyConnectorSignature(desc: ConnectorDescriptor, trustedKeys: ReadonlyMap<string, string>): boolean {
  const key = trustedKeys.get(desc.signature.keyid);
  if (key === undefined) return false; // untrusted keyid ⇒ reject
  return stubSign(key, desc.signature.keyid, connectorContent(desc)).sig === desc.signature.sig;
}

/**
 * Register a connector. Refuses it unless it is BOTH on the approved allowlist AND validly signed by a trusted
 * key. Clamps its scopes to least-privilege (the intersection of requested and granted) — an over-broad request is
 * reduced, never honored beyond what was granted.
 */
export function registerConnector(desc: ConnectorDescriptor, policy: ConnectorPolicy): Registration {
  if (!policy.approvedIds.has(desc.id)) {
    return { ok: false, reason: "connector not on the approved allowlist" }; // unlisted ⇒ refused
  }
  if (!verifyConnectorSignature(desc, policy.trustedKeys)) {
    return { ok: false, reason: "connector signature did not verify" }; // unsigned/forged ⇒ refused
  }
  const granted = policy.grantedScopes.get(desc.id) ?? [];
  const clamped = desc.requestedScopes.filter((s) => granted.includes(s)); // least-privilege: never exceed granted
  return { ok: true, connector: { id: desc.id, grantedScopes: clamped } };
}

/** Label a connector's output as UNTRUSTED (tainted) — every value a connector returns is untrusted input. */
export function connectorOutput<T>(connectorId: string, value: T): Labeled<T> {
  return tainted(value, `connector:${connectorId}`);
}

export type Consequence = "reversible" | "consequential";
export type ActDecision = "allow" | "gate";

/**
 * BREAK THE LETHAL TRIFECTA. An action driven by any tainted (untrusted connector) input, if it is CONSEQUENTIAL,
 * is GATED — routed to the consequence-gate for a human decision, never auto-done. An untainted action, or a
 * reversible one, proceeds. This structurally severs "untrusted read → consequential act": an injected instruction
 * in a connector's output can never itself drive a consequential action.
 */
export function mayAct(consequence: Consequence, inputs: readonly Labeled<unknown>[]): ActDecision {
  const untrusted = inputs.some((l) => l.taint === "untrusted");
  if (consequence === "consequential" && untrusted) {
    return "gate"; // trifecta broken: a consequential act on untrusted input requires the human
  }
  return "allow";
}

/**
 * A connector is a CI RECIPIENT: sensitive context flows to it only if the vault's egress gate permits it for this
 * purpose. Reuses `mayFlow` — a connector recipient not on the datum's permitted list is denied by default.
 */
export function mayFlowToConnector(vault: SensitiveContextVault, entry: VaultEntry, connectorId: string, purpose: Purpose): boolean {
  return vault.mayFlow(entry, { recipient: connectorId, purpose });
}
