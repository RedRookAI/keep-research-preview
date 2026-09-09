/**
 * HostileMcpGateway (Increment W1) — the gateway EVERY external MCP server sits behind. MCP has "no strict
 * boundary between data and instructions" (truefoundry) and is "being wired into mission-critical systems faster
 * than anyone is securing it — treat every MCP server as hostile until proven otherwise" (Practical DevSecOps).
 * This is Keep's hostile-intake gauntlet, layered per the 2026 SOTA.
 *
 * The attacks it defends (OWASP Agentic 2026 ASI01 Agent Goal Hijack; Invariant Labs; Elastic; CSA):
 *  - TOOL POISONING — malicious instructions hidden in tool metadata/descriptions/results. Defense: external
 *    tool output is returned as UNTRUSTED, provenance-tagged DATA — never instructions. (Architecture is the
 *    primary control; "model-layer defenses reduce but don't eliminate prompt injection" — agentmelt.)
 *  - RUG PULL — a tool ships benign, is approved, then silently mutates its definition. Defense: HASH the
 *    definition at approval; re-check at reconcile AND at call time; any change → QUARANTINE + re-approval.
 *    ("Pin tool versions. Hash the description on first approval. Re-prompt if it changes. This kills rug pulls.")
 *  - OVER-PRIVILEGE / unauthorized action — deny-by-default allowlist; DESTRUCTIVE tools are HUMAN-GATED
 *    ("the friction is the feature"); a reference-monitor egress check blocks exfiltration invariants.
 *  - AUDIT BLIND SPOTS — every approve / reconcile / rug-pull / refuse / gate / invoke is audited to the spine.
 *
 * The live server connection (transport + scoped OAuth 2.1 credential) is supplied at deployment (VERIFIED-SEAM);
 * the gauntlet itself is BUILT + proven here. Zero deps (node:crypto). What would change it: MCP adds enforced
 * signed tool descriptions → treat a valid signature as an additional pin input; the gateway stays.
 */

import { createHash } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { ReferenceMonitor } from "../control/reference_monitor.js";
import type { GovernanceLedger } from "../governance/decision_record.js";

export type ToolDisposition = "read-only" | "destructive";

export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema?: unknown;
}

export interface ApprovedTool {
  readonly server: string;
  readonly tool: string;
  readonly definitionHash: string; // pinned at approval — the rug-pull anchor
  readonly disposition: ToolDisposition;
  readonly approvedBy: string;
  readonly at: number;
}

export interface GatewayResult {
  readonly status: "ok" | "refused" | "gated" | "rug-pull" | "quarantined";
  readonly reason?: string;
  /** External output is ALWAYS untrusted, provenance-tagged data — downstream must never treat it as instructions. */
  readonly output?: { readonly trust: "untrusted"; readonly server: string; readonly value: unknown };
}

/** Deny-by-default disposition inference: any mutating/sending verb → destructive (human-gated). The human may
 *  explicitly downgrade a specific tool to read-only at approval; the SAFE DEFAULT is destructive. */
const DESTRUCTIVE_VERB = /\b(write|delete|remove|drop|send|deploy|merge|push|create|update|edit|execute|run|revoke|transfer|pay|purchase|email|post|patch|put)\b/i;
export function inferDisposition(def: ToolDefinition): ToolDisposition {
  // Normalize separators (tool names are underscore/hyphen-joined, e.g. "delete_repo") so verbs are found.
  const hay = `${def.name} ${def.description}`.replace(/[_\-.]/g, " ");
  return DESTRUCTIVE_VERB.test(hay) ? "destructive" : "read-only";
}

function hashDefinition(def: ToolDefinition): string {
  return createHash("sha256").update(`${def.name}\u0000${def.description}\u0000${JSON.stringify(def.inputSchema ?? null)}`, "utf8").digest("hex").slice(0, 32);
}

export interface HostileMcpGatewayConfig {
  readonly spine: Spine;
  readonly referenceMonitor?: ReferenceMonitor;
  readonly governance?: GovernanceLedger;
}

export class HostileMcpGateway {
  private readonly approved = new Map<string, ApprovedTool>(); // key: `${server}\u0000${tool}`
  private readonly quarantined = new Set<string>();
  constructor(private readonly cfg: HostileMcpGatewayConfig) {}

  private key(server: string, tool: string): string {
    return `${server}\u0000${tool}`;
  }

  /** HUMAN approval of a specific tool at its CURRENT definition — pins the hash + disposition (deny-by-default
   *  inference unless the human explicitly classifies). Re-approval clears any quarantine. */
  approve(server: string, def: ToolDefinition, actor: string, disposition?: ToolDisposition, now = Date.now()): ApprovedTool {
    const rec: ApprovedTool = { server, tool: def.name, definitionHash: hashDefinition(def), disposition: disposition ?? inferDisposition(def), approvedBy: actor, at: now };
    this.approved.set(this.key(server, def.name), rec);
    this.quarantined.delete(this.key(server, def.name));
    this.audit("mcp.tool-approved", `${server}/${def.name} pinned as ${rec.disposition}`, "proceeded", actor);
    return rec;
  }

  /** Reconcile a server's CURRENT tool list against pinned definitions (rug-pull defense). A changed definition
   *  → QUARANTINE (refused until re-approved). Unapproved tools stay unavailable (deny-by-default). */
  reconcile(server: string, currentDefs: readonly ToolDefinition[]): { rugPulls: string[]; unapproved: string[] } {
    const rugPulls: string[] = [];
    const unapproved: string[] = [];
    const byName = new Map(currentDefs.map((d) => [d.name, d] as const));
    for (const [k, rec] of this.approved) {
      if (rec.server !== server) continue;
      const cur = byName.get(rec.tool);
      if (cur && hashDefinition(cur) !== rec.definitionHash) {
        this.quarantined.add(k);
        rugPulls.push(rec.tool);
        this.audit("mcp.rug-pull-detected", `${server}/${rec.tool} definition changed after approval — QUARANTINED`, "blocked");
      }
    }
    for (const d of currentDefs) if (!this.approved.has(this.key(server, d.name))) unapproved.push(d.name);
    return { rugPulls, unapproved };
  }

  /** Invoke a tool THROUGH the gateway. Deny-by-default → pin re-check (call-time rug pull) → reference-monitor
   *  egress guard → destructive tools human-gated → execute → result returned as UNTRUSTED data. `currentDef` is
   *  the server's currently-advertised definition (so a definition swapped since approval is caught here too). */
  async invoke(
    server: string,
    currentDef: ToolDefinition,
    args: Record<string, unknown>,
    exec: () => Promise<unknown>,
    opts: { humanApproved?: boolean } = {},
  ): Promise<GatewayResult> {
    const k = this.key(server, currentDef.name);
    const rec = this.approved.get(k);
    if (!rec) {
      this.audit("mcp.refused", `${server}/${currentDef.name} not approved (deny-by-default)`, "blocked");
      return { status: "refused", reason: "tool not approved (deny-by-default)" };
    }
    if (this.quarantined.has(k)) {
      this.audit("mcp.refused", `${server}/${currentDef.name} is quarantined`, "blocked");
      return { status: "quarantined", reason: "tool quarantined after a definition change; re-approval required" };
    }
    if (hashDefinition(currentDef) !== rec.definitionHash) {
      this.quarantined.add(k);
      this.audit("mcp.rug-pull-detected", `${server}/${currentDef.name} definition changed at call time — QUARANTINED`, "blocked");
      return { status: "rug-pull", reason: "tool definition changed since approval; re-approval required" };
    }
    if (this.cfg.referenceMonitor) {
      const violated = this.cfg.referenceMonitor.wouldViolate({ type: "mcp.tool-call", actor: "mcp-gateway", payload: { event: "mcp.tool-call", server, tool: currentDef.name, args } }).filter((v) => v.violated);
      if (violated.length > 0) {
        this.audit("mcp.refused", `${server}/${currentDef.name} blocked by safety invariant(s): ${violated.map((v) => v.clauseId).join(",")}`, "blocked");
        return { status: "refused", reason: "blocked by a safety invariant" };
      }
    }
    if (rec.disposition === "destructive" && !opts.humanApproved) {
      this.audit("mcp.gated", `${server}/${currentDef.name} is destructive — requires explicit human approval (NOT executed)`, "escalated-to-human");
      return { status: "gated", reason: "destructive tool requires explicit human approval before execution" };
    }
    let value: unknown;
    try {
      value = await exec();
    } catch (e) {
      this.audit("mcp.error", `${server}/${currentDef.name} execution error: ${(e as Error).message}`, "blocked");
      return { status: "refused", reason: "tool execution error" };
    }
    this.audit("mcp.invoked", `${server}/${currentDef.name} (${rec.disposition})`, "proceeded");
    return { status: "ok", output: { trust: "untrusted", server, value } };
  }

  /** Diagnostics: is a (server, tool) currently invocable (approved + not quarantined)? */
  isInvocable(server: string, tool: string): boolean {
    const k = this.key(server, tool);
    return this.approved.has(k) && !this.quarantined.has(k);
  }

  approvedTools(): readonly ApprovedTool[] {
    return [...this.approved.values()];
  }

  private audit(action: string, reason: string, outcome: "proceeded" | "blocked" | "escalated-to-human", actor = "mcp-gateway"): void {
    this.cfg.spine.stage({ type: "identity.action", actor, payload: { event: action, reason, ts: Date.now() } });
    this.cfg.governance?.record({
      action,
      actor,
      policy: { effect: outcome === "proceeded" ? "allow" : outcome === "blocked" ? "deny" : "warn", ruleId: "hostile-mcp-gateway", reason, matchedRuleIds: ["hostile-mcp-gateway"], policyVersion: "1" },
      outcome,
    });
  }
}
