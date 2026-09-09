/**
 * ConsequenceForecast (Increment 16.9c-2) — premium, COMPOSITIONAL, multi-hop forward projection.
 *
 * The earlier forecast was a 1-hop, per-effect, direction-blind lookup. The dominant real risk is
 * COMPOSITIONAL: an unsafe state is often reachable only by combining effects that are each benign in
 * isolation. This models effects as nodes, adds known COMPOSITION EDGES to bad sinks, and does
 * REACHABILITY from the present effect set to any sink — escalating even when no single effect is high-risk
 * alone. It projects MULTI-HOP (bounded depth) and honors SANITIZERS/DOWNGRADERS (a mitigating effect that
 * breaks a source->sink path), which also gives directionality.
 *
 * SOTA basis (2026-08-05): security analysis reduces to graph REACHABILITY source->sink (taint patents
 * 9729569 / 8327339; CodeQL/loginsoft 2026). Most real vulns require CROSS-effect composition, "every step
 * benign in isolation" (ChainFuzzer 2603.12614: 302/365 multi-tool). A compositional taint layer needs
 * SANITIZERS (TaintRadar 2607.16456). Project to first/second/THIRD order (Futures Wheel, CHI 2026),
 * bounded for tractability. Uniform consequence-model PROTOCOL with bespoke instances (sandtech 2026).
 *
 * Deterministic + model-free at the floor (fits deterministic-primary + N=1). Zero deps.
 */

import type { EffectClass, IntendedEffect, BlastRadius } from "./plan_consequences.js";

/** A bad end-state reachable by composing effects. */
export type Sink =
  | "data-exfiltration"
  | "supply-chain-execution"
  | "undetected-unauthorized-access"
  | "persistent-privilege-escalation";

export interface ForecastedRisk {
  readonly from: EffectClass;
  readonly enables: string;
  readonly futureBlast: BlastRadius;
  readonly reversible: boolean;
  /** The order (hop distance) at which this risk appears: 1=first, 2=second, 3=third. */
  readonly order: number;
  readonly reason: string;
}

export interface ReachedSink {
  readonly sink: Sink;
  readonly via: readonly EffectClass[];
  readonly reason: string;
}

export interface ForecastVerdict {
  readonly decision: "pass" | "escalate";
  readonly risks: readonly ForecastedRisk[];
  readonly reachedSinks: readonly ReachedSink[];
  readonly maxOrder: number;
  readonly reason: string;
}

/** The uniform port: any bespoke forecast instance (plan-time, patch-time, pre-merge) implements this. */
export interface ForecastModel {
  readonly stage: string;
  project(effects: readonly IntendedEffect[], context?: ForecastContext): ForecastVerdict;
}

/** Stage-specific signals a bespoke instance can use (all optional; the plan-time floor uses none). */
export interface ForecastContext {
  /** Effect classes whose risk is DOWNGRADED by a mitigating change in the same patch (sanitizers). */
  readonly downgraded?: readonly EffectClass[];
  /** Effect classes NET-ADDED as new sinks (directionality from safety-monotonicity at patch-time). */
  readonly netAdded?: readonly EffectClass[];
  readonly maxDepth?: number;
}

const BLAST_RANK: Record<BlastRadius, number> = { critical: 3, high: 2, medium: 1, low: 0 };

interface Projection { enables: string; futureBlast: BlastRadius; reversible: boolean; }
const FORWARD: Partial<Record<EffectClass, Projection>> = {
  "auth-access-control": { enables: "future requests bypass the access check", futureBlast: "high", reversible: false },
  "network-egress": { enables: "future data can leave the trust boundary", futureBlast: "high", reversible: false },
  "secret-credential": { enables: "future credential exposure/reuse", futureBlast: "high", reversible: false },
  "dependency-config": { enables: "new dependency code runs on every build", futureBlast: "medium", reversible: true },
  "db-schema": { enables: "downstream readers/writers hit the changed schema", futureBlast: "high", reversible: false },
  "audit-tamper": { enables: "later actions can be hidden from the audit trail", futureBlast: "high", reversible: false },
};

interface Composition { requires: readonly EffectClass[]; sink: Sink; reason: string; }
const COMPOSITIONS: readonly Composition[] = [
  { requires: ["auth-access-control", "network-egress"], sink: "data-exfiltration", reason: "access to internal data + an egress path -> authenticated data can leave" },
  { requires: ["secret-credential", "network-egress"], sink: "data-exfiltration", reason: "a secret + an egress path -> the secret can be transmitted out" },
  { requires: ["dependency-config", "network-egress"], sink: "supply-chain-execution", reason: "a new dependency + egress -> it can phone home / exfiltrate on every build" },
  { requires: ["auth-access-control", "audit-tamper"], sink: "undetected-unauthorized-access", reason: "access can change AND the change be hidden -> undetected persistent access" },
  { requires: ["secret-credential", "audit-tamper"], sink: "undetected-unauthorized-access", reason: "a secret is touched AND the trail can be hidden -> undetected credential use" },
];

/** The default deterministic, compositional forecast model (the floor). */
export class CompositionalForecast implements ForecastModel {
  readonly stage: string;
  constructor(stage = "plan-time") { this.stage = stage; }

  project(effects: readonly IntendedEffect[], context: ForecastContext = {}): ForecastVerdict {
    const maxDepth = Math.min(context.maxDepth ?? 3, 3);
    const present = new Set<EffectClass>(effects.map((e) => e.cls));
    const downgraded = new Set<EffectClass>(context.downgraded ?? []);

    const risks: ForecastedRisk[] = [];
    for (const eff of effects) {
      const proj = FORWARD[eff.cls];
      if (!proj) continue;
      if (downgraded.has(eff.cls)) continue; // directionality: a mitigated effect is not a forward risk
      risks.push({ from: eff.cls, enables: proj.enables, futureBlast: proj.futureBlast, reversible: proj.reversible, order: 1, reason: `${eff.cls} -> ${proj.enables}` });
    }

    const reachedSinks: ReachedSink[] = [];
    for (const comp of COMPOSITIONS) {
      const allPresent = comp.requires.every((c) => present.has(c));
      const anyDowngraded = comp.requires.some((c) => downgraded.has(c));
      if (allPresent && !anyDowngraded) {
        reachedSinks.push({ sink: comp.sink, via: comp.requires, reason: comp.reason });
        risks.push({ from: comp.requires[0]!, enables: `composed sink: ${comp.sink}`, futureBlast: "high", reversible: false, order: 2, reason: comp.reason });
      }
    }

    if (maxDepth >= 3 && reachedSinks.some((r) => r.sink === "undetected-unauthorized-access")) {
      reachedSinks.push({ sink: "persistent-privilege-escalation", via: ["auth-access-control", "audit-tamper"], reason: "undetected access compounds into persistent privilege escalation (third-order)" });
      risks.push({ from: "auth-access-control", enables: "persistent-privilege-escalation", futureBlast: "critical", reversible: false, order: 3, reason: "third-order: undetected access -> persistent escalation" });
    }

    const seriousFirstOrder = risks.filter((r) => r.order === 1 && BLAST_RANK[r.futureBlast] >= BLAST_RANK["high"] && !r.reversible);
    const escalate = reachedSinks.length > 0 || seriousFirstOrder.length > 0;
    const maxOrder = risks.reduce((m, r) => Math.max(m, r.order), 0);

    if (escalate) {
      const parts: string[] = [];
      if (reachedSinks.length > 0) parts.push(`reachable sink(s): ${reachedSinks.map((r) => r.sink).join(", ")}`);
      if (seriousFirstOrder.length > 0) parts.push(`high-risk irreversible effect(s): ${seriousFirstOrder.map((r) => r.enables).join("; ")}`);
      return { decision: "escalate", risks, reachedSinks, maxOrder, reason: parts.join(" | ") };
    }
    return { decision: "pass", risks, reachedSinks, maxOrder, reason: risks.length > 0 ? "forward effects are bounded/reversible; no sink reachable" : "no forward risk projected" };
  }
}

const DEFAULT = new CompositionalForecast("plan-time");
export function forecastConsequences(effects: readonly IntendedEffect[], context?: ForecastContext): ForecastVerdict {
  return DEFAULT.project(effects, context);
}
