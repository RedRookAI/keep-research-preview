/**
 * Resolution curve (Increment R5) — the honest economics of the resolution moat, computed from the R1–R4 audit
 * trail already on the spine (resolve.best_of_n / resolve.cascade.*). No parallel bookkeeping; it reads the real
 * events.
 *
 * The cardinal honesty rule (ecorpit 2026; FinOps 2026; oplexa): a task that "stayed in the system" but was
 * deferred to a human is CONTAINMENT, not RESOLUTION — the easiest metric to inflate, and a deferred cost rather
 * than a saving. So a genuine RESOLUTION here is winner-verified AND not deferred; everything else (deferred to
 * human, budget-stopped, least-bad) is counted separately and NEVER as success. The headline economic metric is
 * cost per VERIFIED resolution (grounded from real tier spend, and it includes the spend on attempts that deferred
 * — because those still cost money). Reporting resolve-rate without cost rewards systems that just spend more
 * (Microsoft token economics; Claw-SWE-Bench Pareto), so R5 always pairs rate with cost.
 *
 * SOTA basis (2026-08-06): resolution ≠ containment (ecorpit); cost-per-resolved-task over token spend (oplexa,
 * FinOps); pass@k-union (capability) vs intersection (reliability) = the reliability gap (Simmering; τ-bench) —
 * surfaced by the existing computeResolveAtK, referenced not duplicated here; contamination/leak control is
 * required before a resolution NUMBER is trustworthy (Claw-SWE-Bench leak-fix) — hence the VERIFIED-SEAM caveat.
 * Zero deps. What would change it: real contamination-controlled SWE-bench runs on live infra produce the number;
 * this computes the mechanism economics on whatever runs it is given.
 */

import type { StagedEvent } from "../spine/event.js";

export interface ResolutionEconomics {
  /** One resolution = one cascade run (resolve.cascade.done), or a bare best-of-N run when no cascade was used. */
  readonly resolutions: number;
  /** Genuine resolutions: winner cleared verification AND not deferred to a human. */
  readonly verified: number;
  readonly verifiedRate: number;
  /** Deferred to a human (least-bad / not verified / budget-stopped) — a deferred COST, not a resolution. */
  readonly deferredToHuman: number;
  readonly deferredRate: number;
  readonly budgetStopped: number;
  /** Fraction of resolutions that escalated at least one tier. High → the cheap tier is too weak (a cost signal). */
  readonly escalationRate: number;
  readonly meanEscalations: number;
  /** Fraction of resolutions where verified candidates behaviorally diverged (R3). */
  readonly behavioralForkRate: number;
  /** tier name → fraction of resolutions where it was the TERMINAL (last) tier used. */
  readonly terminalTierRate: Readonly<Record<string, number>>;
  /** Total grounded spend across all tier attempts (USD). */
  readonly groundedSpendUsd: number;
  /** Headline: total grounded spend ÷ verified resolutions. null when there are no verified resolutions. */
  readonly costPerVerifiedUsd: number | null;
  readonly costPerResolutionUsd: number | null;
}

const r2 = (x: number): number => Math.round(x * 100) / 100;
const r4 = (x: number): number => Math.round(x * 10000) / 10000;

/** Aggregate the resolve.* audit events into honest economics. Pure. */
export function computeResolutionEconomics(events: readonly StagedEvent[]): ResolutionEconomics {
  const done: Record<string, unknown>[] = [];
  const bestOfN: Record<string, unknown>[] = [];
  const spendByIssue = new Map<string, number>();

  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    const ev = p["event"];
    if (ev === "resolve.cascade.done") done.push(p);
    else if (ev === "resolve.best_of_n") bestOfN.push(p);
    else if (ev === "resolve.cascade.tier") {
      const id = String(p["issueId"]);
      spendByIssue.set(id, (spendByIssue.get(id) ?? 0) + Number(p["estCostUsd"] ?? 0));
    }
  }

  // Resolution unit: cascade.done if any cascades ran, else bare best-of-N runs.
  const usingCascade = done.length > 0;
  const units = usingCascade ? done : bestOfN;
  const n = units.length;

  let verified = 0, deferred = 0, budgetStopped = 0, escalated = 0, escalationsTotal = 0, forks = 0;
  const terminalCounts = new Map<string, number>();

  for (const u of units) {
    if (usingCascade) {
      const cleared = u["winnerCleared"] === true;
      const toHuman = u["escalateToHuman"] === true;
      if (cleared && !toHuman) verified++; else deferred++;
      if (u["stoppedReason"] === "budget") budgetStopped++;
      const esc = Number(u["escalations"] ?? 0);
      escalationsTotal += esc;
      if (esc > 0) escalated++;
      if (u["behavioralFork"] === true) forks++;
      const tiersUsed = Array.isArray(u["tiersUsed"]) ? (u["tiersUsed"] as string[]) : [];
      const terminal = tiersUsed[tiersUsed.length - 1];
      if (terminal) terminalCounts.set(terminal, (terminalCounts.get(terminal) ?? 0) + 1);
    } else {
      // bare best-of-N: verified = winner cleared; no human-deferral concept, so "not cleared" = deferred.
      if (u["winnerCleared"] === true) verified++; else deferred++;
    }
  }

  const groundedSpendUsd = [...spendByIssue.values()].reduce((s, x) => s + x, 0);
  const terminalTierRate: Record<string, number> = {};
  for (const [t, c] of terminalCounts) terminalTierRate[t] = r4(c / (n || 1));

  return {
    resolutions: n,
    verified,
    verifiedRate: n ? r4(verified / n) : 0,
    deferredToHuman: deferred,
    deferredRate: n ? r4(deferred / n) : 0,
    budgetStopped,
    escalationRate: n ? r4(escalated / n) : 0,
    meanEscalations: n ? r4(escalationsTotal / n) : 0,
    behavioralForkRate: n ? r4(forks / n) : 0,
    terminalTierRate,
    groundedSpendUsd: r2(groundedSpendUsd),
    costPerVerifiedUsd: verified > 0 ? r2(groundedSpendUsd / verified) : null,
    costPerResolutionUsd: n > 0 ? r2(groundedSpendUsd / n) : null,
  };
}

/** Render the economics honestly, with the containment≠resolution distinction and the seam caveat spelled out. */
export function renderResolutionCurve(econ: ResolutionEconomics): string {
  const L: string[] = [];
  L.push("Resolution economics (from the recorded run trail)");
  L.push("");
  if (econ.resolutions === 0) {
    L.push("No resolution runs recorded yet. Run some tickets through the cascade, then check back.");
    return L.join("\n");
  }
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
  L.push(`Resolutions attempted:     ${econ.resolutions}`);
  L.push(`VERIFIED (solved):         ${econ.verified}  (${pct(econ.verifiedRate)})`);
  L.push(`Deferred to a human:       ${econ.deferredToHuman}  (${pct(econ.deferredRate)})  — NOT counted as solved`);
  if (econ.budgetStopped > 0) L.push(`  …of which budget-stopped: ${econ.budgetStopped}`);
  L.push("");
  L.push(`Escalated ≥1 tier:         ${pct(econ.escalationRate)}  (mean ${econ.meanEscalations} per resolution)`);
  if (econ.escalationRate > 0.3) L.push(`  ⚠ escalation rate > 30% — the cheap tier may be too weak for this workload.`);
  L.push(`Behavioral forks:          ${pct(econ.behavioralForkRate)}`);
  const tiers = Object.entries(econ.terminalTierRate);
  if (tiers.length > 0) L.push(`Resolved at tier:          ${tiers.map(([t, r]) => `${t} ${pct(r)}`).join(", ")}`);
  L.push("");
  L.push(`Grounded spend:            $${econ.groundedSpendUsd.toFixed(2)}`);
  L.push(`Cost / verified resolution: ${econ.costPerVerifiedUsd === null ? "n/a (no verified resolutions)" : "$" + econ.costPerVerifiedUsd.toFixed(2)}`);
  L.push(`Cost / attempt:            ${econ.costPerResolutionUsd === null ? "n/a" : "$" + econ.costPerResolutionUsd.toFixed(2)}`);
  L.push("");
  L.push("Notes: 'deferred to a human' is a deferred cost, not a saving — it is never counted as solved.");
  L.push("Cost per verified resolution includes spend on attempts that ultimately deferred (they still cost money).");
  L.push("This is the mechanism's economics on the runs recorded here. A trustworthy resolution RATE on a public");
  L.push("benchmark requires contamination-controlled runs on real infrastructure (not available in this context).");
  return L.join("\n");
}
