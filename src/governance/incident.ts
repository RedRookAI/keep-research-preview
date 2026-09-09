/**
 * Clock-aware incident-reporting hooks (Phase 5, #38).
 *
 * On a triggering event (safety-critical failure, prohibited output, containment
 * activation, serious malfunction), emit a structured incident artifact carrying the
 * MULTI-CLOCK reporting deadlines, computed from detection time:
 *   - 24h  (NIS2, significant cyber incidents)
 *   - 72h  (GDPR, personal-data breaches)
 *   - 15 days (EU AI Act, serious incidents)
 * Targets the Omnibus-consolidated single-entry-point reporting model. Bound to the
 * spine for the audit trail.
 */

import type { Spine } from "../spine/spine.js";

export type IncidentType =
  | "serious-malfunction" // AI Act serious incident
  | "prohibited-output" // Article 5 violation attempt
  | "personal-data-breach" // GDPR
  | "cyber-incident" // NIS2
  | "containment-activated"; // kill-switch/circuit-breaker fired

export type Clock = "nis2-24h" | "gdpr-72h" | "aiact-15d" | "aiact-10d-death" | "aiact-2d-critical";

const CLOCK_HOURS: Record<Clock, number> = {
  "nis2-24h": 24,
  "gdpr-72h": 72,
  "aiact-15d": 15 * 24,
  "aiact-10d-death": 10 * 24, // AI Act Art. 73(4): death may be involved → immediately, at most 10 days
  "aiact-2d-critical": 2 * 24, // AI Act Art. 73(3): widespread infringement OR serious/irreversible critical-infrastructure disruption → 2 days
};

/** Severity signals that tighten the AI Act clock (Art. 73(3)/(4)). Absent → the default 15-day clock applies. */
export interface IncidentSeverity {
  /** A person's death may have been caused (Art. 73(4) → 10 days). */
  readonly deathPossible?: boolean;
  /** A widespread infringement, or a serious/irreversible disruption of critical infrastructure (Art. 73(3) → 2 days). */
  readonly widespreadOrCriticalInfra?: boolean;
  /**
   * SOTA 2026-08-19: for a CYBER-INCIDENT (attack on system confidentiality/integrity), the EU AI Act Art.73
   * clock is NOT automatic — Art.73 requires a HARM OUTCOME (death / critical-infra / rights infringement), and
   * the Sept-2025 draft guidance excludes bare system-integrity compromise. Set this only when the cyber-incident
   * plausibly ALSO meets an Art.73 serious-incident outcome (e.g. a fundamental-rights obligation infringement).
   */
  readonly aiActSeriousIncident?: boolean;
  /** For a cyber-incident: personal data is implicated → the GDPR 72h clock applies. Absent → no GDPR clock (a bare
   *  integrity tamper of non-personal data is not a personal-data breach; auto-adding GDPR would be over-reporting). */
  readonly personalDataImplicated?: boolean;
}

/** Does this severity meet an EU AI Act Art.73 serious-incident harm outcome? (death, critical-infra/widespread, or
 *  an explicitly-assessed rights-infringement for a cyber-incident.) */
function meetsAiActOutcome(sev: IncidentSeverity | undefined): boolean {
  return !!(sev?.deathPossible || sev?.widespreadOrCriticalInfra || sev?.aiActSeriousIncident);
}

/** The AI Act clock for a serious incident, tightened by severity (2d critical/widespread > 10d death > 15d default). */
function aiActClock(sev: IncidentSeverity | undefined): Clock {
  if (sev?.widespreadOrCriticalInfra) return "aiact-2d-critical";
  if (sev?.deathPossible) return "aiact-10d-death";
  return "aiact-15d";
}

/** Which reporting clocks apply to each incident type (severity refines the AI Act clock). */
function clocksFor(type: IncidentType, sev?: IncidentSeverity): Clock[] {
  const aiact = aiActClock(sev);
  switch (type) {
    case "serious-malfunction":
      return [aiact];
    case "prohibited-output":
      return [aiact];
    case "personal-data-breach":
      return ["gdpr-72h", aiact];
    case "cyber-incident":
      // SOTA 2026-08-19 correction: a cyber/integrity incident always starts the NIS2 24h clock, but the AI Act
      // Art.73 clock is CONDITIONAL on a harm outcome and GDPR is CONDITIONAL on personal data being implicated —
      // auto-starting either for a bare integrity tamper over-reports. (verdict recorded in KEEP_SOTA_AUDIT.)
      return [
        "nis2-24h",
        ...(sev?.personalDataImplicated ? (["gdpr-72h"] as Clock[]) : []),
        ...(meetsAiActOutcome(sev) ? [aiact] : []),
      ];
    case "containment-activated":
      return [aiact];
  }
}

export interface IncidentDeadline {
  readonly clock: Clock;
  readonly dueTs: number;
  readonly hours: number;
}

export interface IncidentArtifact {
  readonly incidentId: string;
  readonly type: IncidentType;
  readonly summary: string;
  readonly detectedTs: number;
  readonly deadlines: readonly IncidentDeadline[];
  /** The spine event this incident is bound to. */
  readonly spineEventId: string;
  /** Single-entry-point target (Omnibus consolidation). */
  readonly reportingTarget: string;
}

export class IncidentReporter {
  constructor(
    private readonly spine: Spine,
    private readonly clock: () => number = () => Date.now(),
    private readonly reportingTarget = "eu-single-entry-point (anticipated; Digital Omnibus not yet concluded)",
  ) {}

  /** Capture an incident and compute its multi-clock deadlines (severity tightens the AI Act clock). */
  capture(type: IncidentType, summary: string, opts: { detectedTs?: number; severity?: IncidentSeverity } = {}): IncidentArtifact {
    const detected = opts.detectedTs ?? this.clock();
    const deadlines: IncidentDeadline[] = clocksFor(type, opts.severity).map((c) => ({
      clock: c,
      hours: CLOCK_HOURS[c],
      dueTs: detected + CLOCK_HOURS[c] * 3600 * 1000,
    }));
    const spineEventId = this.spine.stage({
      type: "identity.action",
      actor: "incident",
      payload: {
        event: "incident.captured",
        incidentType: type,
        summary,
        detectedTs: detected,
        deadlines: deadlines.map((d) => ({ clock: d.clock, dueTs: d.dueTs })),
        reportingTarget: this.reportingTarget,
        ...(opts.severity ? { severity: opts.severity } : {}),
      },
    });
    return {
      incidentId: spineEventId,
      type,
      summary,
      detectedTs: detected,
      deadlines,
      spineEventId,
      reportingTarget: this.reportingTarget,
    };
  }

  /** The most urgent (soonest) deadline for an incident, for triage. */
  soonestDeadline(incident: IncidentArtifact): IncidentDeadline | undefined {
    return [...incident.deadlines].sort((a, b) => a.dueTs - b.dueTs)[0];
  }
}
