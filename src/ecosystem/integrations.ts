/**
 * Tracker triggers (#46) + CI/CD-native (#48) + project templates (#49).
 *
 * All three "apply patterns already built" to the outside world:
 *  - #46: a NORMALIZED inbound-event model so any tracker (Linear/Jira/GitHub
 *    Issues/...) maps to the same Keep trigger via the connector port — Keep is
 *    tracker-agnostic; adding a tracker is an adapter, not new core.
 *  - #48: Keep runs as a CI/CD pipeline STEP, producing a typed result; the human
 *    merge gate is unchanged (Keep proposes; the human merges).
 *  - #49: reusable project templates with DRIFT PROTECTION — versioned + checksummed,
 *    instantiation records provenance, so a bad shared default is traceable and
 *    updatable, not silently propagated.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "../spine/event.js";

// --- #46 Tracker-agnostic triggers ---

export type TrackerSource = "linear" | "jira" | "github-issues" | "gitlab" | "generic";

export interface NormalizedTrigger {
  readonly source: TrackerSource;
  /** Stable Keep-side trigger type regardless of tracker. */
  readonly kind: "ticket.created" | "ticket.updated" | "ticket.reopened" | "ticket.labeled" | "comment.added";
  readonly ticketId: string;
  readonly title: string;
  readonly body: string;
  readonly labels: readonly string[];
}

/** A tracker adapter normalizes its native payload into a NormalizedTrigger. */
export interface TrackerAdapter {
  readonly source: TrackerSource;
  normalize(nativePayload: Readonly<Record<string, unknown>>): NormalizedTrigger | undefined;
}

/** Route a native tracker payload through the right adapter to a normalized trigger. */
export class TriggerRouter {
  private readonly adapters = new Map<TrackerSource, TrackerAdapter>();

  register(adapter: TrackerAdapter): void {
    this.adapters.set(adapter.source, adapter);
  }

  route(source: TrackerSource, nativePayload: Readonly<Record<string, unknown>>): NormalizedTrigger | undefined {
    return this.adapters.get(source)?.normalize(nativePayload);
  }

  supportedSources(): TrackerSource[] {
    return [...this.adapters.keys()];
  }
}

// --- #48 CI/CD-native ---

export type StepOutcome = "pass" | "fail" | "needs-review";

export interface CiStepResult {
  readonly outcome: StepOutcome;
  readonly summary: string;
  /** Keep NEVER auto-merges from CI; a needs-review/pass still routes to the human gate. */
  readonly humanMergeRequired: boolean;
  readonly exitCode: number;
}

/** Map a Keep review/merge-readiness result into a CI step result. */
export function toCiStepResult(params: { hasBlockers: boolean; readinessOverall: number; irreversible: boolean }): CiStepResult {
  if (params.hasBlockers) {
    return { outcome: "fail", summary: "blocking findings present", humanMergeRequired: true, exitCode: 1 };
  }
  if (params.irreversible || params.readinessOverall < 0.8) {
    return { outcome: "needs-review", summary: "clear of blockers; human review required", humanMergeRequired: true, exitCode: 0 };
  }
  // Even a clean pass keeps the human merge gate (Keep proposes, human merges).
  return { outcome: "pass", summary: "clean; ready for human merge", humanMergeRequired: true, exitCode: 0 };
}

// --- #49 Project templates (with drift protection) ---

export interface ProjectTemplate {
  readonly name: string;
  readonly version: string;
  /** The starting config: model policy, review posture, isolation floor, etc. */
  readonly config: Readonly<Record<string, unknown>>;
}

export interface StampedTemplate {
  readonly template: ProjectTemplate;
  /** Checksum over the canonical config — drift/tamper detection. */
  readonly checksum: string;
}

/** Stamp a template with a content checksum (drift protection). */
export function stampTemplate(template: ProjectTemplate): StampedTemplate {
  const checksum = createHash("sha256").update(canonicalize(template.config), "utf8").digest("hex");
  return { template, checksum };
}

export interface TemplateInstantiation {
  readonly templateName: string;
  readonly templateVersion: string;
  readonly checksum: string;
  readonly instantiatedTs: number;
}

/**
 * Instantiate a template, recording provenance (which template+version+checksum a
 * project came from) so a bad shared default is traceable and can be updated rather
 * than silently propagating. Verifies the stamp first (drift/tamper check).
 */
export function instantiateTemplate(stamped: StampedTemplate, now: number): { config: Readonly<Record<string, unknown>>; provenance: TemplateInstantiation } {
  const recomputed = createHash("sha256").update(canonicalize(stamped.template.config), "utf8").digest("hex");
  if (recomputed !== stamped.checksum) {
    throw new Error(`template "${stamped.template.name}" failed checksum (drift/tamper) — refusing to instantiate`);
  }
  return {
    config: stamped.template.config,
    provenance: {
      templateName: stamped.template.name,
      templateVersion: stamped.template.version,
      checksum: stamped.checksum,
      instantiatedTs: now,
    },
  };
}
