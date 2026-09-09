/**
 * DecisionBrief (Increment 16.9b) — a NEUTRAL, non-persuasive structured brief for the residual that
 * still routes to a human after prevent + self-heal.
 *
 * SOTA constraint (this is the counterintuitive, critical one): better/narrative explanations make
 * oversight WORSE — "when the AI provided narrative rationales, deference increased by another 5 points;
 * better explainability produced worse oversight" (tianpan.co 2026). So a brief must NOT persuade. The
 * SOTA-correct form is the challenge-and-response checklist: intent, data touched, permissions chain,
 * expected blast radius, rollback plan — each a FACT the reviewer positively acknowledges (strata.io
 * 2026), plus the ONE specific thing they must verify. Present facts to verify, not conclusions to accept.
 *
 * Rendered deterministically from the structured verdicts (plan consequences, trajectory drift, patch
 * checks, forward forecast, self-heal outcome) — never free-text opinion. Zero deps.
 */

import type { ConsequenceVerdict, EffectClass } from "./plan_consequences.js";
import type { TrajectoryDrift } from "./trajectory_checkpoint.js";
import type { PatchVerdict } from "./patch_verifier.js";
import type { RemediationOutcome } from "./safe_remediation.js";

/** One line the reviewer must positively acknowledge (a fact, not a recommendation). */
export interface BriefItem {
  readonly label: string;
  readonly value: string;
}

export interface DecisionBrief {
  /** Plain-language summary of WHAT changes (no adjectives, no persuasion). */
  readonly whatChanges: string;
  /** The challenge-and-response facts to acknowledge. */
  readonly facts: readonly BriefItem[];
  /** The single most important thing to verify before approving (framed as a question, not a claim). */
  readonly verifyThis: string;
  /** Why this routed to a human at all (the trigger), stated factually. */
  readonly routedBecause: readonly string[];
  /** Whether the change is reversible (rollback available). */
  readonly reversible: boolean;
}

export interface BriefInputs {
  readonly issueText: string;
  readonly editFiles: readonly string[];
  readonly consequences?: ConsequenceVerdict;
  readonly trajectory?: TrajectoryDrift;
  readonly patchVerdict?: PatchVerdict;
  readonly selfHealing?: RemediationOutcome;
}

/** Plain-language, neutral phrasing for an effect class (no severity adjectives). */
const CLASS_PHRASING: Record<EffectClass, string> = {
  "audit-tamper": "the audit/logging path",
  "filesystem-destructive": "files (deletion/large removal)",
  "db-schema": "the database schema",
  "network-egress": "outbound network access",
  "secret-credential": "secrets or credentials",
  "auth-access-control": "authentication / access control",
  "dependency-config": "dependencies or build config",
  "pure-code": "application code",
};

/**
 * Build a neutral decision brief from the structured verdicts. It states facts and asks ONE verification
 * question; it does NOT argue for approval or describe the change as safe/good. The reviewer acknowledges
 * each fact and answers the verify question.
 */
export function buildDecisionBrief(inputs: BriefInputs): DecisionBrief {
  const touchedClasses = new Set<EffectClass>((inputs.consequences?.effects ?? []).map((e) => e.cls));
  const touchedPhrases = [...touchedClasses].filter((c) => c !== "pure-code").map((c) => CLASS_PHRASING[c]);

  const fileCount = inputs.editFiles.length;
  const whatChanges = `Edits ${fileCount} file${fileCount === 1 ? "" : "s"}${touchedPhrases.length ? `; touches ${touchedPhrases.join(", ")}` : " (application code only)"}.`;

  // The reversibility fact: reversible unless the consequence analysis found an irreversible effect.
  const irreversible = (inputs.consequences?.effects ?? []).some((e) => !e.reversible);
  const reversible = !irreversible;

  const facts: BriefItem[] = [
    { label: "Files changed", value: inputs.editFiles.join(", ") || "(none)" },
    { label: "Areas touched", value: touchedPhrases.length ? touchedPhrases.join(", ") : "application code only" },
    { label: "Reversible", value: reversible ? "yes — a rollback path exists" : "NO — changes may be hard to undo" },
    { label: "Tests", value: inputs.patchVerdict ? (inputs.patchVerdict.checks.some((c) => c.name === "tests-pass" && c.decision === "pass") ? "pass" : "not passing") : "unknown" },
  ];
  if (inputs.selfHealing?.healed) {
    facts.push({ label: "Auto-narrowed", value: `${inputs.selfHealing.droppedEdits?.length ?? 0} accidental edit(s) were removed and the result re-checked` });
  }

  // The routing triggers, stated factually (no spin).
  const routedBecause: string[] = [];
  if (inputs.consequences && inputs.consequences.decision !== "pass") routedBecause.push(inputs.consequences.reason);
  if (inputs.trajectory?.drifted) routedBecause.push(inputs.trajectory.reason);
  if (inputs.patchVerdict && !inputs.patchVerdict.cleared) routedBecause.push(inputs.patchVerdict.reason);
  if (routedBecause.length === 0) routedBecause.push("routine review under the current autonomy level");

  // The ONE thing to verify — a question tied to the highest-risk touched area (not a recommendation).
  const verifyThis = deriveVerifyQuestion(touchedClasses, inputs.trajectory);

  return { whatChanges, facts, verifyThis, routedBecause, reversible };
}

/** Derive a single, specific verification QUESTION for the reviewer (facts to check, not a verdict). */
function deriveVerifyQuestion(classes: ReadonlySet<EffectClass>, trajectory?: TrajectoryDrift): string {
  if (trajectory?.drifted) return `The change touches ${trajectory.newClasses.map((c) => CLASS_PHRASING[c]).join(", ")}, which the original task did not call for. Is that intended?`;
  if (classes.has("auth-access-control")) return "Does this change alter who can access what? Confirm the access rules are still correct.";
  if (classes.has("secret-credential")) return "Does this change handle any secret/credential? Confirm none is exposed.";
  if (classes.has("network-egress")) return "Does this change send data outside the system? Confirm the destination is expected.";
  if (classes.has("db-schema")) return "Does this change alter the database shape? Confirm existing data/readers still work.";
  if (classes.has("dependency-config")) return "Does this add or change a dependency? Confirm the source is trusted.";
  return "Does this change do exactly what the task asked, and nothing more?";
}

/** Render the brief as plain text (for a PR body / notification). Neutral formatting, no persuasion. */
export function renderBrief(brief: DecisionBrief): string {
  const lines: string[] = [];
  lines.push(`What changes: ${brief.whatChanges}`);
  lines.push("");
  lines.push("Please confirm each:");
  for (const f of brief.facts) lines.push(`  - ${f.label}: ${f.value}`);
  lines.push("");
  lines.push(`Routed for review because: ${brief.routedBecause.join("; ")}`);
  lines.push("");
  lines.push(`Before approving, verify: ${brief.verifyThis}`);
  return lines.join("\n");
}
