/**
 * Plan consequence-analysis floor (Increment 16.8a) — real pre-execution blast-radius analysis.
 *
 * Replaces the vacuous skeleton gate (16.7) — which fed a hardcoded 4-step plan to LogicVet and always
 * passed — with an actual consequence taxonomy over the intended effects of THIS issue. SOTA-grounded
 * (VETTING_REDESIGN_SPEC, 2026-08-05):
 *  - Consequence taxonomy + blast-radius classification before execution: "if you do not know what an
 *    action can break, you cannot evaluate whether to allow it" (PhantomByte 2026).
 *  - Reversibility is mandatory: an irreversible high-blast effect with no undo path cannot auto-proceed
 *    (PhantomByte).
 *  - Effect-boundary framing: high-consequence failures are boundary crossings — destructive filesystem
 *    ops, DB modification, egress, audit/monitoring tamper (Containment Verification 2605.09045).
 *  - Second-order: effect COMBINATIONS that individually pass but jointly raise risk (runtime-verification
 *    2026; IEEE-USA/NIST 2026 cascading compromise).
 *
 * This is a SOUND, model-free Tier-0: deterministic classification. Only a sound boundary violation
 * hard-blocks; softer concerns ESCALATE to human (never hard-kill from a fuzzy signal). It is the floor
 * of the plan cascade (16.8b adds the optional independent second-brain tier + human).
 * Zero deps.
 */

import type { Issue } from "../solve/issue_model.js";
import type { SuspectFile } from "../solve/localize.js";
import { forecastConsequences } from "./consequence_forecast.js";

/** Effect boundaries an intended change may cross, worst-first. */
export type EffectClass =
  | "audit-tamper"          // touches the audit/monitoring/logging path itself
  | "filesystem-destructive" // mass delete / rm -rf / drop directory
  | "db-schema"             // drop/alter tables, migrations
  | "network-egress"        // opens outbound connections / exfil surface
  | "secret-credential"     // touches secrets/keys/credentials
  | "auth-access-control"   // touches auth / permission / access checks
  | "dependency-config"     // changes deps / build / CI config
  | "pure-code";            // ordinary code edit (lowest blast)

export type BlastRadius = "critical" | "high" | "medium" | "low";

export interface IntendedEffect {
  readonly cls: EffectClass;
  readonly blast: BlastRadius;
  /** Whether this effect has a known undo path (reversible). */
  readonly reversible: boolean;
  /** The evidence (file/keyword) that surfaced this effect — for the audit trail. */
  readonly evidence: string;
}

export type ConsequenceDecision = "pass" | "block" | "escalate";

export interface ConsequenceCheck {
  readonly name: string;
  readonly sound: boolean;
  readonly decision: ConsequenceDecision;
  readonly reason: string;
}

export interface ConsequenceVerdict {
  readonly decision: ConsequenceDecision;
  readonly cleared: boolean;
  readonly effects: readonly IntendedEffect[];
  readonly checks: readonly ConsequenceCheck[];
  readonly reason: string;
}

// ── effect derivation (from issue text + suspect files) ──

interface Signal { cls: EffectClass; blast: BlastRadius; reversible: boolean; re: RegExp; }

// Ordered worst-first; each maps a text/path signal to an effect class + default blast + reversibility.
const SIGNALS: readonly Signal[] = [
  // Destructive audit tampering (delete/disable/clear) → critical, irreversible. Merely *editing* audit
  // code is caught by PATH_SIGNALS as a non-critical touch (escalate via second-order, not hard-block).
  { cls: "audit-tamper", blast: "critical", reversible: false, re: /\b(disable\s*(logging|monitoring|audit)|tamper\s*with\s*(logs?|audit)|delete\s*(the\s*)?(audit\s*)?logs?|clear\s*(the\s*)?logs?|remove\s*(audit|provenance))\b/i },
  { cls: "filesystem-destructive", blast: "critical", reversible: false, re: /\b(rm\s+-rf|delete\s+all|drop\s+(all|everything)|wipe|purge\s+(all|files)|truncate\s+(all|files)|format\s+disk)\b/i },
  { cls: "db-schema", blast: "critical", reversible: false, re: /\b(drop\s+table|drop\s+database|delete\s+from|truncate\s+table|alter\s+table|migration|drop\s+all\s+tables?)\b/i },
  { cls: "network-egress", blast: "high", reversible: true, re: /\b(fetch|http|https|outbound|exfiltrat|upload\s+to|send\s+to\s+(remote|server)|webhook|curl|wget|socket)\b/i },
  { cls: "secret-credential", blast: "high", reversible: false, re: /\b(secret|credential|password|api[_-]?key|token|private[_-]?key|\.pem|oauth)\b/i },
  { cls: "auth-access-control", blast: "high", reversible: true, re: /\b(auth|authenticat|authoriz|permission|access\s*control|login|rbac|acl|bypass\s*(check|auth)|disable\s*(check|validation))\b/i },
  { cls: "dependency-config", blast: "medium", reversible: true, re: /\b(package\.json|requirements\.txt|dependency|dependencies|ci\s*config|\.github\/workflows|dockerfile|build\s*config)\b/i },
  // Ordinary touch of the audit/logging path (edit, not destroy) — medium, reversible → surfaces the
  // class for second-order analysis without hard-blocking.
  { cls: "audit-tamper", blast: "medium", reversible: true, re: /\b(audit\s*log|logging|monitoring|provenance|the\s*spine)\b/i },
];

/** Path-based signals (suspect files that themselves indicate a sensitive area). */
const PATH_SIGNALS: readonly Signal[] = [
  { cls: "audit-tamper", blast: "critical", reversible: false, re: /(audit|spine|provenance|governance|logging)/i },
  { cls: "secret-credential", blast: "high", reversible: false, re: /(secret|credential|\.pem|\.key|password|token|oauth)/i },
  { cls: "auth-access-control", blast: "high", reversible: true, re: /(auth|login|permission|rbac|acl|access)/i },
  { cls: "db-schema", blast: "critical", reversible: false, re: /(migration|schema|\.sql)/i },
  { cls: "dependency-config", blast: "medium", reversible: true, re: /(package\.json|requirements\.txt|dockerfile|\.github\/workflows|tsconfig)/i },
];

/** Derive the intended effects of an issue from its text + the localized suspect files. */
export function deriveEffects(issue: Issue, suspects: readonly SuspectFile[] = []): IntendedEffect[] {
  const effects: IntendedEffect[] = [];
  const seen = new Set<string>();
  const add = (cls: EffectClass, blast: BlastRadius, reversible: boolean, evidence: string) => {
    const key = `${cls}:${evidence}`;
    if (seen.has(key)) return;
    seen.add(key);
    effects.push({ cls, blast, reversible, evidence });
  };

  for (const s of SIGNALS) {
    const m = issue.text.match(s.re);
    if (m) add(s.cls, s.blast, s.reversible, `issue text: "${m[0]}"`);
  }
  for (const f of suspects) {
    for (const s of PATH_SIGNALS) {
      if (s.re.test(f.path)) add(s.cls, s.blast, s.reversible, `suspect file: ${f.path}`);
    }
  }
  // Default: a pure code edit if nothing sensitive surfaced.
  if (effects.length === 0) add("pure-code", "low", true, "no sensitive effect signals");
  return effects;
}

/**
 * Derive the ACTUAL effects of a produced patch from its edits — the file paths touched and the content
 * ADDED (the replacement text). Used by the trajectory checkpoint to compare what the patch actually does
 * against what the plan gate approved. Same signal machinery as deriveEffects (one consistent taxonomy).
 */
export function deriveEffectsFromEdits(edits: ReadonlyArray<{ file: string; replace: string }>): IntendedEffect[] {
  const effects: IntendedEffect[] = [];
  const seen = new Set<string>();
  const add = (cls: EffectClass, blast: BlastRadius, reversible: boolean, evidence: string) => {
    const key = `${cls}:${evidence}`;
    if (seen.has(key)) return;
    seen.add(key);
    effects.push({ cls, blast, reversible, evidence });
  };
  for (const e of edits) {
    for (const s of PATH_SIGNALS) {
      if (s.re.test(e.file)) add(s.cls, s.blast, s.reversible, `edit path: ${e.file}`);
    }
    for (const s of SIGNALS) {
      const m = e.replace.match(s.re);
      if (m) add(s.cls, s.blast, s.reversible, `added code in ${e.file}: "${m[0]}"`);
    }
  }
  if (effects.length === 0) add("pure-code", "low", true, "no sensitive effect signals in the patch");
  return effects;
}

// ── the checks ──

const CRITICAL_BOUNDARIES: ReadonlySet<EffectClass> = new Set(["audit-tamper", "filesystem-destructive", "db-schema"]);

/** SOUND: crossing a critical, irreversible effect boundary hard-blocks (the worst failures). */
function checkCriticalBoundary(effects: readonly IntendedEffect[]): ConsequenceCheck {
  const worst = effects.find((e) => CRITICAL_BOUNDARIES.has(e.cls) && !e.reversible && e.blast === "critical");
  return worst
    ? { name: "critical-effect-boundary", sound: true, decision: "block", reason: `plan crosses a critical irreversible boundary (${worst.cls}) — ${worst.evidence}` }
    : { name: "critical-effect-boundary", sound: true, decision: "pass", reason: "no critical irreversible boundary crossing" };
}

/** Reversibility: a high+ blast irreversible effect can't auto-proceed → escalate to human. */
function checkReversibility(effects: readonly IntendedEffect[]): ConsequenceCheck {
  const irr = effects.find((e) => !e.reversible && (e.blast === "high" || e.blast === "critical") && !CRITICAL_BOUNDARIES.has(e.cls));
  return irr
    ? { name: "reversibility", sound: true, decision: "escalate", reason: `irreversible high-blast effect (${irr.cls}) with no undo path — ${irr.evidence}` }
    : { name: "reversibility", sound: true, decision: "pass", reason: "no irreversible high-blast effect" };
}

/**
 * Second-order: effect COMBINATIONS that individually pass but jointly raise risk. The canonical one:
 * touching auth/access-control AND (audit-tamper OR disabling a check) — i.e. changing security while
 * also touching what would detect the change.
 */
function checkSecondOrder(effects: readonly IntendedEffect[]): ConsequenceCheck {
  const classes = new Set(effects.map((e) => e.cls));
  const risky: string[] = [];
  if (classes.has("auth-access-control") && classes.has("audit-tamper")) risky.push("touches auth AND the audit path (change + hide-the-change)");
  if (classes.has("secret-credential") && classes.has("network-egress")) risky.push("touches secrets AND network egress (exfiltration surface)");
  if (classes.has("auth-access-control") && classes.has("network-egress")) risky.push("touches auth AND network egress");
  return risky.length > 0
    ? { name: "second-order-combination", sound: false, decision: "escalate", reason: `second-order risk: ${risky.join("; ")}` }
    : { name: "second-order-combination", sound: false, decision: "pass", reason: "no risky effect combination" };
}

/**
 * Analyze the consequences of an issue's intended plan. Runs the sound boundary + reversibility checks
 * (a sound block short-circuits), then the second-order combination check. Any escalate → escalate.
 * Only a SOUND boundary violation blocks; everything softer escalates to human (never a fuzzy hard-kill).
 */
export function analyzeConsequences(issue: Issue, suspects: readonly SuspectFile[] = []): ConsequenceVerdict {
  const effects = deriveEffects(issue, suspects);

  const boundary = checkCriticalBoundary(effects);
  if (boundary.decision === "block") {
    return { decision: "block", cleared: false, effects, checks: [boundary], reason: boundary.reason };
  }

  // Forward-looking (proactive): does any effect ENABLE a future high-risk irreversible state? Escalate now.
  const forecast = forecastConsequences(effects);
  const forecastCheck: ConsequenceCheck = forecast.decision === "escalate"
    ? { name: "forward-consequence-forecast", sound: false, decision: "escalate", reason: forecast.reason }
    : { name: "forward-consequence-forecast", sound: false, decision: "pass", reason: forecast.reason };

  const checks = [boundary, checkReversibility(effects), checkSecondOrder(effects), forecastCheck];
  const escalation = checks.find((c) => c.decision === "escalate");
  if (escalation) {
    return { decision: "escalate", cleared: false, effects, checks, reason: escalation.reason };
  }

  return { decision: "pass", cleared: true, effects, checks, reason: "consequence analysis clean (bounded, reversible, no risky combination, no forward risk)" };
}
