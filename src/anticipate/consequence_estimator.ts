/**
 * CONSEQUENCE ESTIMATOR (moat-heart #2) — derive what proceeding on an intent would trigger.
 *
 * The ask-gate (#1) decides ask-vs-proceed on consequence × uncertainty, but it needs a CONSEQUENCE input. The
 * front door shipped that as a keyword seam (a list of irreversible verbs). This module replaces the seam with a
 * real derivation over three axes drawn from the safety literature and the code already on disk:
 *   1. EXTERNALITY  — does proceeding reach the outside world (send / publish / pay / deploy)? External effects
 *                     can't be unsent; they tend toward irreversible. (Mirrors the always-gate sensitive paths in
 *                     pr_risk: deploy / payment / auth / crypto / migrations.)
 *   2. RECOVERABILITY — is there an undo path? Local, revert-safe edits are reversible; destroying/overwriting real
 *                     work is not. (Composes `classifyRebuild` — the additive-vs-destructive line, the
 *                     Cursor-deleted-the-prod-DB lesson — when a structured target is known.)
 *   3. BLAST RADIUS — scoped (a draft, one variable) vs broad (everything, production, all users).
 *
 * The mapping is precautionary: reaching the world OR destroying → irreversible (unless clearly scoped-and-
 * recoverable-local); a local recoverable edit with no external reach → reversible; and ABSENT or CONFLICTING
 * signals → `unknown`, which the gate treats between reversible and irreversible (so a genuine unknown errs toward
 * asking when the stakes/uncertainty are high, rather than silently proceeding).
 *
 * IDENTITY-FIRST (BUILD-ORDER 8.44B — CAPABILITY-NOT-PROSE): when the RESOLVED capability/tool identity actually
 * being invoked is known (`input.capability`, the callee — not its description), the effect class is derived from
 * that identity, not from re-parsed prose. Prose is attacker-controlled and unbounded ("gently tidy the remote"
 * hiding a `delete production`); the SET OF TOOLS is finite and enumerable. So a resolved destructive/external
 * capability is irreversible however soothing the wording, an UNKNOWN capability is HELD (deny-by-default), and
 * prose becomes a secondary signal that can only RAISE severity, never DOWNGRADE an identity verdict. This is the
 * object-capability / allowlist-not-denylist invariant (see `resolveCapabilityEffect`).
 *
 * PRIMITIVE (UNWIRED) — proven in-env as a CLASSIFIER: the identity-first overlay + three-axis prose derivation +
 * precautionary mapping. NOT protective end-to-end yet: `capability` is an OPTIONAL input no production caller supplies,
 * and it is caller-SUPPLIED, not authentically bound to the resolved callee. The universal wrapper (8.43) feeds each
 * invocation's RESOLVED tool identity here and makes this load-bearing on the shipped path (8.44B-WIRE seam).
 * Both-tracks: the lexical axes are the n=1 floor (no model, no resolved identity needed); an org supplies richer
 * structured signals — a resolved `capability` routes through the allowlist, a `target`/action hint routes through
 * `classifyRebuild`, and a deployment can extend the pattern sets. SEAM: the allowlist's completeness over the LIVE
 * tool registry — if the registry is acquired at runtime, the enumeration must be fed from it; unknown stays HELD.
 */

import type { ConsequenceClass } from "../routing/uncertainty_router.js";
import { classifyRebuild, type RebuildRequest } from "../frontdoor/rebuild_classifier.js";
import { resolveCapabilityEffect, type CapabilityIdentity } from "../reference/reference_registry.js";

export type ConsequenceAxis = "externality" | "recoverability" | "blast-radius";

export interface ConsequenceSignal {
  readonly axis: ConsequenceAxis;
  readonly detail: string;
}

export interface ConsequenceEstimate {
  readonly consequence: ConsequenceClass;
  readonly signals: readonly ConsequenceSignal[];
  readonly rationale: string;
  /** The RESOLVED capability identity this verdict was derived from, when the classification was identity-first. */
  readonly capabilityId?: string;
  /** true when the verdict was FIXED by the resolved capability identity (not re-parsed prose). */
  readonly identityDerived?: boolean;
}

export interface ConsequenceInput {
  readonly message: string;
  /** Optional structured hint — what the action targets — enabling the rebuild_classifier's real-work line. */
  readonly target?: RebuildRequest["target"];
  /**
   * The RESOLVED capability/tool identity actually being invoked (the callee) — NOT its prose description. When
   * present, the effect class is derived IDENTITY-FIRST: an enumerated destructive/external capability is
   * irreversible however soothing the message reads, and an UNKNOWN capability is HELD (irreversible/precautionary),
   * never silently classed reversible. Prose becomes a secondary signal that can only RAISE severity, never
   * DOWNGRADE an identity-derived verdict. Absent → the prose derivation below (unchanged, backward-compatible).
   */
  readonly capability?: CapabilityIdentity;
}

/** Severity ordering so prose can RAISE but never LOWER an identity-derived floor. */
const SEVERITY: Record<ConsequenceClass, number> = { reversible: 0, unknown: 1, irreversible: 2 };
function moreSevere(a: ConsequenceClass, b: ConsequenceClass): ConsequenceClass {
  return SEVERITY[a] >= SEVERITY[b] ? a : b;
}

/** Axis 1 — reaches outside the workspace (aligned with pr_risk's deploy/payment/auth always-gate categories). */
const EXTERNAL_RX = /\b(send|email|e-mail|post|publish|tweet|deploy|release|ship|launch|go live|pay|charge|purchase|buy|invoice|bill|transfer|wire|submit|production|prod)\b/i;
/** Axis 2 (negative) — destroys/overwrites: no automatic undo (aligned with rebuild_classifier's destructive verbs). */
const DESTRUCTIVE_RX = /\b(delete|remove|drop|wipe|erase|destroy|overwrite|purge|reset|revoke|terminate|cancel|shut down|tear down)\b/i;
/** Axis 2 (positive) — local, revert-safe edits. */
const RECOVERABLE_RX = /\b(draft|rename|edit|tweak|adjust|rework|reword|preview|try|explore|sketch|note|comment|format|refactor|prototype|mock)\b/i;
/** Axis 3 — broad blast. */
const BROAD_RX = /\b(all|every|everything|entire|whole|global|everyone|all users|database|the db|production|prod)\b/i;
/** Axis 3 — narrowly scoped. */
const SCOPED_RX = /\b(a single|one |this |single|my draft|locally|just the|only the|a variable|a line)\b/i;

export function estimateConsequence(input: ConsequenceInput): ConsequenceEstimate {
  const prose = proseEstimate(input);

  // No resolved capability → the prose derivation stands (backward-compatible for callers that only have text).
  if (input.capability === undefined) return prose;

  // IDENTITY-FIRST. Classify by the RESOLVED callee identity, not its wording.
  const cap = resolveCapabilityEffect(input.capability);
  const capSignal: ConsequenceSignal = {
    axis: "externality",
    detail: `resolved capability "${cap.id}" classified ${cap.effect} — ${cap.note}`,
  };
  const signals = [capSignal, ...prose.signals];

  // (b) UNKNOWN-DENY (fail-closed): an unenumerated/mislabeled capability is HELD for confirmation, never waved
  // through as recoverable. Strictly safer than a silent proceed; a human can still choose to proceed.
  if (!cap.known) {
    return {
      consequence: "irreversible",
      signals,
      rationale: `unrecognized capability "${cap.id}" — held for confirmation (deny-by-default); an unenumerated capability is never classed recoverable`,
      capabilityId: cap.id,
      identityDerived: true,
    };
  }

  // (a) IDENTITY-FIRST, external branch: an external effect leaves the workspace — it can't be unsent, and no
  // local/prose nuance applies. Classified irreversible DIRECTLY from identity; prose is never consulted here.
  if (cap.effect === "external") {
    return {
      consequence: "irreversible",
      signals,
      rationale: `resolved capability "${cap.id}" is external — reaches outside the workspace; irreversible by identity`,
      capabilityId: cap.id,
      identityDerived: true,
    };
  }

  // Destructive / recoverable identities carry a FLOOR; prose then feeds the combine below.
  //   destructive → irreversible floor;  recoverable → reversible floor.
  const identityFloor: ConsequenceClass = cap.effect === "destructive" ? "irreversible" : "reversible";

  // (c) NO-DOWNGRADE: the final verdict is the MORE SEVERE of the identity floor and the prose verdict. Prose may
  // RAISE severity (a recoverable capability described destructively/externally still escalates) but can NEVER
  // lower an identity-derived floor (soothing prose over a destructive capability stays irreversible).
  const consequence = moreSevere(identityFloor, prose.consequence);

  return {
    consequence,
    signals,
    rationale: cap.effect === "destructive"
      ? `resolved capability "${cap.id}" is destructive — irreversible by identity; prose cannot downgrade this`
      : consequence === "reversible"
        ? `resolved capability "${cap.id}" is known-recoverable — reversible`
        : `resolved capability "${cap.id}" is known-recoverable, but the request escalates severity — treated as ${consequence}`,
    capabilityId: cap.id,
    identityDerived: true,
  };
}

/** Prose derivation (the n=1 floor). Three lexical axes + precautionary mapping — a SECONDARY signal once a
 *  resolved capability identity is known, and the sole signal when it is not. */
function proseEstimate(input: ConsequenceInput): ConsequenceEstimate {
  const m = input.message;
  const signals: ConsequenceSignal[] = [];

  // Axis 1 — externality.
  const external = EXTERNAL_RX.test(m);
  if (external) signals.push({ axis: "externality", detail: "reaches outside the workspace (send/publish/pay/deploy)" });

  // Axis 2 — recoverability. Compose the rebuild classifier when a structured target is known (real-work line).
  let destructive = DESTRUCTIVE_RX.test(m);
  if (input.target !== undefined) {
    const rc = classifyRebuild({ text: m, target: input.target });
    if (!rc.isPureRevision) destructive = true;
  }
  const recoverable = RECOVERABLE_RX.test(m) && !destructive;
  if (destructive) signals.push({ axis: "recoverability", detail: "destroys/overwrites — no automatic undo" });
  else if (recoverable) signals.push({ axis: "recoverability", detail: "local, revert-safe edit" });

  // Axis 3 — blast radius.
  const broad = BROAD_RX.test(m);
  const scoped = SCOPED_RX.test(m) && !broad;
  if (broad) signals.push({ axis: "blast-radius", detail: "broad scope (all / everything / production)" });
  else if (scoped) signals.push({ axis: "blast-radius", detail: "narrowly scoped" });

  // Precautionary mapping.
  if (external || destructive) {
    // Reaching the world is always irreversible; destruction is irreversible unless clearly scoped-recoverable-local.
    if (external || broad || !recoverable) {
      return {
        consequence: "irreversible",
        signals,
        rationale: external
          ? "proceeding reaches outside the workspace — not automatically undoable"
          : "proceeding destroys/overwrites with no automatic undo",
      };
    }
  }
  if (recoverable && !external && !destructive) {
    return { consequence: "reversible", signals, rationale: "a local, revert-safe action — cheap to redirect" };
  }
  return {
    consequence: "unknown",
    signals,
    rationale: signals.length === 0
      ? "no consequence signal in the message — treat as unknown (precautionary)"
      : "conflicting consequence signals — treat as unknown (precautionary)",
  };
}
