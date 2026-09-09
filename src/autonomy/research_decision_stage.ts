import type { ProjectState } from "./project_state.js";
import type { ProjectIntentArtifact } from "./understand_stage.js";
import { detectResearchNeed } from "../research/research_need.js";

export interface ResearchDecisionArtifact {
  readonly schemaVersion: 1;
  readonly required: boolean;
  /** The coordinator is core-owned and therefore always present. */
  readonly coordinator: "built-in";
  /** Whether at least one live retrieval route is configured for this run. */
  readonly available: boolean;
  readonly reason: string;
  readonly signals: readonly string[];
}

const LOCAL_EVIDENCE_RX = /\b(local|repository|repo|codebase|workspace|this project|package\.json|installed|on[- ]disk|file)\b/i;
const EXTERNAL_DOMAIN_RX = /\b(market|prices?|pricing|laws?|legal|regulations?|standards?|best practices?|state of the art|sota|competitors?|public api|vendors?|security advisor(?:y|ies)|release notes?|weather|schedules?)\b/i;
const LOCAL_PATH_RX = /(?:^|[\s`"'(])(?:\.\/)?(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+\.[A-Za-z0-9]+(?=$|[\s`"'),.;])/u;
const LOCAL_STATE_RX = /\bcurrent\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+){0,2}(?:value|limit|count|state|status|contents|setting|settings|configuration)\b/giu;
const RETAINED_SOURCE_RX = /\b(?:from|using)\s+(?:the\s+)?retained\s+(?:(?:launch|project|rollout)\s+)?(?:history|memory|records|decisions)\b/iu;
const RETAINED_STATE_RX = /\b(?:latest|newest|current)\s+(?:(?:retained|recorded|project|rollout)\s+)?(?:policy|decision|setting|settings|configuration|replacement)\b/giu;

function understandingOf(state: ProjectState): ProjectIntentArtifact {
  const value = state.artifacts["understand"] as Partial<ProjectIntentArtifact> | undefined;
  if (value?.schemaVersion !== 1 || value.input?.kind !== "text" || typeof value.intent?.shape !== "string") {
    throw new Error("research decision requires a persisted understand artifact");
  }
  return value as ProjectIntentArtifact;
}

/** Decide from durable understanding; route availability never masquerades as coordinator availability. */
export function decideProjectResearch(state: ProjectState, retrievalAvailable: boolean): ResearchDecisionArtifact {
  const understanding = understandingOf(state);
  const signals: string[] = [];
  const text = understanding.input.text;
  // "Current retry limit" in src/retry.mjs describes runtime state, not the
  // currency of external knowledge. This derived routing text never replaces
  // the retained task; any other research signal still requires retrieval.
  const localStateText = text.replace(LOCAL_STATE_RX, match => match.replace(/^current/iu, "runtime"));
  const namedLocalState = LOCAL_PATH_RX.test(text) && localStateText !== text && !detectResearchNeed(localStateText).needed;
  // A selected retained project history can describe both original and replacement
  // settings. It is not a request to establish worldwide currency. Require the
  // explicit source and file scope; leave every other research trigger intact.
  // This routes work to evidence gathering, never asserts that memory is sufficient
  // or current, and never changes the operator's persisted request or permissions.
  const retainedStateText = localStateText.replace(RETAINED_STATE_RX, match => match.replace(/^(?:latest|newest|current)/iu, "recorded"));
  const namedRetainedState = state.artifacts["memory_context_required"] === true
    && LOCAL_PATH_RX.test(text) && !/https?:\/\//iu.test(text) && RETAINED_SOURCE_RX.test(text)
    && retainedStateText !== text && !detectResearchNeed(retainedStateText).needed;
  const boundedLocal = (LOCAL_EVIDENCE_RX.test(text) || namedLocalState || namedRetainedState) && !EXTERNAL_DOMAIN_RX.test(text);
  const need = detectResearchNeed(text);
  if (!boundedLocal && understanding.intent.shape === "open-ended-goal") signals.push("open-ended-goal-needs-external-grounding");
  if (!boundedLocal && need.needed) {
    signals.push(...need.triggers.filter((trigger) => trigger !== "none").map((trigger) => `research-trigger:${trigger}`));
  }
  const required = signals.length > 0;
  const reason = required
    ? retrievalAvailable
      ? `External research is required (${signals.join(", ")}); the built-in coordinator has a configured retrieval route.`
      : `External research is required (${signals.join(", ")}); the built-in coordinator will record exact retrieval debt until a route is available.`
    : "External research is not required; this bounded request can proceed from persisted operator intent and local project evidence.";
  return Object.freeze({ schemaVersion: 1, required, coordinator: "built-in", available: retrievalAvailable, reason, signals: Object.freeze(signals) });
}
