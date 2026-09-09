import { IntentShapeRouter, type RouteInput, type RouteResult } from "../frontdoor/intent_router.js";
import type { StageExecutor, StageResult } from "./project_loop.js";

export interface ProjectIntentRouter {
  route(input: RouteInput): Promise<RouteResult>;
}

export interface ProjectIntentArtifact {
  readonly schemaVersion: 1;
  readonly input: { readonly kind: "text"; readonly text: string };
  readonly intent: RouteResult;
  readonly ambiguity: {
    readonly detected: boolean;
    readonly clarificationQuestion?: string;
    readonly safeAutonomousInterpretation: "not-needed" | "narrow-reversible-discovery";
  };
  readonly constraints: readonly {
    readonly id: "requested-scope" | "workspace-boundary" | "consequential-effects";
    readonly statement: string;
  }[];
  readonly successCriteria: readonly {
    readonly id: "requested-outcome" | "configured-verification" | "artifact-vetting";
    readonly statement: string;
    readonly evidence: string;
  }[];
}

// Match the durable project-state ceiling so installing understanding never narrows previously
// accepted canonical goals. The preserved side-tree implementation's 32 KiB ceiling was weaker.
const MAX_PROJECT_GOAL_BYTES = 1_000_000;

/** Capture supported text without widening it or inventing task-specific acceptance claims. */
export function captureProjectIntent(goal: string, route: RouteResult): ProjectIntentArtifact {
  if (typeof goal !== "string" || goal.trim() === "" || Buffer.byteLength(goal, "utf8") > MAX_PROJECT_GOAL_BYTES || goal.includes("\0")) {
    throw new Error("project input must be non-empty bounded text");
  }
  // Preserve the exact admitted run goal. Trimming here created a second goal identity and made
  // otherwise valid runs with benign leading/trailing whitespace impossible to plan after restart.
  const text = goal;
  const question = route.shape === "ambiguous" ? route.clarifyingQuestion : undefined;
  return Object.freeze({
    schemaVersion: 1,
    input: Object.freeze({ kind: "text", text }),
    intent: Object.freeze({ ...route }),
    ambiguity: Object.freeze({
      detected: route.shape === "ambiguous",
      ...(question === undefined ? {} : { clarificationQuestion: question }),
      safeAutonomousInterpretation: route.shape === "ambiguous" ? "narrow-reversible-discovery" : "not-needed",
    }),
    constraints: Object.freeze([
      Object.freeze({ id: "requested-scope", statement: `Do not widen beyond the operator's request: ${text}` }),
      Object.freeze({ id: "workspace-boundary", statement: "All project reads and writes remain inside the configured workspace." }),
      Object.freeze({ id: "consequential-effects", statement: "External or irreversible effects require fresh commit-time authority under the configured posture and policy." }),
    ]),
    successCriteria: Object.freeze([
      Object.freeze({ id: "requested-outcome", statement: `The delivered artifact materially satisfies: ${text}`, evidence: "artifact tied to the persisted request" }),
      Object.freeze({ id: "configured-verification", statement: "The configured project verification command passes on the resulting artifact.", evidence: "recorded test execution" }),
      Object.freeze({ id: "artifact-vetting", statement: "The artifact passes the required deterministic vetting stage.", evidence: "persisted vet_artifact result" }),
    ]),
  });
}

/**
 * Install real project understanding without turning ambiguity into a universal human gate.
 * The artifact and clarification question are preserved under every posture. Only interaction
 * differs; downstream effect boundaries still enforce authority independently.
 */
export function buildUnderstandStageExecutor(router: ProjectIntentRouter = new IntentShapeRouter()): StageExecutor {
  return async (state): Promise<StageResult> => {
    const route = await router.route({ text: state.goal });
    const artifact = captureProjectIntent(state.goal, route);
    if (route.shape === "artifact-drop") {
      return {
        output: artifact, control: "capability-unavailable", capability: "project-attachment-intake",
        headline: "The request references attachments, but this text-only project run has no authenticated attachment input.",
      };
    }
    if (route.shape === "ambiguous" && state.posture !== "autonomous") {
      return {
        output: artifact, control: "approval-required",
        headline: "The request has multiple plausible interpretations.",
        detail: route.clarifyingQuestion ?? route.note,
      };
    }
    if (route.shape === "ambiguous") {
      return {
        output: artifact, control: "advance",
        headline: "Ambiguity recorded; autonomous work is limited to narrow, reversible discovery.",
        detail: route.clarifyingQuestion ?? route.note,
      };
    }
    return { output: artifact, control: "advance", headline: `Captured ${route.shape} intent, constraints, and success criteria.` };
  };
}

export const projectGoalByteLimit = (): number => MAX_PROJECT_GOAL_BYTES;
