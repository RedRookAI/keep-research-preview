import { assessSufficiency, type SufficiencyResult } from "../research/rag_grounding_floor.js";
import type { RetrievedChunk } from "../research/grounded_answer.js";
import { isAdmissibleTriResearchSource, isUsableLastKnownGoodSource, type TriResearchLane, type TriResearchReport, type TriResearchSource } from "../research/tri_research_runtime.js";
import type { ProjectState, StageExecutor, StageResult } from "./project_loop.js";

export interface ProjectRetrievalArtifact {
  readonly schemaVersion: 1;
  readonly query: string;
  readonly limit: number;
  readonly providers: readonly ("tri-research" | "project-retriever")[];
  readonly chunks: readonly RetrievedChunk[];
  readonly sourceIds: readonly string[];
  readonly sufficiency: SufficiencyResult;
}

/** Optional personal/enterprise corpus adapter. Built-in tri-research evidence remains available without one. */
export interface ProjectRetriever {
  retrieve(query: string, limit: number): readonly RetrievedChunk[];
}

interface AdmittedResearchArtifact {
  readonly admission: "complete" | "bounded-reversible";
  readonly report: TriResearchReport;
}

const LANES: readonly TriResearchLane[] = ["current", "historical", "cross-disciplinary"];

function admittedResearch(state: ProjectState): AdmittedResearchArtifact {
  const value = state.artifacts["research"] as Partial<AdmittedResearchArtifact> | undefined;
  if (value?.admission !== "complete" && value?.admission !== "bounded-reversible") {
    throw new Error("retrieval requires research admitted as complete or bounded-reversible");
  }
  const report = value.report as Partial<TriResearchReport> | undefined;
  if (report?.schema !== "keep.tri-research/v1" || report.lanes === undefined) {
    throw new Error("retrieval requires a durable tri-research report");
  }
  for (const lane of LANES) {
    if (!Array.isArray(report.lanes[lane]?.sources)) throw new Error(`retrieval requires durable ${lane} research sources`);
  }
  return value as AdmittedResearchArtifact;
}

function researchChunk(source: TriResearchSource): RetrievedChunk {
  return {
    text: source.summary,
    sourceId: source.id,
    ...(source.asOf === undefined || source.asOf.length === 0 ? {} : { asOf: source.asOf }),
    // The tri-research runtime has already admitted this source for the goal. Stale LKG material is
    // explicitly weaker but remains usable only under the bounded-reversible admission predicate.
    score: source.stale === true ? 0.5 : 1,
  };
}

function validChunk(value: RetrievedChunk): boolean {
  return typeof value?.text === "string" && value.text.trim().length > 0
    && typeof value.sourceId === "string" && value.sourceId.trim().length > 0
    && Number.isFinite(value.score) && value.score >= 0 && value.score <= 1
    && (value.asOf === undefined || (typeof value.asOf === "string" && value.asOf.length > 0));
}

function uniqueChunks(chunks: readonly RetrievedChunk[], limit: number): readonly RetrievedChunk[] {
  const seen = new Set<string>();
  const result: RetrievedChunk[] = [];
  for (const chunk of chunks) {
    if (!validChunk(chunk)) throw new Error(`retrieval evidence source "${chunk?.sourceId || "<missing>"}" contains a malformed chunk`);
    const identity = `${chunk.sourceId}\u0000${chunk.text}\u0000${chunk.asOf ?? ""}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    result.push(Object.freeze({ ...chunk }));
    if (result.length === limit) break;
  }
  return Object.freeze(result);
}

export function retrieveProjectEvidence(state: ProjectState, retriever?: ProjectRetriever, limit = 5): ProjectRetrievalArtifact {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 20) throw new Error("retrieval limit must be an integer from 1 to 20");
  const research = admittedResearch(state);
  const byLane = LANES.map((lane) => research.report.lanes[lane].sources
    .filter((source) => isUsableSource(research, lane, source))
    .map(researchChunk));
  const builtInFloor = byLane.flatMap((chunks) => chunks.slice(0, 1));
  const builtInRemainder = byLane.flatMap((chunks) => chunks.slice(1));
  const supplemental = retriever?.retrieve(state.goal, limit) ?? [];
  // Preserve the current/SOTA floor first. With two or more slots, interleave one corpus result
  // before completing the remaining research lanes; with four or more, all three lanes and the
  // corpus are represented. A limit of one cannot represent two providers and keeps the core floor.
  const candidates = retriever === undefined
    ? [...builtInFloor, ...builtInRemainder]
    : [builtInFloor[0], supplemental[0], ...builtInFloor.slice(1), ...supplemental.slice(1), ...builtInRemainder]
      .filter((chunk): chunk is RetrievedChunk => chunk !== undefined);
  const chunks = uniqueChunks(candidates, limit);
  const sufficiency = assessSufficiency(chunks);
  const providers = Object.freeze([
    "tri-research" as const,
    ...(retriever === undefined ? [] : ["project-retriever" as const]),
  ]);
  return Object.freeze({
    schemaVersion: 1,
    query: state.goal,
    limit,
    providers,
    chunks,
    sourceIds: Object.freeze([...new Set(chunks.map((chunk) => chunk.sourceId))]),
    sufficiency,
  });
}

function isUsableSource(research: AdmittedResearchArtifact, lane: TriResearchLane, source: TriResearchSource): boolean {
  if (isAdmissibleTriResearchSource(lane, source, research.report.currentSince, research.report.asOf)) return true;
  return research.admission === "bounded-reversible" && lane !== "current" && isUsableLastKnownGoodSource(source);
}

export function buildRetrievalStageExecutor(retriever?: ProjectRetriever, limit = 5): StageExecutor {
  return async (state): Promise<StageResult> => {
    const artifact = retrieveProjectEvidence(state, retriever, limit);
    if (artifact.sufficiency.status === "insufficient") {
      return {
        output: artifact,
        control: "capability-unavailable",
        capability: "project-evidence-retrieval",
        headline: "Project evidence remains insufficient; dependent work is preserved until retrieval succeeds",
        detail: artifact.sufficiency.reason,
      };
    }
    return { output: artifact, control: "advance", headline: "Bounded project evidence retrieved", detail: artifact.sufficiency.reason };
  };
}
