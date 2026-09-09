import assert from "node:assert/strict";
import test from "node:test";

import { buildRetrievalStageExecutor, retrieveProjectEvidence, type ProjectRetriever } from "../src/autonomy/retrieval_stage.js";
import type { ProjectState } from "../src/autonomy/project_state.js";
import type { TriResearchLane, TriResearchReport, TriResearchSource } from "../src/research/tri_research_runtime.js";

const source = (lane: TriResearchLane, stale = false): TriResearchSource => ({
  id: `source-${lane}`,
  title: lane,
  locator: `https://evidence.invalid/${lane}`,
  retrievedAt: "2026-08-28T10:00:00Z",
  asOf: "2026-08-01",
  summary: `${lane} evidence for the project`,
  ...(stale ? { stale: true } : {}),
});

function report(): TriResearchReport {
  return {
    schema: "keep.tri-research/v1", asOf: "2026-08-28", currentSince: "2026-05-28", complete: true,
    lanes: {
      current: { lane: "current", query: "q", routesTried: ["test"], sources: [source("current")], verified: true, usableForBoundedWork: true },
      historical: { lane: "historical", query: "q", routesTried: ["test"], sources: [source("historical")], verified: true, usableForBoundedWork: true },
      "cross-disciplinary": { lane: "cross-disciplinary", query: "q", routesTried: ["test"], sources: [source("cross-disciplinary")], verified: true, usableForBoundedWork: true },
    },
  };
}

function state(research: unknown = { admission: "complete", report: report() }): ProjectState {
  return {
    schemaVersion: 1, revision: 2, runId: "retrieval", goal: "research current safe orchestration", stage: "rag", posture: "autonomous",
    artifacts: { understand: {}, research }, stepsRemaining: 10, reworkCount: 0, status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
  };
}

test("admitted tri-research is a zero-configuration retrieval provider", () => {
  const artifact = retrieveProjectEvidence(state());
  assert.deepEqual(artifact.providers, ["tri-research"]);
  assert.equal(artifact.sufficiency.status, "sufficient");
  assert.deepEqual(artifact.sourceIds, ["source-current", "source-historical", "source-cross-disciplinary"]);
  assert.equal(artifact.chunks[0]?.text, "current evidence for the project");
});

test("an optional personal/enterprise retriever augments rather than replaces canonical research", () => {
  let call: readonly [string, number] | undefined;
  const retriever: ProjectRetriever = { retrieve(query, limit) { call = [query, limit]; return [{ text: "private corpus evidence", sourceId: "tenant-corpus", score: 0.8 }]; } };
  const artifact = retrieveProjectEvidence(state(), retriever, 4);
  assert.deepEqual(call, ["research current safe orchestration", 4]);
  assert.deepEqual(artifact.providers, ["tri-research", "project-retriever"]);
  assert.ok(artifact.sourceIds.includes("source-current"));
  assert.ok(artifact.sourceIds.includes("tenant-corpus"));
});

test("a configured corpus receives a bounded slot whenever two-provider representation is possible", () => {
  const base = report();
  const extra = (id: string): TriResearchSource => ({ ...source("current"), id, summary: `${id} evidence` });
  const crowded: TriResearchReport = {
    ...base,
    lanes: { ...base.lanes, current: { ...base.lanes.current, sources: [source("current"), extra("current-2"), extra("current-3")] } },
  };
  const retriever: ProjectRetriever = { retrieve: () => [{ text: "tenant evidence", sourceId: "tenant-corpus", score: 0.9 }] };
  const artifact = retrieveProjectEvidence(state({ admission: "complete", report: crowded }), retriever, 4);
  assert.deepEqual(artifact.sourceIds, ["source-current", "tenant-corpus", "source-historical", "source-cross-disciplinary"]);
  assert.deepEqual(retrieveProjectEvidence(state({ admission: "complete", report: crowded }), retriever, 2).sourceIds, ["source-current", "tenant-corpus"]);
  assert.deepEqual(retrieveProjectEvidence(state({ admission: "complete", report: crowded }), retriever, 1).sourceIds, ["source-current"]);
});

test("retained rejected sources stay auditable in research but cannot be promoted into retrieval", () => {
  const base = report();
  const rejected: TriResearchSource = { ...source("current"), id: "rejected-old", asOf: "2020-01-01" };
  const retained: TriResearchReport = {
    ...base,
    lanes: { ...base.lanes, current: { ...base.lanes.current, sources: [rejected, source("current")] } },
  };
  const artifact = retrieveProjectEvidence(state({ admission: "complete", report: retained }));
  assert.ok(!artifact.sourceIds.includes("rejected-old"));
  assert.equal(artifact.sourceIds[0], "source-current");
});

test("bounded retrieval admits timestamped non-current LKG but never stale current evidence", () => {
  const base = report();
  const staleCurrent = { ...source("current", true), id: "stale-current", asOf: "2020-01-01" };
  const bounded: TriResearchReport = {
    ...base, complete: false,
    lanes: {
      current: { ...base.lanes.current, sources: [staleCurrent, source("current")] },
      historical: { ...base.lanes.historical, verified: false, sources: [source("historical", true)] },
      "cross-disciplinary": { ...base.lanes["cross-disciplinary"], verified: false, sources: [source("cross-disciplinary", true)] },
    },
  };
  const artifact = retrieveProjectEvidence(state({ admission: "bounded-reversible", report: bounded }));
  assert.deepEqual(artifact.sourceIds, ["source-current", "source-historical", "source-cross-disciplinary"]);
  assert.equal(artifact.chunks[1]?.score, 0.5);
  assert.equal(artifact.chunks[2]?.score, 0.5);
});

test("LKG without a valid retrieval timestamp cannot become grounded evidence", () => {
  const base = report();
  const invalid = { ...source("historical", true), retrievedAt: "whenever" };
  const bounded: TriResearchReport = {
    ...base, complete: false,
    lanes: {
      ...base.lanes,
      historical: { ...base.lanes.historical, verified: false, sources: [invalid] },
      "cross-disciplinary": { ...base.lanes["cross-disciplinary"], verified: false, sources: [source("cross-disciplinary", true)] },
    },
  };
  const artifact = retrieveProjectEvidence(state({ admission: "bounded-reversible", report: bounded }));
  assert.ok(!artifact.sourceIds.includes("source-historical"));
});

test("empty optional historical asOf is normalized away instead of causing deterministic retries", () => {
  const base = report();
  const historical = { ...source("historical"), asOf: "" };
  const adjusted: TriResearchReport = { ...base, lanes: { ...base.lanes, historical: { ...base.lanes.historical, sources: [historical] } } };
  const artifact = retrieveProjectEvidence(state({ admission: "complete", report: adjusted }));
  assert.equal(artifact.chunks[1]?.sourceId, "source-historical");
  assert.equal(artifact.chunks[1]?.asOf, undefined);
});

test("retrieval is bounded, de-duplicated, and rejects malformed adapter evidence", () => {
  const duplicate: ProjectRetriever = { retrieve: () => [{ text: "current evidence for the project", sourceId: "source-current", asOf: "2026-08-01", score: 1 }] };
  assert.equal(retrieveProjectEvidence(state(), duplicate, 3).chunks.length, 3);
  assert.throws(() => retrieveProjectEvidence(state(), { retrieve: () => [{ text: "bad", sourceId: "x", score: 2 }] }), /source "x".*malformed chunk/);
  assert.throws(() => retrieveProjectEvidence(state(), { retrieve: () => [{ text: " \n", sourceId: "blank", score: 1 }] }, 4), /source "blank".*malformed chunk/);
  assert.throws(() => retrieveProjectEvidence(state(), undefined, 0), /integer from 1 to 20/);
  assert.throws(() => retrieveProjectEvidence(state(), undefined, 21), /integer from 1 to 20/);
});

test("retrieval refuses unadmitted research instead of laundering it into grounded evidence", () => {
  assert.throws(() => retrieveProjectEvidence(state({ report: report() })), /admitted as complete or bounded-reversible/);
});

test("the stage advances on sufficient admitted evidence without requesting human approval", async () => {
  const result = await buildRetrievalStageExecutor()(state());
  assert.equal(result.control, "advance");
  assert.equal((result.output as { sufficiency: { status: string } }).sufficiency.status, "sufficient");
});
