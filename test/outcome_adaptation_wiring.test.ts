import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";

test("composeKeep exposes project-owned outcome-gated soft behavior without learned authority", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-m6-"));
  const configuration = {
    dataDir,
    outcomeAdaptation: {
      initial: {
        prompt: { version: "composed-v1", text: "" },
        routing: { model: "local-small", effort: "none" },
        voice: { promptFormat: "markdown", verbosity: "normal" },
      },
      policy: { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 },
    },
  } as const;
  const app = composeKeep(configuration);
  const project = app.projectManager!.create({ name: "personal adaptation" });
  const adaptation = app.outcomeAdaptation!(project.id);
  adaptation.propose({
    prompt: { version: "candidate-v2", text: "Prefer concise answers" },
    routing: { model: "frontier", effort: "graded" },
    voice: { promptFormat: "markdown", verbosity: "terse" },
  });
  let decision;
  for (let index = 0; index < 8; index++) {
    const assignment = adaptation.assign(`subject-${index}`);
    adaptation.expose(assignment.assignmentId);
    decision = adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: `outcome-${index}`, observedAt: Math.max(Date.now(), assignment.assignedAt), evidence: "observed-product", quality: assignment.arm === "baseline" ? 0.5 : 0.9, regressed: false });
  }
  assert.equal(decision?.kind, "promoted");
  assert.deepEqual(Object.keys(adaptation.current()).sort(), ["prompt", "routing", "voice"]);
  assert.equal(adaptation.current().prompt.version, "candidate-v2");
  const persisted = readFileSync(join(dataDir, "projects", "sessions", `${project.id}.json.documents`, "outcome-adaptation.json"), "utf8");
  assert.doesNotMatch(persisted, /Prefer concise answers|candidate-v2/, "adaptation state is encrypted at rest");
  const restarted = composeKeep(configuration);
  assert.equal(restarted.outcomeAdaptation!(project.id).current().prompt.version, "candidate-v2", "project adaptation survives a clean process restart");
});
