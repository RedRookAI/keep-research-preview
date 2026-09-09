import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import type { ProjectId } from "../src/session/project_id.js";

const TOKEN = "project-secret-intake-token";

function request(path: string, body: unknown): GatewayRequest {
  return { method: "POST", path, query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: JSON.stringify(body) };
}

function filesUnder(root: string): Buffer[] {
  const out: Buffer[] = [];
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    if (statSync(path).isDirectory()) out.push(...filesUnder(path));
    else out.push(readFileSync(path));
  }
  return out;
}

test("PRIV-01: every project request tokenizes credentials before model, spine, session, or disk exposure", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-priv01-"));
  const seenIssues: string[] = [];
  const app = composeKeep({
    dataDir,
    solve: async (issue: { id: string; text: string }) => {
      seenIssues.push(issue.text);
      return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never;
    },
  });
  const firstSecret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  const started = await handleGatewayRequest(app, request("/project", { goal: `write and test a parser using ${firstSecret}` }), { token: TOKEN });
  assert.equal(started.status, 200, started.body);
  const projectId = (JSON.parse(started.body) as { projectId: string }).projectId;
  const secondSecret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  const later = await handleGatewayRequest(app, request("/project", { goal: `add retry tests with ${secondSecret}` }), { token: TOKEN });
  assert.equal(later.status, 200, later.body);

  assert.ok(seenIssues.length >= 2, "both supported project inputs reached the solver");
  assert.ok(seenIssues.every((text) => /\{\{secret:cred_\d+\}\}/u.test(text)), "the solver receives useful stable placeholders");
  const durableProjection = JSON.stringify({
    events: app.spine.currentEvents(),
    records: app.autonomyLoop!.manager.list(),
    history: app.autonomyLoop!.manager.session(projectId as ProjectId).history,
  });
  for (const secret of [firstSecret, secondSecret]) {
    assert.ok(!seenIssues.some((text) => text.includes(secret)), "raw credentials never reach solver/model input");
    assert.ok(!durableProjection.includes(secret), "raw credentials never enter durable runtime projections");
    assert.ok(filesUnder(dataDir).every((bytes) => !bytes.includes(Buffer.from(secret))), "raw credentials never enter durable files");
  }
});
