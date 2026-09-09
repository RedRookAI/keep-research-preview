import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";

// WIRING PROOF (P0-B): composeKeep INVOKES composeInfra — the live-adapter bundle runs in the app,
// not merely exported from index.ts. (Distinct from infra_wiring.test.ts, which tests composeInfra standalone.)

test("composeKeep().infra is the wired live-adapter bundle", () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-ci-")) });
  assert.ok(app.infra, "the infra bundle is reachable from the composed app");
  assert.ok(app.infra.isolation, "process-isolation adapter wired");
  assert.ok(app.infra.triggers, "trigger router wired");
  assert.ok(app.infra.capabilities, "capability hub wired");
});

test("graceful degradation: the builtin scanner backstop is always present in the running app", () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-ci-")) });
  assert.ok(app.infra.scanners.length >= 1, "a builtin backstop scanner is always available");
  assert.ok(app.infra.scanners.some((s) => s.name === "builtin-pattern"), "the builtin pattern scanner is the backstop");
});

test("trigger sources are registered in the wired bundle", () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-ci-")) });
  assert.ok(app.infra.triggers.supportedSources().includes("github-issues"), "trackers registered via the running app");
});
