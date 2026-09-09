import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runFlagshipDemo, formatFlagship } from "../src/demo/flagship.js";

test("FLAGSHIP (crown): one runProject call carries feasibility → solve → governed decision → tamper-evident trail", async () => {
  const r = await runFlagshipDemo({ dataDir: mkdtempSync(join(tmpdir(), "keep-flagship-t-")) });

  // 1. Feasibility pre-flight ran and cleared a real software task.
  assert.equal(r.feasibility.deliverability, "fully-deliverable");
  assert.equal(r.feasibility.proceed, true);

  // 2. The autonomous loop actually drove the build (it reached the implement stage).
  assert.ok(r.visited.includes("implement"), "the run reached the implement stage (a real solve)");

  // 3. A GOVERNED decision was produced — and read back FROM the tamper-evident trail (source of truth).
  assert.equal(r.governedVerdict, "autonomous-merge", "a clean, verified, reversible fix merges autonomously");

  // 4. The trail is real and hash-verifiable.
  assert.ok(r.sealedEvents > 0, "the run left a sealed audit trail");
  assert.equal(r.chainOk, true, "the hash-chain verifies intact");

  // 5. Tamper-evidence: mutating a sealed event is DETECTED.
  assert.equal(r.tamperDetected, true, "tampering with the trail fails verification");
});

test("FLAGSHIP renders a human-readable summary (the demo artifact)", async () => {
  const r = await runFlagshipDemo({ dataDir: mkdtempSync(join(tmpdir(), "keep-flagship-fmt-")) });
  const text = formatFlagship(r);
  assert.match(text, /governed autonomous run/i);
  assert.match(text, /Governed verdict: autonomous-merge/);
  assert.match(text, /Chain verifies  : yes/);
});
