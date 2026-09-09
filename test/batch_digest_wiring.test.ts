import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { PrReviewItem } from "../src/review/batch_digest.js";
import type { MergeReadiness } from "../src/review/merge_readiness.js";

// WIRING PROOF (P0-A #7): batch_digest is reachable + batches, and never batches away a consequential item.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-bd-")) }).secondBrain;
}
// minimal readiness (the digest reads only overall + hasBlockers)
const readiness = (overall: number, hasBlockers: boolean): MergeReadiness =>
  ({ overall, hasBlockers, card: {} as MergeReadiness["card"], reviewDepth: "standard" as MergeReadiness["reviewDepth"] });
const item = (prId: string, overall: number, hasBlockers: boolean): PrReviewItem =>
  ({ prId, title: `PR ${prId}`, readiness: readiness(overall, hasBlockers), effortSignals: { linesChanged: 10, filesTouched: 1, crossCutting: false, inlineFindings: 0 } });

test("composeKeep exposes the review digest", () => {
  assert.equal(typeof sb().reviewDigest, "function");
});

test("low-consequence ready items batch into ONE digest", () => {
  const d = sb().reviewDigest([item("a", 0.9, false), item("b", 0.85, false), item("c", 0.95, false)]);
  assert.equal(d.total, 3);
  assert.equal(d.entries.length, 3, "one digest across all items (not a per-item nag)");
  assert.equal(d.readyToMerge, 3, "all clean, high-readiness items are flagged ready");
});

test("CONSEQUENCE-GATING: a blocked item surfaces FIRST and is never counted ready", () => {
  const d = sb().reviewDigest([item("ready", 0.95, false), item("BLOCKED", 0.5, true), item("ready2", 0.9, false)]);
  assert.equal(d.entries[0]!.prId, "BLOCKED", "the blocked item is triaged to the top, not buried in the batch");
  assert.equal(d.blocked, 1);
  assert.ok(!d.entries.find((e) => e.prId === "BLOCKED")!.readinessPct || d.entries[0]!.hasBlockers, "blocked flagged");
  assert.equal(d.readyToMerge, 2, "the blocked item is NOT fast-tracked as ready-to-merge");
});

test("empty queue degrades sanely (n=1 floor)", () => {
  const d = sb().reviewDigest([]);
  assert.equal(d.total, 0);
  assert.match(d.summary, /No PRs/);
});
