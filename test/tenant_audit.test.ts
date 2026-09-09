import { test } from "node:test";
import assert from "node:assert/strict";

import { auditTrail } from "../src/review/review_core.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// A minimal KeepApp-like shim exposing just the spine (auditTrail only touches app.spine).
function appWithSpine() {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-taud-"))), new InProcessLock(), new SchemaRegistry());
  return { app: { spine } as never, spine };
}

function stageReview(spine: Spine, reviewId: string, tenant?: string) {
  spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId, manifest: {}, ts: 1, ...(tenant ? { tenant } : {}) } });
}

test("P-7 AUDIT: a tenant sees its own audit events", () => {
  const { app, spine } = appWithSpine();
  stageReview(spine, "r1", "tenantA");
  assert.ok(auditTrail(app, "r1", "tenantA").length >= 1, "tenant A sees its own review event");
});

test("P-7 AUDIT ISOLATION: tenant B's audit view excludes tenant A's events", () => {
  const { app, spine } = appWithSpine();
  stageReview(spine, "r1", "tenantA");
  assert.equal(auditTrail(app, "r1", "tenantB").length, 0, "tenant B cannot see tenant A's audit events");
  assert.ok(auditTrail(app, "r1", "tenantA").length >= 1, "tenant A still can (sanity)");
});

test("P-7 AUDIT READ-ONLY: the scoped view does not mutate the append-only spine", () => {
  const { app, spine } = appWithSpine();
  stageReview(spine, "r1", "tenantA");
  const before = spine.currentEvents().length;
  auditTrail(app, "r1", "tenantB");
  auditTrail(app, "r1", "tenantA");
  assert.equal(spine.currentEvents().length, before, "auditTrail is a scoped READ — the spine is untouched");
});

test("P-7 AUDIT N=1: no tenant scope sees the full trail (backward-compat)", () => {
  const { app, spine } = appWithSpine();
  stageReview(spine, "r1", "tenantA");
  stageReview(spine, "r1"); // an un-attributed (global/n=1) event on the same review
  assert.ok(auditTrail(app, "r1").length >= 2, "no-tenant call sees the full trail (own + others + global)");
});
