import { test } from "node:test";
import assert from "node:assert/strict";

import { MemoryStore, deriveImportance, lessonRankScore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function store(): MemoryStore {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-mem-"))), new InProcessLock(), new SchemaRegistry());
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}

test("M1 TAXONOMY: a lesson stored with kind='preference' round-trips categorized as a preference", async () => {
  const s = store();
  const l = await s.ingest("prefers dark mode", { origin: "self", kind: "preference" });
  assert.ok(l, "ingested");
  assert.equal(s.get(l!.id)?.kind, "preference", "the kind is preserved");
});

test("M1 TAXONOMY: a lesson with NO kind supplied defaults to 'procedure' (backward-compatible)", async () => {
  const s = store();
  const l = await s.ingest("always run the tests before merging", { origin: "self" });
  assert.equal(s.get(l!.id)?.kind, "procedure", "defaults to procedure");
});

test("M1 IMPORTANCE: importance modulates retrieval rank (higher importance ranks higher, all else equal)", () => {
  const hi = lessonRankScore(0.5, 1.0, 0.9);
  const lo = lessonRankScore(0.5, 1.0, 0.1);
  assert.ok(hi > lo, `high-importance (${hi}) should rank above low-importance (${lo}) at equal similarity+tier`);
});

test("M1 IMPORTANCE: deriveImportance is bounded [0,1] and MONOTONE in evidence count (honest, never fabricated)", () => {
  const vals = [0, 1, 2, 3, 5, 10].map((n) => deriveImportance("confirmed", n));
  for (const v of vals) assert.ok(v >= 0 && v <= 1, `importance ${v} out of [0,1]`);
  for (let i = 1; i < vals.length; i++) assert.ok(vals[i]! >= vals[i - 1]!, "more corroboration must not lower importance");
  // and tier matters: a confirmed lesson is at least as important as a candidate one with the same evidence
  assert.ok(deriveImportance("confirmed", 0) >= deriveImportance("candidate", 0), "tier lifts importance");
});

test("M1: an explicit importance overrides the derived default", async () => {
  const s = store();
  const l = await s.ingest("critical deploy step", { origin: "self", importance: 0.95 });
  assert.equal(s.get(l!.id)?.importance, 0.95, "explicit importance is honored");
});

// ─── M2: per-agent memory scoping (structural isolation) ───

test("M2 SCOPE: an agent-scoped lesson is retrievable within its own agent scope", async () => {
  const s = store();
  await s.ingest("agent alpha prefers terse output", { origin: "self", scope: "agent", agentId: "alpha" });
  const hits = await s.retrieve("terse output preference", 5, "candidate", "alpha");
  assert.ok(hits.some((h) => /terse output/.test(h.lesson.content)), "alpha retrieves its own agent-scoped memory");
});

test("M2 ISOLATION: agent A's agent-scoped memory is NOT retrievable by agent B", async () => {
  const s = store();
  await s.ingest("agent alpha secret convention xyzzy", { origin: "self", scope: "agent", agentId: "alpha" });
  const asBeta = await s.retrieve("secret convention xyzzy", 5, "candidate", "beta");
  assert.ok(!asBeta.some((h) => /xyzzy/.test(h.lesson.content)), "beta cannot see alpha's agent-scoped memory");
  const asAlpha = await s.retrieve("secret convention xyzzy", 5, "candidate", "alpha");
  assert.ok(asAlpha.some((h) => /xyzzy/.test(h.lesson.content)), "alpha still can (sanity: it exists)");
});

test("M2 BACKWARD-COMPAT: user/project/global lessons are unaffected by the agent dimension", async () => {
  const s = store();
  await s.ingest("shared project convention foobar", { origin: "self", scope: "project" });
  // retrievable with NO agentId (the n=1 path) AND by any agent (shared space)
  const unscoped = await s.retrieve("project convention foobar", 5);
  assert.ok(unscoped.some((h) => /foobar/.test(h.lesson.content)), "unscoped retrieve still sees shared lessons");
  const asAgent = await s.retrieve("project convention foobar", 5, "candidate", "gamma");
  assert.ok(asAgent.some((h) => /foobar/.test(h.lesson.content)), "an agent also sees shared lessons");
});

test("M2 STRUCTURAL: two agents' scoped memories never cross (each only sees its own + shared)", async () => {
  const s = store();
  await s.ingest("alpha-only note apple", { origin: "self", scope: "agent", agentId: "alpha" });
  await s.ingest("beta-only note banana", { origin: "self", scope: "agent", agentId: "beta" });
  await s.ingest("shared note cherry", { origin: "self", scope: "global" });
  const alpha = (await s.retrieve("note", 10, "candidate", "alpha")).map((h) => h.lesson.content).join(" ");
  const beta = (await s.retrieve("note", 10, "candidate", "beta")).map((h) => h.lesson.content).join(" ");
  assert.ok(/apple/.test(alpha) && !/banana/.test(alpha), "alpha sees its own, not beta's");
  assert.ok(/banana/.test(beta) && !/apple/.test(beta), "beta sees its own, not alpha's");
  assert.ok(/cherry/.test(alpha) && /cherry/.test(beta), "both see the shared note");
});

// ─── M4.5: bitemporal provenance (valid-time vs record-time) ───

import { memoryCorrect } from "../src/memory/memory_tools.js";

test("M4.5 VALID-AT: a fact with an explicit [validFrom,validTo) is returned inside its interval, not outside", async () => {
  const s = store();
  await s.ingest("the office was in Berlin", { origin: "self", validFrom: 100, validTo: 200 });
  assert.equal(s.validAt(150).length, 1, "inside the interval → present");
  assert.equal(s.validAt(50).length, 0, "before validFrom → absent");
  assert.equal(s.validAt(200).length, 0, "at validTo (exclusive) → absent");
  assert.equal(s.validAt(250).length, 0, "after validTo → absent");
});

test("M4.5 DISTINCT AXES: valid-time is independent of record-time (recorded now, valid in the past)", async () => {
  const s = store();
  const past = Date.now() - 1_000_000;
  const l = await s.ingest("this held last week", { origin: "self", validFrom: past });
  assert.ok(l, "ingested");
  // found by a valid-at query in the past window...
  assert.equal(s.validAt(past + 10).length, 1, "valid-at(past) finds it");
  // ...yet its RECORD time is now, not the past validFrom
  assert.ok(l!.createdTs > past + 500_000, "createdTs (record time) is now, not the past validFrom");
  assert.equal(l!.validFrom, past, "validFrom (valid time) is the asserted past");
});

test("M4.5 RETRO-EDIT: memoryCorrect closes the old valid interval at the new validFrom", async () => {
  const s = store();
  const first = await s.ingest("API base is v1", { origin: "self", validFrom: 1000 });
  const before = s.get(first!.id)!.validFrom + 1; // 1001, while v1 held
  const res = await memoryCorrect(s, first!.id, "API base is v2");
  assert.ok(res, "corrected");
  const newFrom = s.get(res!.newId)!.validFrom;
  // before the correction boundary → old value held
  const atBefore = s.validAt(before).map((x) => x.content);
  assert.ok(atBefore.some((c) => /v1/.test(c)) && !atBefore.some((c) => /v2/.test(c)), "valid-at(before) → v1 only");
  // at/after the correction boundary → new value holds, old no longer
  const atAfter = s.validAt(newFrom + 1).map((x) => x.content);
  assert.ok(atAfter.some((c) => /v2/.test(c)) && !atAfter.some((c) => /v1/.test(c)), "valid-at(after) → v2 only");
});

test("M4.5 RECORD SURVIVES: after a retro-edit the old record is present, retired, createdTs unchanged", async () => {
  const s = store();
  const first = await s.ingest("API base is v1", { origin: "self", validFrom: 1000 });
  const originalCreatedTs = s.get(first!.id)!.createdTs;
  await memoryCorrect(s, first!.id, "API base is v2");
  const old = s.get(first!.id);
  assert.ok(old, "old record still present (supersede-not-delete)");
  assert.equal(old!.tier, "retired", "old is retired");
  assert.equal(old!.createdTs, originalCreatedTs, "record time (createdTs) is NOT mutated by the valid-time retro-edit");
  assert.ok(old!.validTo !== undefined, "old valid interval is now closed");
});

// ─── P-7 slice 2: tenant-scoped memory isolation (mirror of M2, tenant dimension) ───

test("P-7 MEM TENANT: a project-scoped lesson under tenant T is retrievable when querying as T", async () => {
  const s = store();
  await s.ingest("tenant-t deploy convention zulu", { origin: "self", scope: "project", projectId: "tenantT" });
  const hits = await s.retrieve("deploy convention zulu", 5, "candidate", undefined, "tenantT");
  assert.ok(hits.some((h) => /zulu/.test(h.lesson.content)), "tenant T retrieves its own project-scoped memory");
});

test("P-7 MEM ISOLATION: tenant A's project memory is NOT retrievable by tenant B", async () => {
  const s = store();
  await s.ingest("tenant-a secret convention quebec", { origin: "self", scope: "project", projectId: "tenantA" });
  const asB = await s.retrieve("secret convention quebec", 5, "candidate", undefined, "tenantB");
  assert.ok(!asB.some((h) => /quebec/.test(h.lesson.content)), "tenant B cannot see tenant A's project memory");
  const asA = await s.retrieve("secret convention quebec", 5, "candidate", undefined, "tenantA");
  assert.ok(asA.some((h) => /quebec/.test(h.lesson.content)), "tenant A still can (sanity)");
});

test("P-7 MEM BACKWARD-COMPAT: project-scope with NO projectId stays shared (n=1 unchanged)", async () => {
  const s = store();
  await s.ingest("shared project note yankee", { origin: "self", scope: "project" });
  // retrievable with no projectId (the n=1 path) AND by any tenant (it's in the shared space)
  assert.ok((await s.retrieve("project note yankee", 5)).some((h) => /yankee/.test(h.lesson.content)), "no-projectId path still sees it");
  assert.ok((await s.retrieve("project note yankee", 5, "candidate", undefined, "tenantX")).some((h) => /yankee/.test(h.lesson.content)), "a tenant also sees shared project notes");
});

test("P-7 MEM STRUCTURAL: two tenants' project memories never cross (each sees only its own + shared)", async () => {
  const s = store();
  await s.ingest("A-only note apple", { origin: "self", scope: "project", projectId: "A" });
  await s.ingest("B-only note banana", { origin: "self", scope: "project", projectId: "B" });
  await s.ingest("shared note cherry", { origin: "self", scope: "global" });
  const a = (await s.retrieve("note", 10, "candidate", undefined, "A")).map((h) => h.lesson.content).join(" ");
  const b = (await s.retrieve("note", 10, "candidate", undefined, "B")).map((h) => h.lesson.content).join(" ");
  assert.ok(/apple/.test(a) && !/banana/.test(a), "A sees its own, not B's");
  assert.ok(/banana/.test(b) && !/apple/.test(b), "B sees its own, not A's");
  assert.ok(/cherry/.test(a) && /cherry/.test(b), "both see the shared note");
});
