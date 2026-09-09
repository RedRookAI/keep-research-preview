import { test } from "node:test";
import assert from "node:assert/strict";
import { SkillRetrieval, RETRIEVAL_HARD_CAP, type SkillStateProvider, type SkillLiveState } from "../src/loop/skill_retrieval.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

const skill = (id: string, shape: string, over: Partial<DistilledSkill> = {}): DistilledSkill => ({
  format: "keep.skill/v1", requiredAuthority: ["workspace:write"], id, name: id, description: id, relevanceKey: shape,
  envelope: { preconditions: [`task shape is "${shape}"`], steps: [{ action: "edit", targetPattern: "{file}" }], postconditions: [], declaredEffects: [] },
  provenance: ["T"], confidence: "corroborated", ...over,
});

// A configurable state provider.
function provider(states: Record<string, SkillLiveState>, utils: Record<string, number> = {}): SkillStateProvider {
  return { liveState: (id) => states[id] ?? "unknown", utility: (id) => utils[id] ?? 0 };
}

// ─── relevance filtering ───

test("retrieves only skills whose relevance key matches the task shape", () => {
  const r = new SkillRetrieval({ state: provider({ a: "graduated", b: "graduated" }) });
  r.add(skill("a", "bugfix"));
  r.add(skill("b", "feature"));
  const out = r.retrieve({ taskShape: "bugfix" });
  assert.equal(out.length, 1);
  assert.equal(out[0]?.skill.id, "a");
});

// ─── admission gate: rolled-back / unknown never offered ───

test("admission gate: a rolled-back skill is NEVER offered", () => {
  const r = new SkillRetrieval({ state: provider({ good: "graduated", bad: "rolled-back" }) });
  r.add(skill("good", "bugfix"));
  r.add(skill("bad", "bugfix"));
  const out = r.retrieve({ taskShape: "bugfix" });
  assert.deepEqual(out.map((x) => x.skill.id), ["good"]);
});

test("admission gate: an unknown-state skill is not offered", () => {
  const r = new SkillRetrieval({ state: provider({}) }); // all unknown
  r.add(skill("x", "bugfix"));
  assert.equal(r.retrieve({ taskShape: "bugfix" }).length, 0);
});

// ─── precondition exclusion ───

test("precondition guard excludes a skill when a task fact matches its exclusion", () => {
  const guarded = skill("g", "bugfix", {
    envelope: { preconditions: ['task shape is "bugfix"', "does not apply when: empty-input"], steps: [], postconditions: [], declaredEffects: [] },
  });
  const r = new SkillRetrieval({ state: provider({ g: "graduated" }) });
  r.add(guarded);
  assert.equal(r.retrieve({ taskShape: "bugfix", facts: ["empty-input"] }).length, 0); // excluded
  assert.equal(r.retrieve({ taskShape: "bugfix", facts: ["other"] }).length, 1);        // applies
});

// ─── reranking: graduated > canary, then utility ───

test("reranks graduated above canary", () => {
  const r = new SkillRetrieval({ state: provider({ can: "canary", grad: "graduated" }) });
  r.add(skill("can", "bugfix"));
  r.add(skill("grad", "bugfix"));
  const out = r.retrieve({ taskShape: "bugfix" });
  assert.equal(out[0]?.skill.id, "grad"); // graduated first
});

test("reranks by utility within the same state", () => {
  const r = new SkillRetrieval({ state: provider({ lo: "graduated", hi: "graduated" }, { lo: 1, hi: 50 }) });
  r.add(skill("lo", "bugfix"));
  r.add(skill("hi", "bugfix"));
  const out = r.retrieve({ taskShape: "bugfix" });
  assert.equal(out[0]?.skill.id, "hi"); // higher utility first
});

// ─── bounded top-k: the anti-shadowing property ───

test("bounded top-k: only the top-k skills are offered even with a large library (anti-shadowing)", () => {
  const states: Record<string, SkillLiveState> = {};
  const r = new SkillRetrieval({ topK: 3, state: { liveState: (id) => states[id] ?? "graduated", utility: (id) => Number(id.slice(1)) } });
  for (let i = 0; i < 50; i++) r.add(skill(`s${i}`, "bugfix"));
  const out = r.retrieve({ taskShape: "bugfix" });
  assert.equal(out.length, 3, "never exposes the whole library — stays below the phase transition");
  // highest-utility three (s49, s48, s47).
  assert.deepEqual(out.map((x) => x.skill.id), ["s49", "s48", "s47"]);
});

test("top-k is clamped to the hard cap regardless of config", () => {
  const r = new SkillRetrieval({ topK: 999, state: provider({}) });
  for (let i = 0; i < 20; i++) r.add(skill(`s${i}`, "bugfix"));
  // Force all graduated via a provider that says graduated.
  const r2 = new SkillRetrieval({ topK: 999, state: { liveState: () => "graduated", utility: () => 1 } });
  for (let i = 0; i < 20; i++) r2.add(skill(`s${i}`, "bugfix"));
  assert.ok(r2.retrieve({ taskShape: "bugfix" }).length <= RETRIEVAL_HARD_CAP);
});

// ─── compose ───

test("compose unions the selected skills' steps in rerank order", () => {
  const s1 = skill("s1", "bugfix", { envelope: { preconditions: ['task shape is "bugfix"'], steps: [{ action: "localize", targetPattern: "{file}" }], postconditions: [], declaredEffects: [] } });
  const s2 = skill("s2", "bugfix", { envelope: { preconditions: ['task shape is "bugfix"'], steps: [{ action: "edit", targetPattern: "{file}" }], postconditions: [], declaredEffects: [] } });
  const r = new SkillRetrieval({ state: provider({ s1: "graduated", s2: "canary" }) });
  r.add(s1); r.add(s2);
  const composed = r.compose({ taskShape: "bugfix" });
  assert.deepEqual(composed.skills, ["s1", "s2"]); // graduated first
  assert.ok(composed.steps.includes("localize {file}"));
  assert.ok(composed.steps.includes("edit {file}"));
});

test("compose returns empty when nothing is relevant/live", () => {
  const r = new SkillRetrieval({ state: provider({ x: "rolled-back" }) });
  r.add(skill("x", "bugfix"));
  assert.deepEqual(r.compose({ taskShape: "bugfix" }), { skills: [], steps: [] });
});
