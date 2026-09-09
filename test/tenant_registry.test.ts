import { test } from "node:test";
import assert from "node:assert/strict";

import { TenantRegistryStore, DEFAULT_TENANT, CrossTenantRegistryAccessError } from "../src/registry/tenant_registry.js";
import { publishSkill } from "../src/registry/skill_registry.js";
import { mintProjectId } from "../src/session/project_id.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

const A = mintProjectId();
const B = mintProjectId();

function skill(id: string): DistilledSkill {
  return { id, name: id, trigger: "when x", steps: ["do y"], envelope: { declaredEffects: [] } } as unknown as DistilledSkill;
}

test("P-7 ISOLATION: a skill published to tenant A is NOT visible in tenant B's list", () => {
  const reg = new TenantRegistryStore();
  reg.forTenant(A).put(publishSkill(skill("alpha-skill"), "a"));
  assert.ok(reg.forTenant(A).list().some((p) => p.skill.id === "alpha-skill"), "A sees its own skill");
  assert.equal(reg.forTenant(B).list().length, 0, "B's registry does not contain A's skill");
});

test("P-7 STRUCTURAL: tenant B cannot get tenant A's skill from B's view", () => {
  const reg = new TenantRegistryStore();
  reg.forTenant(A).put(publishSkill(skill("secret-skill"), "a"));
  assert.equal(reg.forTenant(B).get("secret-skill"), undefined, "B's view has no path to A's skill");
});

test("P-7 GUARD: an explicit cross-tenant get throws CrossTenantRegistryAccessError", () => {
  const reg = new TenantRegistryStore();
  reg.forTenant(A).put(publishSkill(skill("guarded"), "a"));
  assert.throws(() => reg.getFor(B, A, "guarded"), CrossTenantRegistryAccessError, "cross-tenant reach is denied deterministically");
  // same-tenant get is allowed
  assert.ok(reg.getFor(A, A, "guarded"), "same-tenant get is allowed");
});

test("P-7 N=1: the default tenant view works unchanged (single-tenant frictionless)", () => {
  const reg = new TenantRegistryStore();
  reg.forTenant().put(publishSkill(skill("solo"), "self"));
  assert.ok(reg.forTenant(DEFAULT_TENANT).list().some((p) => p.skill.id === "solo"), "default tenant stores + lists normally");
});
