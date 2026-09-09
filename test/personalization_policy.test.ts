import { test } from "node:test";
import assert from "node:assert/strict";

import { resolvePolicy, type PolicyLayer, type PolicyRequest } from "../src/governance/personalization_policy.js";

// T3: the nested org-policy layer — PBAC, subsidiarity (user ⊆ team ⊆ org), tighten-not-remove, graceful
// degradation to N=1. Verify by disproof.

const orgDeniesSlack: PolicyLayer = { name: "org", constraints: [{ surface: "connector", deny: ["slack"] }] };
const userWantsSlack: PolicyLayer = { name: "user", constraints: [{ surface: "connector", allow: ["slack", "github"] }] };

test("constraint holds: an org layer that denies a connector refuses it even when the user requests it", () => {
  const req: PolicyRequest = { surface: "connector", value: "slack" };
  const d = resolvePolicy(req, [orgDeniesSlack, userWantsSlack]);
  assert.equal(d.allow, false, "the org constraint tightens the user's request");
  assert.equal(d.decidedBy, "org");
});

test("inner within policy honored: a value permitted by every layer is allowed", () => {
  const d = resolvePolicy({ surface: "connector", value: "github" }, [orgDeniesSlack, userWantsSlack]);
  assert.equal(d.allow, true, "github is permitted by every layer");
  assert.equal(d.effective.value, "github");
});

test("nesting/subsidiarity: an inner allow cannot re-permit what an outer layer forbids", () => {
  // the user layer explicitly allows slack; the org layer forbids it. The outer forbid must stand.
  const userAllowsSlack: PolicyLayer = { name: "user", constraints: [{ surface: "connector", allow: ["slack"] }] };
  const d = resolvePolicy({ surface: "connector", value: "slack" }, [orgDeniesSlack, userAllowsSlack]);
  assert.equal(d.allow, false, "the inner allow does NOT override the outer forbid (subsidiarity)");
  assert.equal(d.decidedBy, "org");
});

test("threshold tightening: the effective threshold is the minimum across the nest", () => {
  const org: PolicyLayer = { name: "org", constraints: [{ surface: "anticipation", maxThreshold: 3 }] };
  const team: PolicyLayer = { name: "team", constraints: [{ surface: "anticipation", maxThreshold: 5 }] };
  const d = resolvePolicy({ surface: "anticipation", threshold: 10 }, [org, team]);
  assert.equal(d.allow, true);
  assert.equal(d.effective.threshold, 3, "tightened to the strictest layer (org's 3), not the request's 10");
  assert.equal(d.decidedBy, "org");
});

test("N=1 FLOOR / graceful degradation: with no org/team layers the user's request is fully honored", () => {
  const d = resolvePolicy({ surface: "connector", value: "slack" }, []); // solo instance: no policy layers
  assert.equal(d.allow, true, "the solo operator is unconstrained except by themselves");
  assert.equal(d.effective.value, "slack");
  const t = resolvePolicy({ surface: "anticipation", threshold: 10 }, []);
  assert.equal(t.effective.threshold, 10, "no layer ⇒ the user's own threshold stands (floor intact)");
});

test("deterministic: same request + nest ⇒ same decision", () => {
  const req: PolicyRequest = { surface: "connector", value: "slack" };
  assert.deepEqual(resolvePolicy(req, [orgDeniesSlack, userWantsSlack]), resolvePolicy(req, [orgDeniesSlack, userWantsSlack]));
});
