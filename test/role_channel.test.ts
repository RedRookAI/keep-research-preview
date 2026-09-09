import { test } from "node:test";
import assert from "node:assert/strict";
import { BoundaryDeniedError, RoleChannel, issueRoleCredential, roleRequest } from "../src/boundary/role_channel.js";

test("only the bound authority instance can address an actuator channel", async () => {
  const authority = issueRoleCredential("authority", "d2-1", "boot-a");
  let effects = 0;
  const channel = new RoleChannel(authority, "authority", async (body: { value: number }) => {
    effects += body.value;
    return effects;
  });
  assert.equal(await channel.receive(roleRequest(authority, { value: 1 })), 1);

  const workload = issueRoleCredential("workload", "d1-1", "boot-a");
  await assert.rejects(() => channel.receive(roleRequest(workload, { value: 100 })), BoundaryDeniedError);
  assert.equal(effects, 1, "D1 cannot invoke the actuator handler");
});

test("role text cannot forge connection-bound identity", async () => {
  const authority = issueRoleCredential("authority", "d2-1", "boot-a");
  const attacker = issueRoleCredential("workload", "d1-1", "boot-a");
  const channel = new RoleChannel(authority, "authority", () => "effect");
  await assert.rejects(() => channel.receive({
    claimed: authority.identity,
    credential: attacker.secret,
    body: {},
  }), BoundaryDeniedError);
});

test("credentials are boot- and instance-bound", async () => {
  const authority = issueRoleCredential("authority", "d2-1", "boot-a");
  const restarted = issueRoleCredential("authority", "d2-1", "boot-b");
  const channel = new RoleChannel(authority, "authority", () => "effect");
  await assert.rejects(() => channel.receive(roleRequest(restarted, {})), BoundaryDeniedError);
});
