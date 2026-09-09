import { test } from "node:test";
import assert from "node:assert/strict";
import { SacrificialActuator, AuthorityActuatorClient } from "../src/boundary/sacrificial_actuator.js";
import { BoundaryDeniedError, issueRoleCredential, roleRequest } from "../src/boundary/role_channel.js";
import type { BrokerRequest, BrokerResult, EffectBroker } from "../src/broker/broker.js";

const REQUEST = Object.freeze({ family: "net", operation: "send" }) as unknown as BrokerRequest;

test("D2 can reach D3, while D1 cannot address the sacrificial actuator", async () => {
  const authority = issueRoleCredential("authority", "d2-1", "boot-a");
  const workload = issueRoleCredential("workload", "d1-1", "boot-a");
  const calls: Array<{ request: BrokerRequest; now: bigint; epoch: bigint }> = [];
  const broker = { dispatch: async (request: BrokerRequest, now: bigint, epoch: bigint): Promise<BrokerResult> => {
    calls.push({ request, now, epoch });
    return { ok: false, reason: "test", auditId: "a" };
  } } as EffectBroker;
  const actuator = new SacrificialActuator(authority, broker, { now: () => 41n, epoch: () => 7n });
  const client = new AuthorityActuatorClient(authority, (message) => actuator.receive(message));

  assert.equal((await client.dispatch(REQUEST)).ok, false);
  await assert.rejects(() => actuator.receive(roleRequest(workload, REQUEST)), BoundaryDeniedError);
  assert.deepEqual(calls, [{ request: REQUEST, now: 41n, epoch: 7n }]);
});

test("D3 samples trusted time and epoch locally; they are absent from the wire request", async () => {
  const authority = issueRoleCredential("authority", "d2-1", "boot-a");
  let observed: readonly bigint[] = [];
  const broker = { dispatch: async (_request: BrokerRequest, now: bigint, epoch: bigint): Promise<BrokerResult> => {
    observed = [now, epoch];
    return { ok: false, reason: "test", auditId: "a" };
  } } as EffectBroker;
  const actuator = new SacrificialActuator(authority, broker, { now: () => 99n, epoch: () => 3n });

  await actuator.receive(roleRequest(authority, REQUEST));
  assert.deepEqual(observed, [99n, 3n]);
});

