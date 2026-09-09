import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign, verify } from "node:crypto";

import { composeKeep } from "../dist/src/compose.js";
import { handleGatewayRequest } from "../dist/src/gateway/http_gateway.js";
import { capabilityArgsDigest } from "../dist/src/ecosystem/capability_port.js";

const TOKEN = "client-signing-token";
const binaryBase64 = Buffer.from("private desktop binary").toString("base64");
const body = JSON.stringify({ platform: "desktop", binaryBase64, distribution: "private-development-only" });
const request = () => ({ method: "POST", path: "/client/sign", query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body });

test("CLIENT-02: private binary signing requires exact authorization, persists its effect, and has no public submission path", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-client-signing-"));
  const keys = generateKeyPairSync("ed25519");
  let calls = 0;
  const adapter = {
    descriptor: { id: "development-client-signer", kind: "connector", name: "local development signer", credentialId: "development-key", trust: "verified" },
    invoke: async (invocation, context) => {
      calls++;
      assert.deepEqual(context, { effect: "external", authorized: true });
      const signedBinaryBase64 = Buffer.from(`${Buffer.from(invocation.args.binaryBase64, "base64").toString("utf8")}:signed`).toString("base64");
      return { ok: true, output: { signedBinaryBase64, keyId: "development.local", signature: sign(null, Buffer.from(signedBinaryBase64, "base64"), keys.privateKey).toString("base64") } };
    },
  };
  const authorizationFor = (invocation) => ({ id: "operator-sign-1", actor: "owner", capabilityId: invocation.capabilityId, operation: invocation.operation, consequence: "external", idempotencyKey: "private-client-v1", argsDigest: capabilityArgsDigest(invocation.args) });
  const verifySignedBinary = (artifact) => artifact.keyId === "development.local" && verify(null, Buffer.from(artifact.signedBinaryBase64, "base64"), keys.publicKey, Buffer.from(artifact.signature, "base64"));
  const configured = () => ({ adapter, verifyAuthorization: (authorization) => authorization.id === "operator-sign-1", authorizationFor, verifySignedBinary });

  const unsigned = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-client-signing-held-")), clientSigning: { adapter: { ...adapter, descriptor: { ...adapter.descriptor, id: "held-client-signer" } }, verifyAuthorization: () => true, verifySignedBinary } });
  const held = await handleGatewayRequest(unsigned, request(), { token: TOKEN });
  assert.equal(held.status, 409);
  assert.match(JSON.parse(held.body).error, /held|authorization/u);
  assert.equal(calls, 0);

  const forgedAdapter = { ...adapter, descriptor: { ...adapter.descriptor, id: "forged-client-signer" }, invoke: async () => ({ ok: true, output: { signedBinaryBase64: binaryBase64, keyId: "forged", signature: "not-a-signature" } }) };
  const forged = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-client-signing-forged-")), clientSigning: { adapter: forgedAdapter, verifyAuthorization: () => true, authorizationFor, verifySignedBinary } });
  const rejectedSignature = await handleGatewayRequest(forged, request(), { token: TOKEN });
  assert.equal(rejectedSignature.status, 409);
  assert.match(JSON.parse(rejectedSignature.body).error, /verification rejected/u);

  const app = composeKeep({ dataDir, clientSigning: configured() });
  const signed = await handleGatewayRequest(app, request(), { token: TOKEN });
  assert.equal(signed.status, 200);
  const artifact = JSON.parse(signed.body);
  assert.equal(Buffer.from(artifact.signedBinaryBase64, "base64").toString("utf8"), "private desktop binary:signed");
  assert.equal(artifact.distribution, "private-development-only");
  assert.equal(calls, 1);

  const restarted = composeKeep({ dataDir, clientSigning: configured() });
  const replay = await handleGatewayRequest(restarted, request(), { token: TOKEN });
  assert.equal(replay.status, 200);
  assert.deepEqual(JSON.parse(replay.body), artifact);
  assert.equal(calls, 1, "restart replays the durably completed exact effect instead of signing twice");

  const publicAttempt = await handleGatewayRequest(restarted, { ...request(), body: JSON.stringify({ platform: "desktop", binaryBase64, distribution: "store-public" }) }, { token: TOKEN });
  assert.equal(publicAttempt.status, 400);
  assert.equal(calls, 1);
});
