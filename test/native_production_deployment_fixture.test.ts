import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { encodeCanonical } from "../src/eir/canonical.js";
import { captureNativeV2Schema } from "../src/platform/native_boundary_protocol_v2.js";
import { productionDeploymentFixture } from "./fixtures/native_v2_production_deployment.js";

const digest = (bytes: string): string => createHash("sha256").update(bytes).digest("hex");

test("production resolver fixture is canonical production schema with exact executable joins", () => {
  const digests = {
    helper: digest("helper"),
    trampoline: digest("trampoline"),
    prober: digest("prober"),
    provisioner: digest("provisioner"),
    role: digest("role"),
  };
  const fixture = productionDeploymentFixture(digests);
  const captured = captureNativeV2Schema(fixture, "deployment", "production");
  assert.equal(captured.canonicalHex, Buffer.from(encodeCanonical(fixture)).toString("hex"));
  assert.ok(fixture !== null && typeof fixture === "object" && !Array.isArray(fixture) && !(fixture instanceof Uint8Array));
  const payload = (fixture as { readonly [key: string]: unknown }).payload as Record<string, unknown>;
  const artifacts = payload.artifacts as Array<Record<string, unknown>>;
  for (const [kind, expected] of Object.entries(digests))
    assert.equal(artifacts.find((row) => row.kind === kind)?.digest, expected);
});
