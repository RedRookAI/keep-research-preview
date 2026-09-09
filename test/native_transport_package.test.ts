import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const packageRoot = join(root, "dist/native/linux-x64");
const manifestPath = join(packageRoot, "manifest.json");

type Artifact = { name: string; bytes: number; sha256: string; mode: number };
type Manifest = {
  schema: string;
  target: string;
  platform: string;
  architecture: string;
  protocolVersion: number;
  channelMaxFrameBytes: number;
  artifacts: Artifact[];
};

function hasInterpreter(bytes: Buffer): boolean {
  const offset = Number(bytes.readBigUInt64LE(32));
  const width = bytes.readUInt16LE(54);
  const count = bytes.readUInt16LE(56);
  for (let index = 0; index < count; index += 1)
    if (bytes.readUInt32LE(offset + index * width) === 3) return true;
  return false;
}

test("A6 package build stages exactly two content-bound static refusal peers", () => {
  assert.equal(lstatSync(packageRoot).mode & 0o777, 0o555);
  const manifestStatus = lstatSync(manifestPath);
  assert.equal(manifestStatus.isFile(), true);
  assert.equal(manifestStatus.isSymbolicLink(), false);
  assert.equal(manifestStatus.mode & 0o777, 0o444);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest;
  assert.deepEqual(
    {
      schema: manifest.schema,
      target: manifest.target,
      platform: manifest.platform,
      architecture: manifest.architecture,
      protocolVersion: manifest.protocolVersion,
      channelMaxFrameBytes: manifest.channelMaxFrameBytes,
    },
    {
      schema: "keep.native-transport-package/v1",
      target: "x86_64-unknown-linux-musl",
      platform: "linux",
      architecture: "x64",
      protocolVersion: 2,
      channelMaxFrameBytes: 65536,
    },
  );
  assert.deepEqual(
    manifest.artifacts.map((row) => row.name),
    ["keep-native-client", "keep-native-supervisor"],
  );
  for (const artifact of manifest.artifacts) {
    const path = join(packageRoot, artifact.name);
    const status = lstatSync(path);
    assert.equal(status.isFile(), true);
    assert.equal(status.isSymbolicLink(), false);
    assert.equal(status.mode & 0o777, 0o555);
    assert.equal(artifact.mode, 0o555);
    const bytes = readFileSync(path);
    assert.equal(bytes.length, artifact.bytes);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), artifact.sha256);
    assert.equal(bytes.subarray(0, 6).toString("hex"), "7f454c460201");
    assert.equal(bytes.readUInt16LE(16), 3, "artifact must be PIE (ET_DYN)");
    assert.equal(bytes.readUInt16LE(18), 62, "artifact must target x86-64");
    assert.equal(hasInterpreter(bytes), false, "artifact must have no dynamic interpreter");
  }
  assert.notEqual(manifest.artifacts[0]?.sha256, manifest.artifacts[1]?.sha256);
  const supervisorDigestPath = join(packageRoot, "keep-native-supervisor.sha256");
  const supervisorDigestStatus = lstatSync(supervisorDigestPath);
  assert.equal(supervisorDigestStatus.isFile(), true);
  assert.equal(supervisorDigestStatus.isSymbolicLink(), false);
  assert.equal(supervisorDigestStatus.mode & 0o777, 0o444);
  assert.equal(
    readFileSync(supervisorDigestPath, "ascii"),
    `${manifest.artifacts[1]?.sha256}\n`,
  );
});
