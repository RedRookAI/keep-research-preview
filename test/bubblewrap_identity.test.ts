import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

// The native and TypeScript launchers embed identities independently. A security
// update must update both and its qualification probe as one change.
test("Bubblewrap security update keeps every launcher on the same dedicated identity", () => {
  const root = process.cwd();
  const identity = JSON.parse(readFileSync(join(root, "tools/bubblewrap/identity.json"), "utf8")) as {
    version: string; path: string; sha256: string;
  };
  assert.equal(identity.version, "0.13.0");
  assert.equal(identity.path, `/opt/keep/bubblewrap/${identity.version}/bwrap`);
  assert.match(identity.sha256, /^[a-f0-9]{64}$/u);
  const typescript = readFileSync(join(root, "src/infra/required_project_jail.ts"), "utf8");
  const native = readFileSync(join(root, "native/crates/p2-d2-supervisor/src/supervisor.rs"), "utf8");
  const probe = readFileSync(join(root, "tools/native_p2_d2_candidate_probe.mjs"), "utf8");
  assert.equal(typescript.match(/const BWRAP_PATH = "([^"]+)"/u)?.[1], identity.path);
  assert.equal(native.match(/const BWRAP_DIRECTORY: &str = "([^"]+)"/u)?.[1], dirname(identity.path));
  assert.equal(probe.match(/const bwrap = "([^"]+)"/u)?.[1], identity.path);
  for (const source of [typescript, native, probe]) {
    assert.equal(source.match(/const BWRAP_(?:SHA256|DIGEST)(?:: &str)? = "([a-f0-9]+)"/u)?.[1], identity.sha256);
    assert.ok(!source.includes('"/usr/bin/bwrap"'), "affected system launcher remains selectable");
    assert.ok(!source.includes("52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"), "affected identity remains trusted");
  }
});
