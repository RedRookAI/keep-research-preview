import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileGatewayTokenStore } from "../src/cli/gateway_token_store.js";

test("installed gateway token store persists and atomically rotates a protected token", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-gateway-token-"));
  const path = join(root, "gateway-token");
  const first = "a".repeat(48), second = "b".repeat(48);
  const initial = new FileGatewayTokenStore(path);
  assert.equal(initial.load(), undefined);
  initial.save(first);
  assert.equal(new FileGatewayTokenStore(path).load(), first);
  initial.save(second);
  assert.equal(new FileGatewayTokenStore(path).load(), second);
  assert.equal(readFileSync(path, "utf8"), `${second}\n`);
  if (process.platform !== "win32") { chmodSync(path, 0o644); assert.throws(() => initial.load(), /mode-0600/u); }
});

test("installed gateway token store refuses malformed files and symlinks", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-gateway-token-hostile-"));
  const target = join(root, "target"), path = join(root, "gateway-token");
  writeFileSync(target, `${"c".repeat(48)}\n`, { mode: 0o600 });
  symlinkSync(target, path);
  assert.throws(() => new FileGatewayTokenStore(path).load(), /regular file/u);
  assert.throws(() => new FileGatewayTokenStore(join(root, "other")).save("not-a-token"), /malformed/u);
});
