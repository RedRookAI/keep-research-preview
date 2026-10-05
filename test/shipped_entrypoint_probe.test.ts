import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The SHIPPED-ENTRYPOINT PROBE (ledger-build harness A2). Drives the REAL built binary
 * `dist/src/cli/keep.js`: provider mode must be explicit, and local mode without
 * repository configuration must not invent a runnable solve. The domain probe also
 * checks that a dispatched worker failure is held for reconciliation, not silently
 * converted into retry authority. Configured native repository work has separate
 * tests; this unconfigured probe does not establish that that pipeline is absent.
 */

function runCli(args: readonly string[], overlay: Readonly<Record<string, string>> = { KEEP_PROVIDER: "local" }) {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-probe-"));
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("KEEP_")));
  try {
    const result = spawnSync(process.execPath, [join(process.cwd(), "dist/src/cli/keep.js"), ...args], {
      cwd: process.cwd(),
      input: "",
      encoding: "utf8",
      timeout: 20000,
      env: { ...inherited, ...overlay, KEEP_DATA_DIR: dataDir },
    });
    if (args[0] === "solve") assert.deepEqual(readdirSync(dataDir), [], "unconfigured solve must not compose mutable product state");
    return result;
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}

test("SHIPPED-ENTRYPOINT PROBE: explicit local solve refuses missing repository setup", () => {
  const r = runCli(["solve", "make the totals not double-count tax"]);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /Solve setup incomplete: KEEP_REPOSITORY: is required/u);
  assert.match(r.stderr, /Run keep doctor/u);
  assert.equal(r.status, 2);
});

test("SHIPPED-ENTRYPOINT PROBE: missing provider mode refuses before command composition", () => {
  const r = runCli(["solve", "make the totals not double-count tax"], {});
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /KEEP_PROVIDER: is required; choose explicit local or remote mode/);
  assert.match(r.stderr, /Run keep doctor/u);
  assert.equal(r.status, 2);
});

test("SHIPPED-ENTRYPOINT PROBE (isolation): the solve seam message is not printed with no command", () => {
  const r = runCli([]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Usage: keep <command> \[args\]/);
  assert.doesNotMatch(r.stdout, /No model\/repository is configured yet/);
});

test("SHIPPED-ENTRYPOINT PROBE: domain worker failure requires reconciliation rather than automatic retry", () => {
  const r = runCli(["project", "--domain=long-form-fiction", "locally write and vet a novel manuscript"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Project status: waiting — an external effect must be reconciled/u);
  assert.match(r.stdout, /Stage "understand" threw; reconcile its effect before retry: domain provider returned non-JSON output/u);
  assert.match(r.stdout, /Resume signal: [a-f0-9-]+:understand:1/u);
  assert.doesNotMatch(r.stdout, /a bounded retry is scheduled/u);
  assert.doesNotMatch(r.stdout, /not available in this build/u);
});
