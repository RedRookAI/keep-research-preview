import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
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
    return spawnSync(process.execPath, [join(process.cwd(), "dist/src/cli/keep.js"), ...args], {
      cwd: process.cwd(),
      input: "",
      encoding: "utf8",
      timeout: 20000,
      env: { ...inherited, ...overlay, KEEP_DATA_DIR: dataDir },
    });
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}

test("SHIPPED-ENTRYPOINT PROBE: explicit local mode reaches the honest inert `solve` seam", () => {
  const r = runCli(["solve", "make the totals not double-count tax"]);
  assert.match(r.stdout, /No model\/repository is configured yet/);
  assert.equal(r.status, 2);
});

test("SHIPPED-ENTRYPOINT PROBE: missing provider mode refuses before command composition", () => {
  const r = runCli(["solve", "make the totals not double-count tax"], {});
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /KEEP_PROVIDER: is required; choose explicit local or remote mode/);
  assert.equal(r.status, 1);
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
