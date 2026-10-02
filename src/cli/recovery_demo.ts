/** Run the shipped synthetic recovery harness from the installed package. */
import { spawnSync } from "node:child_process";
import { join } from "node:path";
export function runRecoveryDemo(packageRoot: string): number {
  const result = spawnSync(process.execPath, [join(packageRoot, "acceptance/installed_sg32_resources.mjs"), packageRoot], {
    encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
  });
  if (result.error || result.status !== 0) {
    process.stderr.write(result.stderr || result.error?.message || `Recovery experiment failed (${result.signal ?? result.status}).\n`);
    return 1;
  }
  const report: { status?: string; cases?: number; singleEntryCases?: number; root?: string } = JSON.parse(result.stdout.trim());
  if (report.status !== "INSTALLED_UNCERTAIN_CAPACITY_REGRESSION_PASS" || report.cases !== 16 || report.singleEntryCases !== 8 || typeof report.root !== "string") {
    process.stderr.write("Recovery experiment returned an unexpected result.\n"); return 1;
  }
  process.stdout.write("Recovery experiment passed: 24 checks; 0 model calls.\n");
  process.stdout.write(`Detailed results: ${join(report.root, "report.json")}\n`);
  return 0;
}
