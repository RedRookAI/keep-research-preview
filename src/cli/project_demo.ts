/** Present the shipped installed repository journey; responses and decisions are scripted. */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function runProjectDemo(packageRoot: string): Promise<number> {
  const path = process.env.PATH ?? "/usr/bin:/bin";
  const git = spawnSync("git", ["--version"], { env: { PATH: path, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" }, encoding: "utf8", timeout: 5000 });
  if (git.error || git.status !== 0) {
    process.stderr.write("The repository walkthrough needs Git on PATH. Install Git, or try keep demo recovery.\n");
    return 2;
  }
  const root = mkdtempSync(join(tmpdir(), "keep-project-demo-"));
  process.stdout.write("Keep — a repository change you can inspect\n\n");
  process.stdout.write("Scripted local responses; no account, API key or paid calls.\nThe walkthrough simulates approval and veto on its own sample repository.\n\n");
  process.stdout.write("Running: approval gate → edit → tests → restart → review → veto\n");
  const child = spawn(process.execPath, [join(packageRoot, "acceptance/installed_solve.mjs"), root], {
    detached: true, stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: path, TMPDIR: root, KEEP_INSTALLED_PACKAGE_ROOT: packageRoot, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
  });
  const stop = () => { if (child.pid) try { process.kill(-child.pid, "SIGKILL"); } catch { /* own group already exited */ } };
  let interrupted = false, stderr = "", bytes = 0;
  const interrupt = () => { interrupted = true; stop(); };
  process.once("SIGINT", interrupt); process.once("SIGTERM", interrupt);
  child.stdout.on("data", chunk => { bytes += chunk.length; if (bytes > 4 * 1024 * 1024) stop(); });
  child.stderr.on("data", chunk => { if (stderr.length < 16384) stderr += String(chunk).slice(0, 16384 - stderr.length); });
  const timer = setTimeout(stop, 120_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("exit", resolve); });
    if (code !== 0 || interrupted) throw new Error(stderr || "walkthrough was interrupted or could not complete");
    const result = JSON.parse(readFileSync(join(root, "result.json"), "utf8")) as {
      status: string; root: string; diff: string; controlledModelCalls: number; passedTests: string[];
      sourceUnchanged: boolean; restartNoReplay: boolean; wrongTokenRefused: boolean; explicitApprovalBeforeDispatch: boolean;
    };
    if (result.status !== "PASS" || result.root !== root || !result.sourceUnchanged || !result.restartNoReplay || !result.wrongTokenRefused || !result.explicitApprovalBeforeDispatch || result.controlledModelCalls !== 2 || !Array.isArray(result.passedTests) || result.passedTests.length !== 2 || typeof result.diff !== "string") throw new Error("walkthrough returned incomplete evidence");
    process.stdout.write("\nPASS  Approval gate held: 0 model calls before sample approval\n");
    process.stdout.write("PASS  Materialized change: retry limit 0 → 7\n");
    process.stdout.write(`PASS  Tests: ${result.passedTests.join("; ")}\n`);
    process.stdout.write("PASS  Restart retained the proposal without replay\nPASS  Wrong token refused; exact proposal vetoed; original source unchanged\n");
    process.stdout.write(`\nThe proposed change\n\n${result.diff.trim()}\n\n`);
    process.stdout.write(`Inspect the report, workspace and commands: ${root}\n`);
    process.stdout.write("2 scripted model responses; 0 paid calls. This demonstrates the workflow, not model quality or production isolation.\n");
    process.stdout.write('Next: configure your provider/repository, run keep doctor, then keep solve "your goal". See docs/installed-solve.md.\n');
    return 0;
  } catch (error) {
    stop(); process.stderr.write(`Repository walkthrough could not complete: ${(error as Error).message}\nRetained evidence: ${root}\nTry keep demo recovery for the account-free recovery experiment.\n`); return 1;
  } finally { clearTimeout(timer); process.removeListener("SIGINT", interrupt); process.removeListener("SIGTERM", interrupt); }
}
