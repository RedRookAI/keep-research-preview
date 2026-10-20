import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export interface NativeWorkerReceipt { readonly workerId: string; readonly pid: number; readonly origin: string; readonly receipt: string; readonly tokenFile: string; readonly stderrLog?: string; }

/** Only fixed installed Keep code is launched, never a caller-supplied script or shell. */
export async function launchNativeWorker(args: readonly string[], runtimeEnv: NodeJS.ProcessEnv): Promise<NativeWorkerReceipt> {
  if (runtimeEnv["KEEP_PROVIDER_API_KEY_STDIN"] !== undefined) throw new Error("detached worker requires an environment or file credential, not stdin");
  if (args.some(arg => !["serve", "--gateway", "--project-worker", "--detach", "--paused"].includes(arg) && !/^--port=\d{1,5}$/u.test(arg))) throw new Error("detached worker accepts only --port/--paused and binds literal loopback");
  const workerId = randomUUID(), env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(runtimeEnv)) if (key.startsWith("KEEP_") || ["PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "XDG_CONFIG_HOME", "APPDATA"].includes(key)) env[key] = value;
  delete env["KEEP_GATEWAY_URL"]; delete env["KEEP_GATEWAY_TOKEN"]; delete env["KEEP_GATEWAY_SESSION_FILE"];
  // stdout contains the legacy pairing display; never copy its bearer to a log.
  const logDirectory = runtimeEnv["KEEP_DATA_DIR"] ? join(runtimeEnv["KEEP_DATA_DIR"], "native-workers") : undefined;
  if (logDirectory) mkdirSync(logDirectory, { recursive: true, mode: 0o700 });
  const stderrLog = logDirectory ? join(logDirectory, `${workerId}.stderr.log`) : undefined;
  const logFd = stderrLog ? openSync(stderrLog, "wx", 0o600) : undefined;
  let child;
  try {
    child = spawn(process.execPath, [fileURLToPath(new URL("../main.js", import.meta.url)), ...args.filter(arg => arg !== "--detach"), `--managed-worker-id=${workerId}`],
      { env, detached: true, shell: false, stdio: ["ignore", "ignore", logFd ?? "ignore", "ipc"], windowsHide: true });
  } finally { if (logFd !== undefined) closeSync(logFd); }
  return new Promise((resolve, reject) => {
    let finished = false;
    const fail = (message: string) => { if (finished) return; finished = true; clearTimeout(timer); child.unref(); if (child.connected) child.disconnect(); reject(new Error(`${message}; worker ${workerId}, pid ${child.pid ?? "unassigned"}; do not automatically relaunch`)); };
    const timer = setTimeout(() => fail("worker startup acknowledgement unavailable"), 30_000);
    child.once("error", () => fail("worker spawn failed"));
    child.once("exit", () => fail("worker exited before readiness"));
    child.on("message", message => {
      if (finished || !message || typeof message !== "object") return;
      const row = message as Partial<NativeWorkerReceipt>;
      if (row.workerId !== workerId || row.pid !== child.pid || typeof row.origin !== "string" || typeof row.receipt !== "string" || typeof row.tokenFile !== "string") return;
      finished = true; clearTimeout(timer); child.unref(); if (child.connected) child.disconnect(); resolve({ ...row as NativeWorkerReceipt, ...(stderrLog ? { stderrLog } : {}) });
    });
  });
}

/** Private, append-only lifecycle receipts. No model/gateway credential values. */
export function recordNativeWorker(dataDir: string, receipt: Omit<NativeWorkerReceipt, "receipt">, state: "ready" | "stopped"): NativeWorkerReceipt {
  const directory = join(dataDir, "native-workers"); mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, `${receipt.workerId}.${state}.json`);
  const record = { ...receipt, receipt: path };
  const fd = openSync(path, "wx", 0o600);
  try { writeFileSync(fd, JSON.stringify({ schema: "keep.native-worker/v1", ...record, state, observedAt: Date.now() }) + "\n"); fsyncSync(fd); }
  finally { closeSync(fd); }
  if (process.platform !== "win32") { const dir = openSync(directory, "r"); try { fsyncSync(dir); } finally { closeSync(dir); } }
  return record;
}
