import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { FileGatewayTokenStore } from "./gateway_token_store.js";
import { createGatewayClient } from "./gateway_client.js";
import { launchNativeWorker, type NativeWorkerReceipt } from "./native_worker.js";
import { captureRuntimeContract } from "./runtime_config.js";

interface InstanceProfile { readonly schema: "keep.instance/v1"; readonly environment: Record<string, string>; }
const PROFILE = "instance.json";
const CURRENT = "current-worker.json";
const PENDING = "startup-pending.json";
const FIELDS = new Set(["KEEP_PROVIDER", "KEEP_DATA_DIR", "KEEP_REPOSITORY", "KEEP_WORKSPACE_BASE", "KEEP_REVISION", "KEEP_REPO_REF", "KEEP_BASE_BRANCH", "KEEP_TEST_COMMAND", "KEEP_TEST_ARGS_JSON", "KEEP_TEST_NAMESPACE_JAIL", "KEEP_PROJECT_MODEL", "KEEP_CODEX_PROCESSING", "KEEP_CODEX_EXECUTABLE", "KEEP_CODEX_MODEL", "KEEP_CODEX_MAX_INVOCATIONS", "KEEP_CODEX_MAX_PROMPT_BYTES", "KEEP_CODEX_MAX_OUTPUT_BYTES", "KEEP_CODEX_TIMEOUT_MS"]);
const CODEX_FIELDS = [...FIELDS].filter(key => key === "KEEP_PROJECT_MODEL" || key.startsWith("KEEP_CODEX_"));
const within = (parent: string, child: string): boolean => child === parent || child.startsWith(parent + sep);

function privateDirectory(path: string): string {
  const s = lstatSync(path);
  if (!s.isDirectory() || s.isSymbolicLink() || (process.platform !== "win32" && ((s.mode & 0o077) !== 0 || s.uid !== process.getuid?.()))) throw new Error("instance directory must be owned by this user, private (0700), and not a symlink");
  return realpathSync(path);
}
function readPrivate(path: string): unknown {
  const s = lstatSync(path);
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.size > 65_536 || (process.platform !== "win32" && ((s.mode & 0o077) !== 0 || s.uid !== process.getuid?.()))) throw new Error("instance record must be an owned private regular file");
  return JSON.parse(readFileSync(path, "utf8"));
}
function writePrivate(path: string, value: unknown): void {
  const temporary = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  renameSync(temporary, path);
}
function profileAt(directory: string): InstanceProfile {
  const row = readPrivate(join(directory, PROFILE)) as InstanceProfile;
  if (!row || Object.keys(row).sort().join(",") !== "environment,schema" || row.schema !== "keep.instance/v1" || !row.environment || typeof row.environment !== "object" || Array.isArray(row.environment)
    || Object.entries(row.environment).some(([key, value]) => !FIELDS.has(key) || typeof value !== "string" || value.includes("\0"))
    || row.environment.KEEP_PROVIDER !== "local" || row.environment.KEEP_DATA_DIR !== join(directory, "data") || row.environment.KEEP_WORKSPACE_BASE !== join(directory, "workspaces")) throw new Error("invalid owner instance profile; paths must remain in this instance and only supported settings are accepted");
  privateDirectory(row.environment.KEEP_DATA_DIR);
  privateDirectory(row.environment.KEEP_WORKSPACE_BASE);
  return row;
}
function workerAt(directory: string): NativeWorkerReceipt {
  const row = readPrivate(join(directory, CURRENT)) as NativeWorkerReceipt;
  if (!row || typeof row.workerId !== "string" || !/^[0-9a-f-]{36}$/u.test(row.workerId) || !Number.isSafeInteger(row.pid) || row.pid < 1
    || row.tokenFile !== join(directory, "data", "gateway-token") || row.receipt !== join(directory, "data", "native-workers", `${row.workerId}.ready.json`)) throw new Error("invalid instance worker identity");
  const origin = new URL(row.origin);
  if (origin.protocol !== "http:" || origin.hostname !== "127.0.0.1" || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash) throw new Error("instance worker must use a literal-loopback origin");
  return row;
}
async function request(directory: string, worker: NativeWorkerReceipt, method: "GET" | "POST", path: string, body?: unknown) {
  const token = new FileGatewayTokenStore(join(directory, "data", "gateway-token")).load();
  if (!token) throw new Error("instance gateway token is missing");
  const response = await createGatewayClient(worker.origin)({ method, path, headers: { authorization: `Bearer ${token}` }, query: {}, body: body === undefined ? "" : JSON.stringify(body) });
  if (response.status !== 200 && response.status !== 202) throw new Error(`instance ${path} refused (${response.status}): ${response.body}`);
  return JSON.parse(response.body) as Record<string, unknown>;
}
async function status(directory: string, worker: NativeWorkerReceipt) {
  const state = await request(directory, worker, "GET", "/worker/status");
  if (state.workerId !== worker.workerId || state.pid !== worker.pid) throw new Error("the responding worker does not match this instance; no lifecycle action was taken");
  return state;
}
function runtimeEnvironment(profile: InstanceProfile): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA"]) if (process.env[name] !== undefined) environment[name] = process.env[name];
  return { ...environment, ...profile.environment };
}

/** An inert owner profile around the existing worker and authenticated lifecycle API. */
export async function runInstanceCommand(args: readonly string[], write: (text: string) => void): Promise<number> {
  const [action, directoryArg, ...options] = args;
  if (!action || !["init", "start", "status", "projects", "stop"].includes(action) || !directoryArg || directoryArg.startsWith("--")) {
    write("Usage: keep instance init <directory> --repository=<path> --test-command=<executable> [--test-args=<JSON>] [--branch=<branch>]\n       keep instance start <directory> [--port=N] [--paused]\n       keep instance status|projects|stop <directory>"); return 2;
  }
  try {
    if (action === "init") {
      const allowed = ["--repository=", "--test-command=", "--test-args=", "--branch="];
      if (options.some(option => !allowed.some(prefix => option.startsWith(prefix))) || new Set(options.map(option => option.split("=")[0])).size !== options.length) throw new Error("init accepts one repository, test command, optional test-args JSON and branch");
      const option = (name: string) => options.find(value => value.startsWith(`--${name}=`))?.slice(name.length + 3);
      if (!option("repository") || !option("test-command")) throw new Error("init requires --repository=<path> and --test-command=<executable>");
      const repository = realpathSync(resolve(option("repository")!));
      const branch = option("branch") ?? execFileSync("git", ["-C", repository, "symbolic-ref", "--short", "HEAD"], { encoding: "utf8" }).trim();
      const revision = execFileSync("git", ["-C", repository, "rev-parse", "--verify", "--end-of-options", `${branch}^{commit}`], { encoding: "utf8" }).trim();
      const requested = resolve(directoryArg);
      if (existsSync(requested)) throw new Error("instance directory already exists; use its saved profile or choose a new directory");
      const canonicalParent = realpathSync(resolve(requested, ".."));
      const directory = join(canonicalParent, basename(requested));
      if (within(repository, directory) || within(directory, repository)) throw new Error("instance directory and source repository must be disjoint");
      const testArgs = JSON.parse(option("test-args") ?? "[]") as unknown;
      if (!Array.isArray(testArgs) || testArgs.some(value => typeof value !== "string")) throw new Error("test-args must be a JSON array of strings");
      mkdirSync(directory, { mode: 0o700 });
      mkdirSync(join(directory, "data"), { mode: 0o700 });
      mkdirSync(join(directory, "workspaces"), { mode: 0o700 });
      const environment: Record<string, string> = { KEEP_PROVIDER: "local", KEEP_DATA_DIR: join(directory, "data"), KEEP_REPOSITORY: repository,
        KEEP_WORKSPACE_BASE: join(directory, "workspaces"), KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_BASE_BRANCH: branch,
        KEEP_TEST_COMMAND: option("test-command")!, KEEP_TEST_ARGS_JSON: JSON.stringify(testArgs) };
      for (const key of CODEX_FIELDS) if (process.env[key] !== undefined) environment[key] = process.env[key]!;
      if (process.env.KEEP_TEST_NAMESPACE_JAIL !== undefined) environment.KEEP_TEST_NAMESPACE_JAIL = process.env.KEEP_TEST_NAMESPACE_JAIL;
      captureRuntimeContract(runtimeEnvironment({ schema: "keep.instance/v1", environment }), { cwd: process.cwd() }, { projectRequired: true });
      writePrivate(join(directory, PROFILE), { schema: "keep.instance/v1", environment });
      write(`Instance saved: ${directory}\nRepository: ${repository}@${revision}\nStart: keep instance start ${directory}\n${environment.KEEP_PROJECT_MODEL === "codex" ? "Codex selected; startup is not a generation qualification." : "Generation is not configured. The local stub will start with dispatch paused."}`);
      return 0;
    }
    const directory = privateDirectory(resolve(directoryArg));
    const profile = profileAt(directory);
    if (action !== "start" && options.length) throw new Error(`${action} accepts only the instance directory`);
    const lock = join(directory, ".control-lock");
    try { mkdirSync(lock, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("another instance control is in progress; inspect this instance before retrying"); throw error; }
    try {
      if (action === "start") {
        if (options.some(option => option !== "--paused" && !/^--port=\d{1,5}$/u.test(option)) || options.filter(option => option.startsWith("--port=")).length > 1) throw new Error("start accepts --port=0..65535 and --paused");
        const port = Number(options.find(option => option.startsWith("--port="))?.slice(7) ?? "0");
        if (port > 65535) throw new Error("port must be 0..65535");
        if (existsSync(join(directory, PENDING))) throw new Error("previous startup is unresolved; inspect data/native-workers before another launch");
        if (existsSync(join(directory, CURRENT))) {
          const previous = workerAt(directory);
          if (!existsSync(join(directory, "data", "native-workers", `${previous.workerId}.stopped.json`))) {
            const current = await status(directory, previous);
            write(`Keep is already running: ${previous.origin}\nWorker: ${previous.workerId}\nDispatch: ${String(current.state)}\nSaved profile edits apply after an owned stop/start.`); return 0;
          }
        }
        const paused = !profile.environment.KEEP_PROJECT_MODEL || options.includes("--paused");
        writePrivate(join(directory, PENDING), { schema: "keep.instance-start/v1", requestedAt: Date.now() });
        const worker = await launchNativeWorker(["serve", "--gateway", "--project-worker", "--detach", `--port=${port}`, ...(paused ? ["--paused"] : [])], runtimeEnvironment(profile));
        writePrivate(join(directory, CURRENT), worker);
        unlinkSync(join(directory, PENDING));
        write(`Keep is running: ${worker.origin}\nConsole: ${worker.origin}/console\nSign-in credential file (private): ${join(directory, "data", "gateway-token")}\nWorker: ${worker.workerId}\nDispatch: ${paused ? "paused" : "enabled"}\nState: ${profile.environment.KEEP_DATA_DIR}\nWorkspaces: ${profile.environment.KEEP_WORKSPACE_BASE}\nLifecycle records: ${join(directory, "data", "native-workers")}\nPrivate startup diagnostics: ${worker.stderrLog ?? "not recorded"}\nStatus: keep instance status ${directory}\nProjects: keep instance projects ${directory}\nStop: keep instance stop ${directory}`);
        return 0;
      }
      const worker = workerAt(directory);
      if (existsSync(join(directory, "data", "native-workers", `${worker.workerId}.stopped.json`))) {
        write(`Keep is stopped. State retained: ${profile.environment.KEEP_DATA_DIR}\nStart: keep instance start ${directory}`); return action === "projects" ? 1 : 0;
      }
      const current = await status(directory, worker);
      if (action === "status") write(`Keep is running: ${worker.origin}\nConsole: ${worker.origin}/console\nSign-in credential file (private): ${join(directory, "data", "gateway-token")}\nWorker: ${worker.workerId}\nDispatch: ${String(current.state)}\nState: ${profile.environment.KEEP_DATA_DIR}\nSaved generation setup: ${profile.environment.KEEP_PROJECT_MODEL === "codex" ? "Codex selected; live compatibility qualification is separate" : "not configured (local stub)"}\nProfile edits apply after an owned stop/start.`);
      else if (action === "projects") write(JSON.stringify(await request(directory, worker, "GET", "/projects"), null, 2));
      else {
        await request(directory, worker, "POST", "/worker/stop", { workerId: worker.workerId });
        write(`Stop accepted for worker ${worker.workerId}. State retained: ${profile.environment.KEEP_DATA_DIR}\nStatus: keep instance status ${directory}`);
      }
      return 0;
    } finally { rmdirSync(lock); }
  } catch (error) { write(`Instance ${action} failed: ${(error as Error).message}`); return 1; }
}
