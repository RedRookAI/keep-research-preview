import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { readRestrictedClientProfile } from "../gateway/restricted_client.js";
import { FileGatewayTokenStore } from "./gateway_token_store.js";
import { createGatewayClient } from "./gateway_client.js";
import { launchNativeWorker, type NativeWorkerReceipt } from "./native_worker.js";
import { captureRuntimeContract, gitChildHardening, RuntimeConfigError } from "./runtime_config.js";
import { inspectRequiredJailLauncher } from "../infra/required_project_jail.js";
import { describeRepositoryReadiness, inspectRepositoryReadiness, prepareRepositoryWorkspace } from "../solve/repository_prerequisites.js";
import { materializeRepository, spineMaterializationJournal } from "../git/repository_materializer.js";
import { Spine } from "../spine/spine.js";
import { FileSpineStore } from "../spine/store.js";
import { FileSystemLock } from "../lock/lock.js";
import { SchemaRegistry } from "../spine/upcaster.js";
import { FileWitnessSink } from "../spine/witness_sink.js";

interface InstanceProfile { readonly schema: "keep.instance/v1"; readonly environment: Record<string, string>; }
const PROFILE = "instance.json";
const CURRENT = "current-worker.json";
const PENDING = "startup-pending.json";
const FIELDS = new Set(["KEEP_OPENCLAW_CLIENT_PROFILE", "KEEP_PROVIDER", "KEEP_DATA_DIR", "KEEP_REPOSITORY", "KEEP_WORKSPACE_BASE", "KEEP_REVISION", "KEEP_REPO_REF", "KEEP_BASE_BRANCH", "KEEP_TEST_COMMAND", "KEEP_TEST_ARGS_JSON", "KEEP_TEST_NAMESPACE_JAIL", "KEEP_TEST_JAIL_EXECUTABLE", "KEEP_PROJECT_MODEL", "KEEP_CODEX_PROCESSING", "KEEP_CODEX_EXECUTABLE", "KEEP_CODEX_MODEL", "KEEP_CODEX_MAX_INVOCATIONS", "KEEP_CODEX_MAX_PROMPT_BYTES", "KEEP_CODEX_MAX_OUTPUT_BYTES", "KEEP_CODEX_TIMEOUT_MS"]);
const CODEX_FIELDS = [...FIELDS].filter(key => key === "KEEP_PROJECT_MODEL" || key.startsWith("KEEP_CODEX_"));
const INIT_SETTINGS: Readonly<Record<string, string>> = {
  "test-prerequisites": "KEEP_TEST_PREREQUISITES_JSON", "workspace-preparation": "KEEP_WORKSPACE_PREPARATION", "workspace-toolchain": "KEEP_WORKSPACE_TOOLCHAIN",
  "project-model": "KEEP_PROJECT_MODEL", "codex-processing": "KEEP_CODEX_PROCESSING", "codex-executable": "KEEP_CODEX_EXECUTABLE",
  "codex-model": "KEEP_CODEX_MODEL", "codex-max-invocations": "KEEP_CODEX_MAX_INVOCATIONS", "codex-max-prompt-bytes": "KEEP_CODEX_MAX_PROMPT_BYTES",
  "codex-max-output-bytes": "KEEP_CODEX_MAX_OUTPUT_BYTES", "codex-timeout-ms": "KEEP_CODEX_TIMEOUT_MS",
  "test-namespace-jail": "KEEP_TEST_NAMESPACE_JAIL", "test-jail-executable": "KEEP_TEST_JAIL_EXECUTABLE",
};
for (const field of Object.values(INIT_SETTINGS)) FIELDS.add(field);
const within = (parent: string, child: string): boolean => child === parent || child.startsWith(parent + sep);

function generationSetup(profile: InstanceProfile): string {
  const env = profile.environment;
  if (!env.KEEP_PROJECT_MODEL) return "Generation is not configured. The local stub will start with dispatch paused.";
  return `Codex selected; model=${env.KEEP_CODEX_MODEL}; executable=${env.KEEP_CODEX_EXECUTABLE ?? "runtime PATH selection"}\nSaved caller limits: invocations=${env.KEEP_CODEX_MAX_INVOCATIONS}; prompt bytes=${env.KEEP_CODEX_MAX_PROMPT_BYTES}; captured output bytes=${env.KEEP_CODEX_MAX_OUTPUT_BYTES}; timeout ms=${env.KEEP_CODEX_TIMEOUT_MS}\nGeneration qualification is separate. Profile edits apply after an owned stop/start.\nRestricted client profile: ${env.KEEP_OPENCLAW_CLIENT_PROFILE ?? "not issued"}`;
}

function checkSetup(profile: InstanceProfile): string {
  const env = profile.environment;
  const workspace = join(env.KEEP_WORKSPACE_BASE!, env.KEEP_REPO_REF!);
  let prerequisites: string[];
  try { prerequisites = JSON.parse(env.KEEP_TEST_PREREQUISITES_JSON ?? "[]") as string[]; }
  catch { return "Repository check prerequisites are malformed; correct KEEP_TEST_PREREQUISITES_JSON in the saved profile."; }
  return describeRepositoryReadiness(inspectRepositoryReadiness(env.KEEP_REPOSITORY!, existsSync(workspace) ? workspace : undefined,
    { command: env.KEEP_TEST_COMMAND!, args: JSON.parse(env.KEEP_TEST_ARGS_JSON ?? "[]") as string[] }, { prerequisites, ...(env.KEEP_WORKSPACE_PREPARATION ? { preparation: true } : {}) }));
}

function inspectSetup(environment: Record<string, string>): void {
  let contract: ReturnType<typeof captureRuntimeContract>;
  try {
    contract = captureRuntimeContract(runtimeEnvironment({ schema: "keep.instance/v1", environment }), { cwd: process.cwd() }, { projectRequired: true });
  } catch (error) {
    if (error instanceof RuntimeConfigError) {
      const flag = Object.entries(INIT_SETTINGS).find(([, field]) => field === error.field)?.[0];
      if (error.field === "KEEP_CODEX_EXECUTABLE") throw new Error(`${error.message}. Select an existing compatible native engine with --codex-executable=/absolute/path and sign in using that engine's login command before retrying.`);
      if (error.field === "KEEP_PROJECT_MODEL" && environment.KEEP_PROJECT_MODEL === "codex" && environment.KEEP_CODEX_PROCESSING !== "owner-public-repository")
        throw new Error(`${error.message}. Select --codex-processing=owner-public-repository only for an authorized public repository.`);
      if (flag) throw new Error(`${error.message}. Correct --${flag}=<value> and retry init.`);
      throw error;
    }
    if ((error as Error).message === "invalid owner Codex project descriptor" || (error as Error).name === "CodexAccountError")
      throw new Error("Incompatible Codex version, model or caller limits. Select an engine reporting codex-cli <version> with --codex-executable, a supported --codex-model, positive safe-integer caller limits and --codex-timeout-ms no greater than 2147483647.");
    // Native probe failures may contain account diagnostics; retain only corrective setup guidance.
    if (environment.KEEP_PROJECT_MODEL === "codex")
      throw new Error("Codex metadata inspection failed. Select an executable compatible native engine with --codex-executable=/absolute/path and verify its --version and login status locally before retrying.");
    throw error;
  }
  if (contract.installedProject!.testCommand.namespaceJail === "required") {
    try { inspectRequiredJailLauncher(contract.installedProject!.testCommand.jailExecutable); }
    catch { throw new Error("Required jail helper is absent or untrusted. Select the qualified root-owned helper with --test-namespace-jail=required --test-jail-executable=/absolute/protected/path. No helper was installed or executed."); }
  }
}

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
  const fd = openSync(temporary, "wx", 0o600);
  try { writeFileSync(fd, JSON.stringify(value, null, 2) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temporary, path);
  if (process.platform !== "win32") {
    const directory = openSync(resolve(path, ".."), "r");
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
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
  if (!action || !["init", "prepare", "client-issue", "start", "status", "projects", "stop"].includes(action) || !directoryArg || directoryArg.startsWith("--")) {
    write("Usage: keep instance init <directory> --repository=<path> --test-command=<executable> [--test-args=<JSON>] [--branch=<branch>]\n       Codex: --project-model=codex --codex-processing=owner-public-repository --codex-executable=<absolute-path> --codex-model=<model> --codex-max-invocations=N --codex-max-prompt-bytes=N --codex-max-output-bytes=N --codex-timeout-ms=N\n       Helpers: --test-namespace-jail=required|best-effort|off [--test-jail-executable=<absolute-path>]\n       Prerequisites: --test-prerequisites=<JSON-path-array> [--workspace-preparation=npm-offline --workspace-toolchain=<absolute-node-distribution>]\n       keep instance prepare <directory>\n       keep instance client-issue <directory> --profile=<absolute-path> --token-file=<absolute-path> --agent-id=<id> --expires-at=<ISO-date>\n       keep instance start <directory> [--port=N] [--paused]\n       keep instance status|projects|stop <directory>"); return 2;
  }
  try {
    if (action === "init") {
      const allowed = ["repository", "test-command", "test-args", "branch", ...Object.keys(INIT_SETTINGS)];
      if (options.some(option => !allowed.some(name => option.startsWith(`--${name}=`))) || new Set(options.map(option => option.split("=")[0])).size !== options.length) throw new Error("init accepts each documented --name=value option once; see keep instance for usage");
      const option = (name: string) => options.find(value => value.startsWith(`--${name}=`))?.slice(name.length + 3);
      if (!option("repository") || !option("test-command")) throw new Error("init requires --repository=<path> and --test-command=<executable>");
      const repository = realpathSync(resolve(option("repository")!));
      const hardening = gitChildHardening(process.platform, process.env);
      const git = (args: string[]) => execFileSync("git", [...hardening.configArgs, "-C", repository, ...args], { encoding: "utf8", env: hardening.env, timeout: 5000, maxBuffer: 65536, stdio: ["ignore", "pipe", "pipe"] }).trim();
      const branch = option("branch") ?? git(["symbolic-ref", "--short", "HEAD"]);
      const revision = git(["rev-parse", "--verify", "--end-of-options", `${branch}^{commit}`]);
      const requested = resolve(directoryArg);
      if (existsSync(requested)) throw new Error("instance directory already exists; use its saved profile or choose a new directory");
      const canonicalParent = realpathSync(resolve(requested, ".."));
      const directory = join(canonicalParent, basename(requested));
      if (within(repository, directory) || within(directory, repository)) throw new Error("instance directory and source repository must be disjoint; choose a new instance directory outside the repository");
      const testArgs = JSON.parse(option("test-args") ?? "[]") as unknown;
      if (!Array.isArray(testArgs) || testArgs.some(value => typeof value !== "string")) throw new Error("test-args must be a JSON array of strings");
      const environment: Record<string, string> = { KEEP_PROVIDER: "local", KEEP_DATA_DIR: join(directory, "data"), KEEP_REPOSITORY: repository,
        KEEP_WORKSPACE_BASE: join(directory, "workspaces"), KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_BASE_BRANCH: branch,
        KEEP_TEST_COMMAND: option("test-command")!, KEEP_TEST_ARGS_JSON: JSON.stringify(testArgs) };
      for (const key of [...CODEX_FIELDS, "KEEP_OPENCLAW_CLIENT_PROFILE", "KEEP_TEST_PREREQUISITES_JSON", "KEEP_WORKSPACE_PREPARATION", "KEEP_WORKSPACE_TOOLCHAIN"]) if (process.env[key] !== undefined) environment[key] = process.env[key]!;
      if (process.env.KEEP_TEST_NAMESPACE_JAIL !== undefined) environment.KEEP_TEST_NAMESPACE_JAIL = process.env.KEEP_TEST_NAMESPACE_JAIL;
      if (process.env.KEEP_TEST_JAIL_EXECUTABLE !== undefined) environment.KEEP_TEST_JAIL_EXECUTABLE = process.env.KEEP_TEST_JAIL_EXECUTABLE;
      for (const [name, field] of Object.entries(INIT_SETTINGS)) if (option(name) !== undefined) environment[field] = option(name)!;
      if (options.some(value => value.startsWith("--codex-") || value.startsWith("--project-model=")) && !environment.KEEP_CODEX_EXECUTABLE)
        throw new Error("Select an existing compatible native engine with --codex-executable=/absolute/path; the bundled generation engine may be selected from its installation path.");
      mkdirSync(directory, { mode: 0o700 });
      try {
        mkdirSync(join(directory, "data"), { mode: 0o700 });
        mkdirSync(join(directory, "workspaces"), { mode: 0o700 });
        inspectSetup(environment);
        writePrivate(join(directory, PROFILE), { schema: "keep.instance/v1", environment });
      } catch (error) {
        // Remove only our empty setup directories, preserving any unexpected contents.
        for (const path of [join(directory, "workspaces"), join(directory, "data"), directory]) try { rmdirSync(path); } catch { /* retain nonempty or changed state for inspection */ }
        throw error;
      }
      write(`Instance saved: ${directory}\nRepository: ${repository}@${revision}\nStart: keep instance start ${directory}\n${generationSetup({ schema: "keep.instance/v1", environment })}`);
      return 0;
    }
    const directory = privateDirectory(resolve(directoryArg));
    if (action !== "start" && action !== "client-issue" && options.length) throw new Error(`${action} accepts only the instance directory`);
    const lock = join(directory, ".control-lock");
    try { mkdirSync(lock, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("another instance control is in progress; inspect this instance before retrying"); throw error; }
    try {
      const profile = profileAt(directory);
      if (action === "client-issue") {
        const fields = new Map<string, string>();
        for (const option of options) {
          const match = /^--(profile|token-file|agent-id|expires-at)=(.+)$/u.exec(option);
          if (!match || option.includes("\0") || fields.has(match[1]!)) throw new Error("client-issue requires each documented option exactly once");
          fields.set(match[1]!, match[2]!);
        }
        if (fields.size !== 4) throw new Error("client-issue requires --profile, --token-file, --agent-id and --expires-at");
        if (profile.environment.KEEP_OPENCLAW_CLIENT_PROFILE !== undefined) throw new Error("This instance already has a client profile binding; inspect or revoke that grant before changing its saved setup. No new client was issued.");
        if (existsSync(join(directory, PENDING))) throw new Error("Previous startup is unresolved; reconcile this instance before issuing a client.");
        if (existsSync(join(directory, CURRENT))) {
          const previous = workerAt(directory);
          if (!existsSync(join(directory, "data", "native-workers", `${previous.workerId}.stopped.json`))) throw new Error("Stop this owned instance before issuing a client; its worker may still be active or unresolved.");
        }
        if (profile.environment.KEEP_PROJECT_MODEL !== "codex") throw new Error("Client issuance requires this instance's saved personal public-repository Codex setup.");
        // Reuse the installed owner issuance path with the exact saved runtime.
        // No shell, ambient KEEP_* settings, credential values or generation call.
        try {
          execFileSync(process.execPath, [fileURLToPath(new URL("../main.js", import.meta.url)), "openclaw-client", "issue", ...options], {
            cwd: directory, env: runtimeEnvironment(profile), stdio: ["ignore", "pipe", "pipe"], maxBuffer: 65_536,
          });
        } catch {
          throw new Error("Client issuance did not confirm success; no profile reference was saved. Inspect the selected private output files and this instance's retained grants before an explicit retry. Verify the saved engine metadata/login status, private output paths, agent ID and future expiry. No account diagnostic or credential value was printed.");
        }
        const clientPath = realpathSync(fields.get("profile")!);
        const client = readRestrictedClientProfile(clientPath);
        if (client.agentId !== fields.get("agent-id") || client.expiresAt !== Date.parse(fields.get("expires-at")!))
          throw new Error("Issued client readback differs; retain the private files and grant for inspection. No profile reference was saved.");
        try {
          writePrivate(join(directory, PROFILE), { ...profile, environment: { ...profile.environment, KEEP_OPENCLAW_CLIENT_PROFILE: clientPath } });
        } catch {
          throw new Error("Client was issued but saving its instance reference was not confirmed. Preserve the private client files and grant; inspect instance.json before any retry. No new instance or allowance was created.");
        }
        write(`Restricted client issued and saved for this instance. Profile: ${clientPath}\nPrivate plugin credential file: ${fields.get("token-file")}\nStart: keep instance start ${directory}\n${generationSetup(profileAt(directory))}`);
        return 0;
      }
      if (action === "prepare") {
        if (existsSync(join(directory, PENDING))) throw new Error("Previous startup is unresolved; reconcile this instance before preparing its workspace.");
        if (existsSync(join(directory, CURRENT))) {
          const previous = workerAt(directory);
          if (!existsSync(join(directory, "data", "native-workers", `${previous.workerId}.stopped.json`))) throw new Error("Stop this owned instance before preparing its workspace; active project execution and preparation cannot overlap.");
        }
        const env = profile.environment;
        // Preparation validates repository settings without inspecting or invoking the generation engine.
        const contract = captureRuntimeContract(Object.fromEntries(Object.entries(runtimeEnvironment(profile)).filter(([key]) => key !== "KEEP_PROJECT_MODEL" && !key.startsWith("KEEP_CODEX_"))), { cwd: process.cwd() }, { projectRequired: true });
        const project = contract.installedProject!;
        const spine = new Spine(new FileSpineStore(env.KEEP_DATA_DIR!), new FileSystemLock(join(env.KEEP_DATA_DIR!, ".locks")), new SchemaRegistry(), undefined, new FileWitnessSink(env.KEEP_DATA_DIR!));
        const report = await spine.withCoordinationLock("repository.materialization", async () => {
          const materialized = await materializeRepository({ sourceDir: project.repository.root, workspaceBase: project.workspaceBase.root, repoRef: project.repoRef, commit: project.revision, baseBranch: project.baseBranch }, undefined, spineMaterializationJournal(spine));
          let result;
          try { result = await prepareRepositoryWorkspace(project.repository.root, materialized.projectDir, project.testCommand, project.repositoryCheckSetup ?? { prerequisites: [] }); }
          catch (error) { throw new Error(`Owned workspace: ${materialized.projectDir}\n${(error as Error).message}`); }
          spine.stage({ type: "identity.action", actor: "repository-preparation", payload: { event: "repository.prepared", workspace: materialized.projectDir, commit: materialized.commit,
            checker: project.testCommand.command, args: project.testCommand.args, preparation: project.repositoryCheckSetup?.preparation ?? null } });
          await spine.seal();
          return result;
        });
        write(`Owned workspace: ${join(project.workspaceBase.root, project.repoRef)}\n${describeRepositoryReadiness(report)}`); return 0;
      }
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
      if (action === "status" && !existsSync(join(directory, CURRENT))) {
        write(`Keep has no acknowledged worker. ${existsSync(join(directory, PENDING)) ? "Previous startup is unresolved; inspect this instance's data/native-workers before another launch." : `Start: keep instance start ${directory}`}\nState: ${profile.environment.KEEP_DATA_DIR}\nSaved generation setup: ${generationSetup(profile)}\n${checkSetup(profile)}`);
        return existsSync(join(directory, PENDING)) ? 1 : 0;
      }
      const worker = workerAt(directory);
      if (existsSync(join(directory, "data", "native-workers", `${worker.workerId}.stopped.json`))) {
        write(`Keep is stopped. State retained: ${profile.environment.KEEP_DATA_DIR}\nStart: keep instance start ${directory}\nSaved generation setup: ${generationSetup(profile)}\n${checkSetup(profile)}`); return action === "projects" ? 1 : 0;
      }
      const current = await status(directory, worker);
      if (action === "status") write(`Keep is running: ${worker.origin}\nConsole: ${worker.origin}/console\nSign-in credential file (private): ${join(directory, "data", "gateway-token")}\nWorker: ${worker.workerId}\nDispatch: ${String(current.state)}\nState: ${profile.environment.KEEP_DATA_DIR}\nSaved generation setup: ${generationSetup(profile)}\n${checkSetup(profile)}`);
      else if (action === "projects") write(JSON.stringify(await request(directory, worker, "GET", "/projects"), null, 2));
      else {
        await request(directory, worker, "POST", "/worker/stop", { workerId: worker.workerId });
        write(`Stop accepted for worker ${worker.workerId}. State retained: ${profile.environment.KEEP_DATA_DIR}\nStatus: keep instance status ${directory}`);
      }
      return 0;
    } finally { rmdirSync(lock); }
  } catch (error) { write(`Instance ${action} failed: ${(error as Error).message}`); return 1; }
}
