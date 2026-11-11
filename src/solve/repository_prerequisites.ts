/** Read-only repository readiness and explicitly requested, offline workspace preparation. */
import { createHash } from "node:crypto";
import { closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { delimiter, isAbsolute, join, sep } from "node:path";
import { SandboxedCommandRunner } from "./sandboxed_runner.js";
import type { TestRunner } from "./validate.js";
import type { CapturedTestCommand } from "../cli/runtime_config.js";
import { GitAdapter } from "../infra/git_adapter.js";

export interface WorkspacePreparation {
  readonly mode: "npm-offline";
  readonly toolchainRoot: string;
  readonly node: string;
  readonly nodeSha256: string;
  readonly npmCli: string;
  readonly npmCliSha256: string;
}
export interface RepositoryCheckSetup {
  readonly prerequisites: readonly string[];
  readonly preparation?: WorkspacePreparation;
}
export interface RepositoryReadiness {
  readonly ready: boolean;
  readonly command: { readonly executable: string; readonly args: readonly string[] };
  readonly packageManager?: string;
  readonly lockfile?: string;
  readonly missing: readonly string[];
  readonly nextAction?: string;
}
const inside = (root: string, path: string) => path === root || path.startsWith(root + sep);
const hash = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const preparationHold = (workspace: string) => join(workspace, ".git", "keep-preparation-hold.json");
const trackedState = async (git: GitAdapter) => [await git.head(), (await git.git(["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--"])).stdout];
const stateDigest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const PENDING_INTEGRITY = "workspace preparation integrity is pending or unresolved";
function recordPreparationIntent(workspace: string, beforeWorkspace: unknown, beforeSource: unknown): void {
  const fd = openSync(preparationHold(workspace), "wx", 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ trackedStateSha256: stateDigest(beforeWorkspace), sourceStateSha256: stateDigest(beforeSource) }));
    fsyncSync(fd);
  } finally { closeSync(fd); }
  const directory = openSync(join(workspace, ".git"), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
}
export function validatePrerequisitePaths(paths: readonly string[]): void {
  if (paths.length > 128 || paths.some(path => typeof path !== "string" || path.length > 1024 || !path || path.includes("\0") || path.includes("\\") || isAbsolute(path)
    || path.split("/").some(part => !part || part === "." || part === ".." || part === ".git"))) throw new Error("prerequisites must be bounded repository-relative paths without traversal or .git");
}
export function captureWorkspacePreparation(root: string, repository: string, workspaceBase: string): WorkspacePreparation {
  if (!isAbsolute(root)) throw new Error("workspace toolchain must be an absolute existing Node distribution root");
  const toolchainRoot = realpathSync(root);
  if ([repository, workspaceBase].some(path => inside(path, toolchainRoot) || inside(toolchainRoot, path))) throw new Error("workspace toolchain must be disjoint from repository and workspaces");
  const node = realpathSync(join(toolchainRoot, "bin", "node")), npmCli = realpathSync(join(toolchainRoot, "lib", "node_modules", "npm", "bin", "npm-cli.js"));
  if (![node, npmCli].every(path => inside(toolchainRoot, path) && lstatSync(path).isFile()) || !(lstatSync(node).mode & 0o111)) throw new Error("selected Node/npm files must remain inside the selected toolchain");
  return Object.freeze({ mode: "npm-offline", toolchainRoot, node, npmCli, nodeSha256: hash(node), npmCliSha256: hash(npmCli) });
}

function present(root: string, path: string): boolean {
  try {
    const candidate = join(root, path);
    const stat = lstatSync(candidate);
    return (stat.isFile() || stat.isDirectory()) && inside(realpathSync(root), realpathSync(candidate));
  } catch { return false; }
}

/** Metadata is inspected in source only until the owned workspace exists. Source dependencies are never copied. */
export function inspectRepositoryReadiness(repository: string, workspace: string | undefined,
  command: { readonly command: string; readonly args: readonly string[] }, setup: Pick<RepositoryCheckSetup, "prerequisites"> & { readonly preparation?: unknown } = { prerequisites: [] }): RepositoryReadiness {
  validatePrerequisitePaths(setup.prerequisites);
  const root = workspace ?? repository;
  const missing: string[] = [];
  if (workspace && (!lstatSync(workspace).isDirectory() || lstatSync(workspace).isSymbolicLink())) throw new Error("Owned workspace must be a real directory; inspect its materialization before retrying.");
  const preparationUnresolved = workspace !== undefined && existsSync(preparationHold(workspace));
  if (preparationUnresolved) missing.push(PENDING_INTEGRITY);
  let packageManager: string | undefined, lockfile: string | undefined, hasDependencies = false;
  let dependencyPaths: string[] = [];
  try {
    const packageFile = join(root, "package.json");
    if (existsSync(packageFile)) {
      const stat = lstatSync(packageFile);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) throw new Error();
      const pkg = JSON.parse(readFileSync(packageFile, "utf8")) as Record<string, unknown>;
      if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) throw new Error();
      packageManager = typeof pkg.packageManager === "string" ? pkg.packageManager.slice(0, 128) : "npm (inferred)";
      const dependencies = [...new Set([pkg.dependencies, pkg.devDependencies].flatMap(value => value && typeof value === "object" ? Object.keys(value) : []))];
      if (dependencies.some(name => !/^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9_-][A-Za-z0-9._-]*$/u.test(name))) throw new Error();
      hasDependencies = dependencies.length > 0;
      dependencyPaths = dependencies.map(name => `node_modules/${name}/package.json`);
      lockfile = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"].find(path => present(root, path));
    }
  } catch { missing.push("readable regular package.json metadata"); }
  const candidates = isAbsolute(command.command) ? [command.command] : command.command.includes("/") ? [join(root, command.command)] : (process.env.PATH ?? "/usr/bin:/bin").split(delimiter).map(path => join(path, command.command));
  if (!candidates.some(path => { try { const stat = lstatSync(realpathSync(path)); return stat.isFile() && (stat.mode & 0o111) !== 0; } catch { return false; } })) missing.push(`checker executable ${command.command}`);
  const paths = [...new Set([...setup.prerequisites, ...dependencyPaths])];
  for (const path of paths) if (!workspace || !present(root, path)) missing.push(path);
  const ready = missing.length === 0;
  let nextAction: string | undefined;
  if (!ready) {
    if (preparationUnresolved) nextAction = "Inspect the retained preparation and its actual process state. Reconcile source and workspace tracked bytes with their pre-dispatch identities, then explicitly run keep instance prepare again to recheck the hold. Source is never restored automatically.";
    else if (missing.some(path => path.startsWith("checker executable"))) nextAction = "Select an available checker executable or supply that declared checker in the owned workspace, then recheck readiness.";
    else if (packageManager && !packageManager.startsWith("npm@") && packageManager !== "npm (inferred)") nextAction = `Package manager ${packageManager} has no supported automatic preparation recipe. Prepare the named owned workspace with your selected toolchain, then recheck and resume this held project.`;
    else if (hasDependencies && lockfile !== "package-lock.json" && lockfile !== "npm-shrinkwrap.json") nextAction = "npm preparation requires package-lock.json or npm-shrinkwrap.json committed in the selected revision. Supply that revision or prepare the owned workspace explicitly, then recheck.";
    else nextAction = setup.preparation ? "Run keep instance prepare <directory> while this instance is stopped. Supply any needed offline npm cache in workspace/.keep-preparation-cache; network access is denied. Recheck and resume the same held project." : "Prepare the named owned workspace explicitly or select --workspace-preparation=npm-offline --workspace-toolchain=/absolute/node-distribution when configuring an instance, then recheck and resume this held project.";
  }
  return { ready, command: { executable: command.command, args: [...command.args] }, ...(packageManager ? { packageManager } : {}), ...(lockfile ? { lockfile } : {}), missing, ...(nextAction ? { nextAction } : {}) };
}
export function describeRepositoryReadiness(report: RepositoryReadiness): string {
  return `Checker: ${report.command.executable} ${JSON.stringify(report.command.args)}\nPackage manager: ${report.packageManager ?? "not declared"}; lockfile: ${report.lockfile ?? "not present"}\n${report.ready ? "Declared check prerequisites are present; the checker has not been run." : `Missing check prerequisites: ${report.missing.join(", ")}\nNext action: ${report.nextAction}`}`;
}

/** Caller must own the workspace and exclude concurrent project execution before entering this handoff. */
export async function prepareRepositoryWorkspace(repository: string, workspace: string, command: CapturedTestCommand, setup: RepositoryCheckSetup,
  runnerFor: (config: ConstructorParameters<typeof SandboxedCommandRunner>[0]) => TestRunner = config => new SandboxedCommandRunner(config)): Promise<RepositoryReadiness> {
  const hold = preparationHold(workspace);
  if (existsSync(hold)) {
    const stat = lstatSync(hold);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) throw new Error("Preparation hold record is invalid; inspect the retained owned workspace.");
    const prior = JSON.parse(readFileSync(hold, "utf8")) as { trackedStateSha256?: string; sourceStateSha256?: string };
    if (prior.trackedStateSha256 !== stateDigest(await trackedState(new GitAdapter(workspace))) || prior.sourceStateSha256 !== stateDigest(await trackedState(new GitAdapter(repository))))
      throw new Error("Restore the exact tracked source and workspace repository/checker bytes from before preparation, then explicitly run prepare again. Source is never restored automatically.");
    unlinkSync(hold);
  }
  const report = inspectRepositoryReadiness(repository, workspace, command, setup);
  if (report.ready) return report;
  if (report.missing.some(path => path.startsWith("checker executable") || path === "readable regular package.json metadata")) throw new Error(describeRepositoryReadiness(report));
  if (!setup.preparation) throw new Error(describeRepositoryReadiness(report));
  if (report.packageManager && !report.packageManager.startsWith("npm@") && report.packageManager !== "npm (inferred)") throw new Error(report.nextAction);
  if (report.lockfile !== "package-lock.json" && report.lockfile !== "npm-shrinkwrap.json") throw new Error(report.nextAction ?? "npm preparation needs a committed lockfile");
  if (command.namespaceJail !== "required") throw new Error("Workspace preparation requires --test-namespace-jail=required and the qualified helper. No preparation process was started.");
  const p = setup.preparation;
  if (!inside(p.toolchainRoot, p.node) || !inside(p.toolchainRoot, p.npmCli) || hash(p.node) !== p.nodeSha256 || hash(p.npmCli) !== p.npmCliSha256) throw new Error("Selected preparation toolchain changed; inspect it and explicitly reconcile the instance setup before preparation.");
  const workspaceGit = new GitAdapter(workspace), sourceGit = new GitAdapter(repository);
  const beforeWorkspace = await trackedState(workspaceGit), beforeSource = await trackedState(sourceGit);
  // This durable intent precedes factory construction and runner dispatch. Throws,
  // uncertain completion and failed readback retain it until explicit reconciliation.
  recordPreparationIntent(workspace, beforeWorkspace, beforeSource);
  const result = await runnerFor({ command: p.node, args: [p.npmCli, "ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--global=false", "--userconfig=/dev/null", "--globalconfig=/dev/null", `--prefix=${workspace}`, `--cache=${join(workspace, ".keep-preparation-cache")}`],
    projectDir: workspace, namespaceJail: "required", ...(command.jailExecutable ? { jailExecutable: command.jailExecutable } : {}),
    readOnlyPaths: [p.toolchainRoot], allowNet: false, envAllowlist: [], timeoutMs: command.timeoutMs, cpuLimitSec: command.cpuLimitSec, maxOutputBytes: command.maxOutputBytes,
  }).run(".");
  if (JSON.stringify(await trackedState(workspaceGit)) !== JSON.stringify(beforeWorkspace) || JSON.stringify(await trackedState(sourceGit)) !== JSON.stringify(beforeSource)) {
    throw new Error("Preparation changed tracked repository/checker bytes. Preserve this workspace for inspection; no project generation or automatic retry is admitted.");
  }
  const observation = result.processIsolation;
  if (result.runnerError || observation?.namespacePolicy !== "required" || observation.namespaceSetup !== "launcher-confirmed" || observation.basis !== "launcher-status"
    || observation.degraded.length > 0 || !result.results.length || result.results.some(row => !row.passed))
    throw new Error("Offline workspace preparation held. The required helper/setup, selected toolchain or offline dependencies are unavailable, or preparation failed. Inspect the selected helper and workspace cache; network access was not granted. No automatic retry or generation was started.");
  const after = inspectRepositoryReadiness(repository, workspace, command, setup);
  if (after.missing.some(path => path !== PENDING_INTEGRITY)) throw new Error(describeRepositoryReadiness(after));
  unlinkSync(hold);
  const { nextAction: _pendingAction, ...completed } = after;
  return { ...completed, ready: true, missing: [] };
}
