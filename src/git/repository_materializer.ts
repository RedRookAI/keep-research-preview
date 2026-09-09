/** Materialize one exact local Git revision into a confined workspace directory. */
import { execFile } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { GitAdapter } from "../infra/git_adapter.js";
import { installedEffectAdmission, INSTALLED_EFFECT_OWNERS, type InstalledEffectAdmission } from "../control/installed_effect_admission.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "./pinned_remote.js";
import { gitChildHardening } from "../cli/runtime_config.js";
import type { Spine } from "../spine/spine.js";

export interface DevelopmentForgeTarget {
  readonly remote: string;
  readonly fetchUrl: string;
  readonly pushUrl: string;
  readonly expectedFetchUrlSha256: string;
  readonly expectedPushUrlSha256: string;
}

const execFileAsync = promisify(execFile);

export interface MaterializeRepositoryRequest {
  readonly sourceDir: string;
  readonly workspaceBase: string;
  readonly repoRef: string;
  readonly commit: string;
  readonly baseBranch?: string;
  /** Optional private development forge. Exact URLs are pinned before they are installed in the clone. */
  readonly developmentForge?: DevelopmentForgeTarget;
}

export interface MaterializedRepository {
  readonly repoRef: string;
  readonly projectDir: string;
  readonly commit: string;
  readonly baseBranch: string;
}

export interface MaterializationRecord { readonly sourceDir: string; readonly workspaceBase: string; readonly repoRef: string; readonly commit: string; readonly baseBranch: string; }
export interface MaterializationJournal { load(workspaceBase: string, repoRef: string): MaterializationRecord | undefined; save(record: MaterializationRecord): Promise<void>; }

export function spineMaterializationJournal(spine: Spine): MaterializationJournal {
  return {
    load: (workspaceBase, repoRef) => {
      const rows = spine.replay().filter((event) => event.type === "identity.action" && event.actor === "repository-materializer" && event.payload["event"] === "repository.materialized" && event.payload["workspaceBase"] === workspaceBase && event.payload["repoRef"] === repoRef);
      if (rows.length === 0) return undefined;
      const payload = rows.at(-1)!.payload;
      if (typeof payload["sourceDir"] !== "string" || typeof payload["commit"] !== "string") return undefined;
      const baseBranch = payload["baseBranch"] === undefined ? "main" : payload["baseBranch"];
      if (typeof baseBranch !== "string") return undefined;
      return { sourceDir: payload["sourceDir"], workspaceBase, repoRef, commit: payload["commit"], baseBranch };
    },
    save: async (record) => { spine.stage({ type: "identity.action", actor: "repository-materializer", payload: { event: "repository.materialized", ...record } }); await spine.seal(); },
  };
}

function confined(base: string, candidate: string): boolean {
  const rel = relative(base, candidate);
  return rel !== "" && !rel.startsWith("..") && !rel.startsWith(sep);
}

/**
 * Clone from an operator-selected local repository and check out exactly the requested commit.
 * The destination must be new, and the returned commit is re-read from the materialized tree.
 */
export async function materializeRepository(req: MaterializeRepositoryRequest, effectAdmission: InstalledEffectAdmission = installedEffectAdmission, journal?: MaterializationJournal): Promise<MaterializedRepository> {
  effectAdmission.admit(INSTALLED_EFFECT_OWNERS.repositoryMaterialize.id);
  if (req.developmentForge) {
    const forge = req.developmentForge;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(forge.remote)) throw new Error("development forge remote name is not canonical");
    if (pinnedRemoteFetchUrlSha256(forge.fetchUrl) !== forge.expectedFetchUrlSha256 || pinnedRemoteUrlSha256(forge.pushUrl) !== forge.expectedPushUrlSha256) {
      throw new Error("development forge URL does not match its operator-pinned digest");
    }
  }
  mkdirSync(req.workspaceBase, { recursive: true });
  const workspaceBase = realpathSync(req.workspaceBase);
  const sourceDir = realpathSync(req.sourceDir);
  const projectDir = resolve(workspaceBase, req.repoRef);
  if (!confined(workspaceBase, projectDir) || basename(projectDir) === ".git") {
    throw new Error(`repoRef escapes or aliases repository metadata: ${req.repoRef}`);
  }
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(req.commit)) throw new Error("materialization requires one exact commit id");
  const baseBranch = req.baseBranch ?? "main";
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(baseBranch) || baseBranch.includes("..")) {
    throw new Error("materialization base branch is not canonical");
  }

  const source = new GitAdapter(sourceDir, effectAdmission);
  const resolvedCommit = (await source.git(["rev-parse", "--verify", `${req.commit}^{commit}`])).stdout.trim();
  if (resolvedCommit !== req.commit) throw new Error("requested commit does not resolve to itself");

  if (existsSync(projectDir)) {
    if (!journal) throw new Error(`materialization destination already exists without a durable provenance record: ${req.repoRef}`);
    const record = journal.load(workspaceBase, req.repoRef);
    if (!record || record.sourceDir !== sourceDir || record.commit !== req.commit || record.baseBranch !== baseBranch) throw new Error("existing materialization does not match its durable provenance record");
    if (!lstatSync(projectDir).isDirectory()) throw new Error("existing materialization must be a real directory, not a link");
    const canonicalProject = realpathSync(projectDir);
    if (!confined(workspaceBase, canonicalProject) || !lstatSync(join(canonicalProject, ".git")).isDirectory()) throw new Error("existing materialization escapes confinement or redirects Git metadata");
    const git = new GitAdapter(canonicalProject, effectAdmission);
    const [head, origin, admitted] = await Promise.all([git.head(), git.git(["config", "--get", "remote.origin.url"]), git.git(["rev-parse", "--verify", `${req.commit}^{commit}`])]);
    let canonicalOrigin: string; try { canonicalOrigin = realpathSync(origin.stdout.trim()); } catch { throw new Error("existing materialization origin is not the captured source repository"); }
    if (canonicalOrigin !== sourceDir || head !== req.commit || admitted.stdout.trim() !== req.commit) throw new Error("existing materialization Git identity does not match the admitted source and revision");
    return Object.freeze({ repoRef: req.repoRef, projectDir: canonicalProject, commit: req.commit, baseBranch });
  }

  const hardening = gitChildHardening(process.platform, process.env);
  await execFileAsync("git", [...hardening.configArgs, "clone", "--no-checkout", "--", sourceDir, projectDir], {
    env: hardening.env,
    maxBuffer: 32 * 1024 * 1024,
  });
  const git = new GitAdapter(projectDir, effectAdmission);
  // A clone may create the remote's default branch even with --no-checkout. The destination is
  // guaranteed new above, so resetting that unborn/unpublished local ref is unambiguous.
  await git.git(["checkout", "-B", baseBranch, resolvedCommit]);
  const observed = await git.head();
  if (observed !== resolvedCommit || !(await git.isClean())) throw new Error("materialized repository identity verification failed");
  if (req.developmentForge) {
    const forge = req.developmentForge;
    await git.git(["config", `remote.${forge.remote}.url`, forge.fetchUrl]);
    await git.git(["config", `remote.${forge.remote}.pushurl`, forge.pushUrl]);
  }
  await journal?.save(Object.freeze({ sourceDir, workspaceBase, repoRef: req.repoRef, commit: observed, baseBranch }));
  return Object.freeze({ repoRef: req.repoRef, projectDir, commit: observed, baseBranch });
}
