import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

import { GraphLocalizer } from "../coderag/graph_localizer.js";
import { HierarchicalLocalizer, type Localizer, type RepoFile } from "../solve/localize.js";
import type { Workspace } from "../solve/workspace.js";
import type { ProjectState } from "./project_loop.js";

export interface ProjectLocalizationArtifact {
  readonly schemaVersion: 1;
  readonly disposition: "localized" | "no-readable-files" | "no-candidates";
  readonly repositoryRef: string;
  readonly repositoryTreeSha256: string;
  readonly inspectedFiles: number;
  readonly inspectedBytes: number;
  readonly stages: readonly string[];
  readonly selected: readonly {
    readonly path: string;
    readonly contentSha256: string;
    readonly score: number;
    readonly isTest: boolean;
    readonly suspectSymbols: readonly string[];
    readonly reason: string;
  }[];
}

const MAX_FILES = 100_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_PATH_BYTES = 16 * 1024;
const LOCALIZATION_STAGES = new Set(["bm25", "graph", "embedding", "llm-rerank"]);

function byteOrder(a: RepoFile, b: RepoFile): number { return a.path < b.path ? -1 : a.path > b.path ? 1 : 0; }

/** Canonical content identity shared by localization, edit admission, and pre-effect rechecks. */
export function projectRepositoryTreeSha256(files: readonly RepoFile[]): string {
  const tree = createHash("sha256");
  for (const file of [...files].sort(byteOrder)) {
    const digest = createHash("sha256").update(Buffer.from(file.content, "utf8")).digest("hex");
    tree.update(String(Buffer.byteLength(file.path, "utf8"))).update(":").update(file.path).update(":").update(digest);
  }
  return tree.digest("hex");
}

function validateFiles(input: readonly RepoFile[]): readonly RepoFile[] {
  if (input.length > MAX_FILES) throw new Error(`configured repository exceeds the ${MAX_FILES}-file localization bound`);
  const seen = new Set<string>();
  let total = 0;
  const files = [...input].sort(byteOrder);
  for (const file of files) {
    if (typeof file.path !== "string" || file.path.length === 0 || file.path.includes("\0")
      || file.path.includes("\\") || Buffer.byteLength(file.path, "utf8") > MAX_PATH_BYTES || isAbsolute(file.path)
      || file.path.split("/").some((part) => part === "." || part === ".." || part.length === 0)) {
      throw new Error(`workspace returned an unsafe or non-canonical project path: ${String(file.path)}`);
    }
    if (seen.has(file.path)) throw new Error(`workspace returned duplicate project path: ${file.path}`);
    seen.add(file.path);
    if (typeof file.content !== "string") throw new Error(`workspace returned non-text project content: ${file.path}`);
    const bytes = Buffer.byteLength(file.content, "utf8");
    if (bytes > MAX_FILE_BYTES) throw new Error(`project file exceeds the ${MAX_FILE_BYTES}-byte localization bound: ${file.path}`);
    total += bytes;
    if (!Number.isSafeInteger(total) || total > MAX_TOTAL_BYTES) throw new Error(`configured repository exceeds the ${MAX_TOTAL_BYTES}-byte localization bound`);
  }
  return files;
}

/** Read-only project localization. Durable output contains identities and digests, never repository file bytes. */
export async function localizeProjectRepository(
  state: ProjectState,
  workspace: Workspace,
  repositoryRef: string,
  localizer?: Localizer,
  topK = 3,
): Promise<ProjectLocalizationArtifact> {
  if (repositoryRef.length === 0 || Buffer.byteLength(repositoryRef, "utf8") > MAX_PATH_BYTES) throw new Error("repositoryRef must be bounded non-empty text");
  if (!Number.isSafeInteger(topK) || topK < 1 || topK > 20) throw new Error("localization topK must be an integer from 1 to 20");
  const files = validateFiles(await workspace.files(repositoryRef, { maxFiles: MAX_FILES, maxFileBytes: MAX_FILE_BYTES, maxTotalBytes: MAX_TOTAL_BYTES }));
  let inspectedBytes = 0;
  const contentDigests = new Map<string, string>();
  for (const file of files) {
    const bytes = Buffer.from(file.content, "utf8");
    inspectedBytes += bytes.length;
    const digest = createHash("sha256").update(bytes).digest("hex");
    contentDigests.set(file.path, digest);
  }
  if (files.length === 0) return artifact("no-readable-files", [], []);
  const explicitlyNamed = files.filter((file) => state.goal.includes(file.path)).map((file) => ({ path: file.path, score: Number.MAX_SAFE_INTEGER, isTest: /(?:^|\/)(?:test|tests|__tests__)(?:\/|$)|(?:\.test|\.spec)\.[^.]+$/u.test(file.path), suspectSymbols: [] as string[] }));
  // Exact existing paths already identify the requested edit neighborhood. Use
  // deterministic retrieval for backfill; preserve full graph discovery for unnamed
  // tasks and never override an explicitly configured localizer.
  const result = await (localizer ?? (explicitlyNamed.length > 0 ? new HierarchicalLocalizer() : new GraphLocalizer())).localize({ id: state.runId, text: state.goal, repoRef: repositoryRef }, files, topK);
  if (!Array.isArray(result.stages) || result.stages.length === 0 || result.stages.length > LOCALIZATION_STAGES.size
    || new Set(result.stages).size !== result.stages.length
    || result.stages.some((stage) => typeof stage !== "string" || !LOCALIZATION_STAGES.has(stage))) {
    throw new Error("localizer returned an invalid stage trace");
  }
  if (!Array.isArray(result.suspects)) throw new Error("localizer returned invalid candidates");
  if (result.suspects.length > topK) throw new Error("localizer returned more candidates than requested");
  const suspects = [...explicitlyNamed, ...result.suspects.filter((suspect) => !explicitlyNamed.some((named) => named.path === suspect.path))].slice(0, topK);
  if (suspects.length === 0) return artifact("no-candidates", result.stages, []);
  const selectedPaths = new Set<string>();
  const selected = suspects.map((suspect, index) => {
    if (suspect === null || typeof suspect !== "object" || typeof suspect.path !== "string") throw new Error("localizer returned an invalid candidate");
    const contentSha256 = contentDigests.get(suspect.path);
    if (contentSha256 === undefined) throw new Error(`localizer returned a path outside the inspected repository: ${suspect.path}`);
    if (selectedPaths.has(suspect.path)) throw new Error(`localizer returned duplicate candidate path: ${suspect.path}`);
    selectedPaths.add(suspect.path);
    if (!Number.isFinite(suspect.score) || suspect.score < 0) throw new Error(`localizer returned an invalid score for ${suspect.path}`);
    if (typeof suspect.isTest !== "boolean") throw new Error(`localizer returned an invalid test classification for ${suspect.path}`);
    const symbols = suspect.suspectSymbols ?? [];
    if (!Array.isArray(symbols) || symbols.length > 32 || new Set(symbols).size !== symbols.length
      || symbols.some((symbol) => typeof symbol !== "string" || Buffer.byteLength(symbol, "utf8") > 256
        || !/^[\p{ID_Start}_$][\p{ID_Continue}.$:#-]*$/u.test(symbol))) {
      throw new Error(`localizer returned invalid suspect symbols for ${suspect.path}`);
    }
    return Object.freeze({
      path: suspect.path,
      contentSha256,
      score: suspect.score,
      isTest: suspect.isTest,
      suspectSymbols: Object.freeze([...symbols]),
      reason: `rank ${index + 1} from ${result.stages.join(" + ")} retrieval at score ${suspect.score}${suspect.isTest ? "; test file was down-weighted" : ""}`,
    });
  });
  return artifact("localized", result.stages, selected);

  function artifact(
    disposition: ProjectLocalizationArtifact["disposition"],
    stages: readonly string[],
    selected: ProjectLocalizationArtifact["selected"],
  ): ProjectLocalizationArtifact {
    return Object.freeze({
      schemaVersion: 1,
      disposition,
      repositoryRef,
      repositoryTreeSha256: projectRepositoryTreeSha256(files),
      inspectedFiles: files.length,
      inspectedBytes,
      stages: Object.freeze([...stages]),
      selected: Object.freeze([...selected]),
    });
  }
}
