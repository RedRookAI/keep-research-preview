import { createHash } from "node:crypto";
import type { GitAdapter } from "../infra/git_adapter.js";
import { closeSync, constants, existsSync, fstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";

export interface PinnedRemoteTransport {
  readonly remote: string;
  readonly fetchUrl: string;
  readonly fetchUrlSha256: string;
  readonly pushUrl: string;
  readonly pushUrlSha256: string;
}

export function pinnedRemoteUrlSha256(url: string): string {
  return createHash("sha256").update("keep.git-push-url/v1\0").update(url).digest("hex");
}

export function pinnedRemoteFetchUrlSha256(url: string): string {
  return createHash("sha256").update("keep.git-fetch-url/v1\0").update(url).digest("hex");
}

export function assertRemoteName(remote: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(remote)) throw new Error("remote target is not one canonical configured-remote name");
}

/** Resolve repository configuration once, compare it to operator-owned policy, then carry the exact URL to effects. */
export async function resolvePinnedRemoteTransport(
  git: GitAdapter,
  remote: string,
  expectedFetchUrlSha256: string | undefined,
  expectedPushUrlSha256: string | undefined,
): Promise<PinnedRemoteTransport> {
  assertRemoteName(remote);
  if (!/^[0-9a-f]{64}$/u.test(expectedFetchUrlSha256 ?? "")) throw new Error("remote operation requires an operator-pinned fetch URL digest");
  if (!/^[0-9a-f]{64}$/u.test(expectedPushUrlSha256 ?? "")) throw new Error("remote operation requires an operator-pinned push URL digest");
  const fetchUrls = (await git.git(["remote", "get-url", "--all", "--", remote])).stdout.trim().split("\n").filter(Boolean);
  const pushUrls = (await git.git(["remote", "get-url", "--push", "--all", "--", remote])).stdout.trim().split("\n").filter(Boolean);
  if (fetchUrls.length !== 1) throw new Error("configured remote must resolve to one exact fetch URL");
  if (pushUrls.length !== 1) throw new Error("configured remote must resolve to one exact push URL");
  const fetchUrl = fetchUrls[0]!;
  const pushUrl = pushUrls[0]!;
  for (const [label, url] of [["fetch", fetchUrl], ["push", pushUrl]] as const) {
    if (url.length === 0 || url.length > 8192 || url.includes("\0") || !/^(?:https|ssh|file):\/\//u.test(url)) throw new Error(`configured ${label} URL scheme or shape is not explicitly permitted`);
  }
  const fetchUrlSha256 = pinnedRemoteFetchUrlSha256(fetchUrl);
  const pushUrlSha256 = pinnedRemoteUrlSha256(pushUrl);
  if (fetchUrlSha256 !== expectedFetchUrlSha256) throw new Error("configured fetch URL does not equal the operator-pinned transport");
  if (pushUrlSha256 !== expectedPushUrlSha256) throw new Error("configured push URL does not equal the operator-pinned transport");
  return Object.freeze({ remote, fetchUrl, fetchUrlSha256, pushUrl, pushUrlSha256 });
}

/**
 * Network commands consume these exact URL operands, never a configured remote name. Repository URL lists can
 * therefore neither redirect an observation nor fan a push out to additional destinations. The closed control-plane
 * appraisal still refuses url.* rewrite keys immediately before each invocation.
 */
export function pinnedFetchOperand(transport: PinnedRemoteTransport): string { return transport.fetchUrl; }
export function pinnedPushOperand(transport: PinnedRemoteTransport): string { return transport.pushUrl; }

function readStableControlFile(path: string, label: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > 1024 * 1024) throw new Error(`${label} carrier kind or size refused`);
    const text = readFileSync(fd, "utf8");
    const after = fstatSync(fd);
    if (after.dev !== before.dev || after.ino !== before.ino || after.mode !== before.mode || after.size !== before.size) throw new Error(`${label} carrier changed during appraisal`);
    return text;
  } finally { closeSync(fd); }
}

/** Closed repository-local Git control plane required before every checkout/reset/revert/pull mutation. */
export async function appraiseGitMutationControlPlane(git: GitAdapter, expectedProject?: string): Promise<string> {
  const project = realpathSync((await git.git(["rev-parse", "--show-toplevel"])).stdout.trim());
  if (expectedProject !== undefined && project !== realpathSync(expectedProject)) throw new Error("Git mutation project does not equal the expected complete worktree root");
  const entries = (await git.git(["config", "--local", "--null", "--list"])).stdout.split("\0").filter(Boolean);
  const allowed = /^(?:core\.(?:repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode)|user\.(?:name|email)|remote\.[a-z0-9._-]{1,128}\.(?:url|pushurl|fetch)|branch\.[a-z0-9._\/-]{1,240}\.(?:remote|merge))$/u;
  for (const entry of entries) {
    const separator = entry.indexOf("\n");
    if (separator <= 0) throw new Error("repository-local Git configuration entry is malformed");
    const key = entry.slice(0, separator).toLowerCase();
    const value = entry.slice(separator + 1);
    if (!allowed.test(key)) throw new Error(`repository-local Git configuration key is not allowlisted: ${key}`);
    if (Buffer.byteLength(value, "utf8") > 8192) throw new Error(`repository-local Git configuration value exceeds policy: ${key}`);
  }
  const worktreeConfigRaw = (await git.git(["rev-parse", "--git-path", "config.worktree"])).stdout.trim();
  const worktreeConfig = resolve(git.workingDirectory(), worktreeConfigRaw);
  if (worktreeConfig !== "" && existsSync(worktreeConfig)) throw new Error("Git worktree configuration carrier is forbidden");
  const attributeQueries = [
    await git.git(["ls-files", "-z", "--", ".gitattributes", ":(glob)**/.gitattributes"]),
    await git.git(["ls-files", "-z", "--others", "--exclude-standard", "--", ".gitattributes", ":(glob)**/.gitattributes"]),
    await git.git(["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", ".gitattributes", ":(glob)**/.gitattributes"]),
  ];
  const listed = [...new Set(attributeQueries.flatMap((result) => result.stdout.split("\0").filter(Boolean)))].sort();
  if (listed.length > 4096) throw new Error("Git attributes carrier count exceeds policy");
  for (const relativePath of listed) {
    if (relativePath.startsWith("/") || relativePath.split("/").some((part) => part === "" || part === "." || part === ".." || part === ".git")) throw new Error("Git attributes path is noncanonical");
    const text = readStableControlFile(resolve(project, relativePath), "Git attributes");
    for (const line of text.split(/\r?\n/u)) {
      const content = line.replace(/\\ /gu, "").trim();
      if (content === "" || content.startsWith("#")) continue;
      const attributes = content.split(/\s+/u).slice(1);
      const controls = attributes.filter((attribute) => /^(?:-|!|)(?:filter|diff|merge|working-tree-encoding)(?:=|$)/iu.test(attribute));
      // The closed Git child ignores repository, global, and system filter configuration, so this
      // canonical LFS declaration cannot select a repository-controlled command. Permit the
      // interoperable data marker while continuing to refuse every custom driver/encoding and any
      // extra control token. This keeps ordinary Git LFS repositories publishable without turning
      // `.gitattributes` into execution authority.
      const canonicalLfs = controls.length > 0 && controls.every((attribute) => ["filter=lfs", "diff=lfs", "merge=lfs"].includes(attribute.toLowerCase())) && controls.some((attribute) => attribute.toLowerCase() === "filter=lfs");
      if (controls.length > 0 && !canonicalLfs) throw new Error(`Git attributes execution or byte-transformation control is forbidden: ${relativePath}`);
    }
  }
  const infoAttributesRaw = (await git.git(["rev-parse", "--git-path", "info/attributes"])).stdout.trim();
  const infoAttributes = resolve(git.workingDirectory(), infoAttributesRaw);
  if (infoAttributes !== "" && existsSync(infoAttributes)) {
    const text = readStableControlFile(infoAttributes, "Git info/attributes");
    if (text.split(/\r?\n/u).some((line) => line.trim() !== "" && !line.trimStart().startsWith("#"))) throw new Error("Git info/attributes policy is forbidden for publication");
  }
  return project;
}
