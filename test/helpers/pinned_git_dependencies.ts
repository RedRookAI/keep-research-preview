import { execFileSync } from "node:child_process";

import { GitAdapter } from "../../src/infra/git_adapter.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../../src/git/pinned_remote.js";
import type { MergePort } from "../../src/oversight/merge_executor.js";

/**
 * Build the real solve-to-PR Git dependency tuple for a fixture repository.
 *
 * Production refuses every remote operation unless the operator has pinned both
 * fetch and push identities. Integration tests use this helper so they exercise
 * that same fail-closed contract rather than silently constructing a legacy,
 * unpinned transport.
 */
export function pinnedGitDependencies(worktree: string, mergePort?: MergePort) {
  const configuredFetchUrl = execFileSync("git", ["remote", "get-url", "origin"], {
    cwd: worktree,
    encoding: "utf8",
  }).trim();
  const configuredPushUrl = execFileSync("git", ["remote", "get-url", "--push", "origin"], {
    cwd: worktree,
    encoding: "utf8",
  }).trim();
  const explicitUrl = (value: string): string => /^(?:https|ssh|file):\/\//u.test(value) ? value : `file://${value}`;
  const fetchUrl = explicitUrl(configuredFetchUrl);
  const pushUrl = explicitUrl(configuredPushUrl);
  if (fetchUrl !== configuredFetchUrl) {
    execFileSync("git", ["remote", "set-url", "origin", fetchUrl], { cwd: worktree });
  }
  if (pushUrl !== configuredPushUrl) {
    execFileSync("git", ["config", "--local", "remote.origin.pushurl", pushUrl], { cwd: worktree });
  }

  return {
    git: new GitAdapter(worktree),
    baseBranch: "main",
    remoteConfig: {
      remote: "origin",
      expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(fetchUrl),
      expectedPushUrlSha256: pinnedRemoteUrlSha256(pushUrl),
    },
    ...(mergePort ? { mergePort } : {}),
  } as const;
}
