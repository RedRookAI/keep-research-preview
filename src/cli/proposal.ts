/** Offline inspection runs before app/provider composition. */
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { MAX_PROPOSAL_EXPORT_BYTES, verifyProposalExport } from "../audit/proposal_export.js";
import { gitChildHardening } from "./runtime_config.js";

export function runProposalCommand(args: readonly string[], write: (value: string) => void): number {
  try {
    const [action, path, option] = args;
    if (!path || !["show", "patch", "verify"].includes(action ?? "") || args.length > 3 ||
      (option !== undefined && (action !== "verify" || !option.startsWith("--repository=") || option === "--repository=")))
      throw new Error("Usage: keep proposal show|patch|verify EXPORT.json [--repository=PATH (verify only)]");
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let input: string;
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.size > MAX_PROPOSAL_EXPORT_BYTES) throw new Error("export must be a regular file no larger than 16 MiB");
      const bytes = Buffer.alloc(before.size + 1);
      let length = 0;
      while (length < bytes.length) { const count = readSync(fd, bytes, length, bytes.length - length, length); if (!count) break; length += count; }
      const after = fstatSync(fd);
      if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error("export changed during inspection");
      input = bytes.subarray(0, length).toString("utf8");
      if (!Buffer.from(input).equals(bytes.subarray(0, length))) throw new Error("export must be valid UTF-8");
    } finally { closeSync(fd); }
    const receipt = verifyProposalExport(input), d = receipt.data, p = d.proposal;
    if (action === "patch") write(p.diff);
    else if (action === "show") write(JSON.stringify(d, null, 2));
    else {
      if (option !== undefined) {
        const repository = option.slice("--repository=".length), hardening = gitChildHardening(process.platform, process.env);
        const git = (args: string[], patch?: string): string => execFileSync("git", [...hardening.configArgs, "-c", "core.fsmonitor=false", "-C", repository, ...args], {
          env: { ...hardening.env, GIT_OPTIONAL_LOCKS: "0" }, encoding: "utf8", timeout: 5000, maxBuffer: MAX_PROPOSAL_EXPORT_BYTES,
          stdio: ["pipe", "pipe", "pipe"], ...(patch === undefined ? {} : { input: patch }),
        }).trim();
        let filters = "";
        try { filters = git(["config", "--includes", "--get-regexp", "^filter\\."]); }
        catch (error) { if ((error as { status?: number }).status !== 1) throw new Error("repository filter configuration cannot be inspected safely"); }
        if (filters) throw new Error("repository clean filters require separate inspection before a portable patch check");
        if (git(["rev-parse", "HEAD"]) !== p.baseRevision) throw new Error("repository HEAD differs from the recorded source revision");
        if (git(["status", "--porcelain", "--untracked-files=all", "--ignore-submodules=all"])) throw new Error("repository must be clean before checking the recorded patch");
        try { git(["apply", "--check", "--index", "-"], p.diff); } catch { throw new Error("patch does not apply to the recorded clean source"); }
      }
      write(`Export integrity matches${option === undefined ? "" : "; recorded clean source and patch check match"}. Unsigned retained evidence; inspect attribution and recorded delivery separately.`);
    }
    return 0;
  } catch (error) { write(`Proposal inspection refused: ${error instanceof Error ? error.message : "invalid export"}`); return 2; }
}
