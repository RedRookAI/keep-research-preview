import { createHash, randomBytes } from "node:crypto";
import { existsSync, lstatSync, openSync, fsyncSync, closeSync, writeFileSync, unlinkSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, resolve, sep } from "node:path";
import type { KeepApp } from "../compose.js";
import { OWNER } from "../identity/rbac.js";
import { readRestrictedClientProfile, type RestrictedClientProfile } from "../gateway/restricted_client.js";

/** Local owner administration only. No endpoint returns these credentials to the agent. */
export async function runOpenClawClientCommand(app: KeepApp, args: readonly string[], ownerAuthorized: boolean, write: (text: string) => void): Promise<number> {
  try {
    if (!ownerAuthorized || app.identity || app.tenantDeployment) throw new Error("requires the local personal owner");
    const [action, ...options] = args;
    const allowed = action === "issue" ? ["profile", "token-file", "agent-id", "expires-at"] : action === "revoke" ? ["profile"] : [];
    const values = new Map<string, string>();
    for (const option of options) {
      const match = /^--([a-z-]+)=(.+)$/u.exec(option);
      if (!match || !allowed.includes(match[1]!) || values.has(match[1]!)) throw new Error("invalid or repeated client option");
      values.set(match[1]!, match[2]!);
    }
    if (!allowed.length || values.size !== allowed.length) throw new Error("use openclaw-client issue --profile=PATH --token-file=PATH --agent-id=ID --expires-at=ISO_DATE, or revoke --profile=PATH");
    const profilePath = values.get("profile")!;
    if (!isAbsolute(profilePath)) throw new Error("profile requires an absolute private path");
    if (action === "revoke") {
      const profile = readRestrictedClientProfile(profilePath);
      const restored = app.authorization.restorePrincipal(profile.grantId);
      if (restored && (restored.id !== profile.agentId || restored.delegatedBy !== OWNER.id || restored.tenant !== undefined)) throw new Error("profile grant is not owned by this owner");
      const revoked = await app.authorization.revokeFor(OWNER, profile.grantId);
      write(revoked ? "OpenClaw client grant revoked. The token file is retained for explicit operator disposal." : "No live grant was found; no new authority was issued.");
      return 0;
    }
    if (!app.projectRuntime?.commandBinding || app.projectGenerationApprovalRequired !== true) throw new Error("issuance requires a configured personal project runtime with human generation approval");
    const tokenPath = values.get("token-file")!, agentId = values.get("agent-id")!;
    const expiresAt = Date.parse(values.get("expires-at")!);
    if (!isAbsolute(tokenPath) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(agentId) || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) throw new Error("token path, agent ID or future expiry is invalid");
    for (const path of [profilePath, tokenPath]) {
      const parent = realpathSync(dirname(path)), stat = lstatSync(parent);
      if (existsSync(path) || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new Error("new credential files require an existing private owned parent and must not overwrite files");
      for (const root of Object.values(app.runtimePaths ?? {})) if (parent === realpathSync(root) || parent.startsWith(realpathSync(root) + sep)) throw new Error("client credentials must be outside the repository and workspace");
    }
    if (resolve(profilePath) === resolve(tokenPath)) throw new Error("profile and token file must differ");
    const principal = await app.authorization.issue(OWNER, agentId, ["change.solve"], expiresAt);
    const bearer = randomBytes(32).toString("hex");
    const profile: RestrictedClientProfile = { schema: "keep.openclaw-client/v1", clientId: agentId, agentId, grantId: principal.grantId,
      expiresAt, bearerSha256: createHash("sha256").update(bearer).digest("hex"), commandBinding: app.projectRuntime.commandBinding };
    const created: string[] = [];
    try {
      for (const [path, text] of [[profilePath, JSON.stringify(profile, null, 2) + "\n"], [tokenPath, bearer + "\n"]]) {
        const fd = openSync(path!, "wx", 0o600); created.push(path!);
        try { writeFileSync(fd, text!); fsyncSync(fd); } finally { closeSync(fd); }
      }
      for (const parent of new Set([dirname(profilePath), dirname(tokenPath)])) if (process.platform !== "win32") {
        const fd = openSync(parent, "r"); try { fsyncSync(fd); } finally { closeSync(fd); }
      }
    } catch (error) {
      await app.authorization.revokeFor(OWNER, principal.grantId);
      for (const path of created) unlinkSync(path);
      throw error;
    }
    write(`Restricted client issued for ${agentId}. Profile: ${profilePath}\nPrivate plugin credential: ${tokenPath}\nSet KEEP_OPENCLAW_CLIENT_PROFILE to the profile before starting this instance. No credential value was printed.`);
    return 0;
  } catch (error) { write(`OpenClaw client command refused: ${(error as Error).message}`); return 2; }
}
