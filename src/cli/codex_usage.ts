import type { Spine } from "../spine/spine.js";
import { authorizeCodexFollowup, codexProjectIdentity, inspectCodexInvocations, type CodexProjectDescriptor } from "../gateway/codex_project_provider.js";

/** Intentionally local-only; restricted clients cannot grant account retries. */
export async function runCodexUsageCommand(spine: Spine, args: readonly string[], ownerAuthorized: boolean,
  descriptor: CodexProjectDescriptor | undefined, write: (text: string) => void): Promise<number> {
  try {
    if (!ownerAuthorized) throw new Error("requires the local personal owner");
    if (args.length === 1 && args[0] === "status") {
      write(JSON.stringify(await inspectCodexInvocations(spine), null, 2));
      return 0;
    }
    const [action, ...options] = args, values = new Map<string, string>();
    for (const option of options) {
      const match = /^--(uncertain|expected-claims|additional-invocations)=(.+)$/u.exec(option);
      if (!match || values.has(match[1]!)) throw new Error("invalid or repeated Codex usage option");
      values.set(match[1]!, match[2]!);
    }
    if (action !== "authorize-followup" || values.size !== 3 || !descriptor ||
        !/^[1-9][0-9]*$/u.test(values.get("expected-claims")!) || !/^[1-9][0-9]*$/u.test(values.get("additional-invocations")!))
      throw new Error("use codex-usage status, or authorize-followup --uncertain=ID[,ID] --expected-claims=N --additional-invocations=N with the configured personal Codex project");
    await authorizeCodexFollowup(spine, descriptor, { uncertainClaimIds: values.get("uncertain")!.split(","),
      expectedClaims: Number(values.get("expected-claims")), additionalInvocations: Number(values.get("additional-invocations")) });
    write(`Bounded follow-up authorized for Codex identity ${codexProjectIdentity(descriptor)}. Earlier uncertain claims remain charged and unresolved. No model was called. Normal project approval and runtime restrictions still apply.`);
    return 0;
  } catch (error) { write(`Codex usage command refused: ${(error as Error).message}`); return 2; }
}
