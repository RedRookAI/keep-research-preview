import { createHash } from "node:crypto";

import type { CapabilityHub, CapabilityInvocation, CapabilityResult } from "../ecosystem/capability_port.js";
import type { Spine } from "../spine/spine.js";
import {
  audiobookSynthesisRequestSha256,
  type AudiobookSynthesisPort,
  type AudiobookSynthesisRequest,
  type AudiobookSynthesisResult,
} from "./domain_workflows.js";

export interface AudiobookSynthesisAuthorization {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly actor: string;
  readonly tenant?: string;
  readonly capabilityId: string;
  readonly operation: "audio.synthesize";
  readonly requestSha256: string;
  readonly idempotencyKey: string;
  readonly notBeforeMs: number;
  readonly expiresAtMs: number;
}

export interface CapabilityAudiobookSynthesisConfig {
  readonly hub: CapabilityHub;
  readonly spine: Spine;
  readonly capabilityId: string;
  /** Resolves a separately issued authorization; absence is a held effect, never implied consent. */
  readonly authorizationFor: (request: AudiobookSynthesisRequest) => Promise<AudiobookSynthesisAuthorization | undefined> | AudiobookSynthesisAuthorization | undefined;
  /** Cryptographic/policy verifier owned outside the worker. */
  readonly verifyAuthorization: (authorization: AudiobookSynthesisAuthorization) => Promise<boolean> | boolean;
  readonly now?: () => number;
  /** Composition-owned wrapper used when fleet mode requires an exact admission permit. */
  readonly dispatch?: (invocation: CapabilityInvocation, authorization: AudiobookSynthesisAuthorization) => Promise<CapabilityResult>;
}

const SHA256 = /^[0-9a-f]{64}$/u;

function authorization(value: unknown): AudiobookSynthesisAuthorization | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return undefined;
  const row = value as Record<string, unknown>;
  const fields = ["schemaVersion", "id", "actor", "tenant", "capabilityId", "operation", "requestSha256", "idempotencyKey", "notBeforeMs", "expiresAtMs"];
  if (Object.keys(row).some((key) => !fields.includes(key)) || row["schemaVersion"] !== 1 || row["operation"] !== "audio.synthesize") return undefined;
  for (const key of ["id", "actor", "capabilityId", "idempotencyKey"] as const) if (typeof row[key] !== "string" || row[key].length === 0 || row[key].length > 4096) return undefined;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(row["actor"] as string)) return undefined;
  if (row["tenant"] !== undefined && (typeof row["tenant"] !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(row["tenant"]))) return undefined;
  if (typeof row["requestSha256"] !== "string" || !SHA256.test(row["requestSha256"]) || !Number.isSafeInteger(row["notBeforeMs"]) || !Number.isSafeInteger(row["expiresAtMs"])) return undefined;
  return Object.freeze({ schemaVersion: 1, id: row["id"] as string, actor: row["actor"] as string, ...(row["tenant"] === undefined ? {} : { tenant: row["tenant"] as string }), capabilityId: row["capabilityId"] as string, operation: "audio.synthesize", requestSha256: row["requestSha256"], idempotencyKey: row["idempotencyKey"] as string, notBeforeMs: row["notBeforeMs"] as number, expiresAtMs: row["expiresAtMs"] as number });
}

async function terminal(spine: Spine, actor: string, intentEntryHash: string, disposition: "aborted" | "error", reason: string): Promise<void> {
  spine.stage({ type: "effect.terminal", actor, payload: { kind: "audiobook.synthesis.terminal", intentEntryHash, disposition, reason: reason.slice(0, 512) } });
  await spine.seal();
}

/** Build the only supported CapabilityHub-backed audiobook effect executor. */
export function buildCapabilityAudiobookSynthesisPort(config: CapabilityAudiobookSynthesisConfig): AudiobookSynthesisPort {
  if (!config.spine.durableStorage()) throw new Error("audiobook synthesis requires a durable spine before external effects");
  if (typeof config.capabilityId !== "string" || config.capabilityId.length === 0 || typeof config.authorizationFor !== "function" || typeof config.verifyAuthorization !== "function") throw new Error("audiobook synthesis capability configuration is incomplete");
  const now = config.now ?? Date.now;
  return Object.freeze({
    verifyReceipt(receipt: import("./domain_workflows.js").AudiobookSynthesisReceipt) {
      try {
        return config.spine.replay().some((event) => event.type === "effect.receipt"
          && event.payload["kind"] === "audiobook.synthesis.receipt"
          && event.payload["intentEntryHash"] === receipt.effectId
          && event.payload["requestSha256"] === receipt.requestSha256
          && event.payload["idempotencyKey"] === receipt.idempotencyKey
          && event.payload["audioMasterSha256"] === receipt.audioMasterSha256);
      } catch { return false; }
    },
    async synthesize(request: AudiobookSynthesisRequest, signal: AbortSignal): Promise<AudiobookSynthesisResult> {
      const requestSha256 = audiobookSynthesisRequestSha256(request);
      if (signal.aborted) return { status: "unavailable", requestSha256, reason: "audiobook synthesis was cancelled before authorization" };
      let admitted: AudiobookSynthesisAuthorization | undefined;
      try { admitted = authorization(await config.authorizationFor(request)); } catch { admitted = undefined; }
      const instant = now();
      let verified = false;
      try { verified = admitted !== undefined && await config.verifyAuthorization(admitted); } catch { verified = false; }
      if (admitted === undefined || !verified || admitted.capabilityId !== config.capabilityId || admitted.operation !== "audio.synthesize"
        || admitted.requestSha256 !== requestSha256 || admitted.idempotencyKey !== request.idempotencyKey
        || instant < admitted.notBeforeMs || instant > admitted.expiresAtMs || admitted.expiresAtMs - admitted.notBeforeMs > 24 * 60 * 60 * 1_000) {
        return { status: "held", requestSha256, reason: "Audiobook synthesis requires fresh exact authorization for this capability, request, and idempotency identity." };
      }
      const intentEntryHash = config.spine.stage({
        type: "effect.intent", actor: admitted.actor,
        payload: { kind: "audiobook.synthesis.intent", authorizationId: admitted.id, capabilityId: admitted.capabilityId, operation: admitted.operation, requestSha256, idempotencyKey: request.idempotencyKey },
      });
      try { await config.spine.seal(); }
      catch { return { status: "unavailable", requestSha256, reason: "Audiobook synthesis pre-effect intent could not be durably sealed." }; }
      if (signal.aborted) {
        await terminal(config.spine, admitted.actor, intentEntryHash, "aborted", "cancelled after intent and before dispatch");
        return { status: "unavailable", requestSha256, reason: "Audiobook synthesis was cancelled before dispatch." };
      }
      const invocation: CapabilityInvocation = {
        capabilityId: admitted.capabilityId, operation: admitted.operation,
        args: { sourceManuscript: request.sourceManuscript, sourceRights: request.sourceRights, pronunciationGuide: request.pronunciationGuide, rightsBrief: request.rightsBrief, narrationPlan: request.narrationPlan, chapterCues: request.chapterCues, idempotencyKey: request.idempotencyKey, requestSha256 },
        signal, auditArgs: "digest",
      };
      const result = config.dispatch === undefined
        ? await config.hub.invoke(invocation, { requireVerified: true, confirm: true, ...(admitted.tenant === undefined ? {} : { tenant: admitted.tenant }) })
        : await config.dispatch(invocation, admitted);
      if (result.held) {
        await terminal(config.spine, admitted.actor, intentEntryHash, "aborted", result.error ?? "effect mediation held synthesis");
        return { status: "held", requestSha256, reason: result.error ?? "Audiobook synthesis was held by effect mediation." };
      }
      if (!result.ok) {
        await terminal(config.spine, admitted.actor, intentEntryHash, signal.aborted ? "aborted" : "error", result.error ?? "synthesis adapter failed");
        return signal.aborted
          ? { status: "unreconciled", requestSha256, effectId: intentEntryHash, reason: result.error ?? "Audiobook synthesis was aborted after dispatch; reconciliation is required." }
          : { status: "failed", requestSha256, reason: result.error ?? "Audiobook synthesis failed." };
      }
      const audioMaster = result.output !== null && typeof result.output === "object" ? (result.output as Record<string, unknown>)["audioMaster"] : undefined;
      if (typeof audioMaster !== "string" || audioMaster.length === 0 || audioMaster.includes("\0")) {
        await terminal(config.spine, admitted.actor, intentEntryHash, "error", "adapter returned no admissible audio master");
        return { status: "failed", requestSha256, reason: "Audiobook synthesis adapter returned no admissible audio master." };
      }
      const audioMasterSha256 = createHash("sha256").update(Buffer.from(audioMaster, "utf8")).digest("hex");
      const receipt = Object.freeze({ schemaVersion: 1 as const, requestSha256, idempotencyKey: request.idempotencyKey, effectId: intentEntryHash, audioMasterSha256, delivered: true as const });
      config.spine.stage({ type: "effect.receipt", actor: admitted.actor, payload: { kind: "audiobook.synthesis.receipt", intentEntryHash, requestSha256, idempotencyKey: request.idempotencyKey, audioMasterSha256 } });
      try { await config.spine.seal(); }
      catch { return { status: "unreconciled", requestSha256, effectId: intentEntryHash, reason: "Audiobook synthesis completed but its receipt could not be durably sealed; reconciliation is required." }; }
      return { status: "completed", requestSha256, audioMaster, receipt };
    },
  });
}
