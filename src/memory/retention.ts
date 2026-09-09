/** Host-selected private-source retention, independent of model egress authority. */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { scanIngestion } from "./ingestion.js";

export const MEMORY_RETENTION_POLICY_SCHEMA = "keep.memory-retention-policy/v1";
export type MemoryRetentionAuthority = "owner" | "organization";
export interface MemoryRetentionPolicy {
  readonly schema: typeof MEMORY_RETENTION_POLICY_SCHEMA;
  readonly authority: MemoryRetentionAuthority;
  readonly purposes: readonly { readonly id: string; readonly maxUseMs: number | null }[];
}
export interface CapturedMemoryRetentionPolicy extends MemoryRetentionPolicy { readonly identity: string }
export interface PrivateSourceRetention {
  readonly representation: "keep.memory.private-source/v1";
  readonly purpose: string;
  readonly policyIdentity: string;
  readonly useUntil: number | null;
}
export type PrivateSourceAdmission =
  | { readonly accepted: true; readonly content: string; readonly retention: PrivateSourceRetention; readonly findings: readonly string[] }
  | { readonly accepted: false; readonly reason: "policy" | "request" | "lifetime" | "ingestion"; readonly findings: readonly string[] };

function inertRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("memory retention policy requires inert objects");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== keys.length || keys.some(key => !descriptors[key])
    || Object.entries(descriptors).some(([key, d]) => !keys.includes(key) || !("value" in d) || !d.enumerable)) throw new Error("invalid memory retention policy fields");
  return value as Record<string, unknown>;
}
const purposeId = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9.-]{0,127}$/u.test(value);
const timestamp = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** Capture inert configuration once. Identity is computed, never supplied by a memory command. */
export function captureMemoryRetentionPolicy(value: unknown): CapturedMemoryRetentionPolicy {
  const raw = inertRecord(value, ["schema", "authority", "purposes"]);
  if (raw["schema"] !== MEMORY_RETENTION_POLICY_SCHEMA || (raw["authority"] !== "owner" && raw["authority"] !== "organization")) throw new Error("invalid memory retention policy schema or authority");
  const input = raw["purposes"];
  if (!Array.isArray(input) || types.isProxy(input) || Object.getPrototypeOf(input) !== Array.prototype || input.length > 32
    || Reflect.ownKeys(input).length !== input.length + 1
    || Array.from({ length: input.length }, (_, index) => Object.getOwnPropertyDescriptor(input, String(index))).some(d => !d || !("value" in d) || !d.enumerable)) throw new Error("memory retention policy requires at most32 inert purposes");
  const ids = new Set<string>();
  const purposes = input.map(value => {
    const row = inertRecord(value, ["id", "maxUseMs"]), id = row["id"], maxUseMs = row["maxUseMs"];
    if (!purposeId(id) || ids.has(id) || (maxUseMs !== null && (!timestamp(maxUseMs) || maxUseMs === 0))) throw new Error("invalid memory retention purpose or duration");
    ids.add(id); return Object.freeze({ id, maxUseMs });
  }).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const policy = { schema: MEMORY_RETENTION_POLICY_SCHEMA, authority: raw["authority"], purposes: Object.freeze(purposes) } as const;
  const identity = createHash("sha256").update(JSON.stringify(policy)).digest("hex");
  return Object.freeze({ ...policy, identity });
}

/** No clock arithmetic overflow and no conversion of an omitted deadline to unlimited use. */
export function privateRetentionAllowed(policy: CapturedMemoryRetentionPolicy | undefined, authority: MemoryRetentionAuthority,
  purpose: string, createdAt: number, useUntil: number | null, now: number): boolean {
  if (!policy || policy.authority !== authority || !purposeId(purpose) || !timestamp(createdAt) || !timestamp(now) || now < createdAt) return false;
  const rule = policy.purposes.find(row => row.id === purpose);
  if (!rule || (useUntil !== null && (!timestamp(useUntil) || useUntil <= now))) return false;
  return rule.maxUseMs === null || (useUntil !== null && useUntil - createdAt <= rule.maxUseMs);
}

/** Caller must separately prove initialized consent and current memory/resource authority.
 * This gate neither grants those permissions nor permits disclosure, embedding or tool effects. */
export function admitPrivateMemorySource(policy: CapturedMemoryRetentionPolicy | undefined, authority: MemoryRetentionAuthority,
  request: { readonly content: string; readonly purpose: string; readonly useUntil: number | null }, now: number): PrivateSourceAdmission {
  const refuse = (reason: Extract<PrivateSourceAdmission, { accepted: false }>["reason"], findings: readonly string[] = []): PrivateSourceAdmission => Object.freeze({ accepted: false, reason, findings: Object.freeze([...findings]) });
  if (!policy || policy.authority !== authority || !policy.purposes.some(row => row.id === request.purpose)) return refuse("policy");
  if (typeof request.content !== "string" || !request.content || Buffer.byteLength(request.content) > 1024 * 1024 || !purposeId(request.purpose)) return refuse("request");
  if (!privateRetentionAllowed(policy, authority, request.purpose, now, request.useUntil, now)) return refuse("lifetime");
  const scan = scanIngestion(request.content);
  // Reuse existing detectors. The ordinary sanitized path is unchanged. Never
  // quietly modify a source that the operator explicitly asked to retain exactly.
  if (scan.decision === "reject" || scan.findings.some(finding => finding.startsWith("secret:"))) return refuse("ingestion", scan.findings);
  return Object.freeze({ accepted: true, content: request.content,
    retention: Object.freeze({ representation: "keep.memory.private-source/v1", purpose: request.purpose, policyIdentity: policy.identity, useUntil: request.useUntil }),
    findings: Object.freeze([...scan.findings]) });
}
