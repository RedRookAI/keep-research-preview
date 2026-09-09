/** Explicit operator-owned profile; a request cannot introduce retention policy. */
import { isAbsolute, resolve } from "node:path";
import { captureMemoryRetentionPolicy, MEMORY_RETENTION_POLICY_SCHEMA, type CapturedMemoryRetentionPolicy, type MemoryRetentionAuthority, type MemoryRetentionPolicy } from "../memory/retention.js";
import { readProtectedProfile, writeProtectedProfile } from "./provider_profile.js";

export function loadMemoryRetentionProfile(path: string, authority: MemoryRetentionAuthority): CapturedMemoryRetentionPolicy {
  if (!isAbsolute(path)) throw new Error("memory retention profile path must be absolute");
  const policy = captureMemoryRetentionPolicy(readProtectedProfile(path, "memory retention profile"));
  if (policy.authority !== authority) throw new Error("memory retention profile authority conflicts with installation authority");
  return policy;
}

export function writeMemoryRetentionProfile(path: string, value: MemoryRetentionPolicy): void {
  if (!isAbsolute(path)) throw new Error("memory retention profile path must be absolute");
  const { identity: _identity, ...policy } = captureMemoryRetentionPolicy(value);
  writeProtectedProfile(path, policy);
}

export function memoryRetentionProfileFromArgs(args: readonly string[], cwd: string): { path: string; policy: MemoryRetentionPolicy } {
  const fields = new Map<string, string>();
  for (const arg of args) {
    const match = /^--(profile|authority|purposes|max-use-ms)=(.+)$/u.exec(arg);
    if (!match || fields.has(match[1]!)) throw new Error("memory-retention configure requires unique --profile, --authority, --purposes and --max-use-ms values");
    fields.set(match[1]!, match[2]!);
  }
  if (fields.size !== 4) throw new Error("memory-retention configure requires --profile, --authority, --purposes and --max-use-ms (positive milliseconds or unlimited)");
  const duration = fields.get("max-use-ms")!;
  if (duration !== "unlimited" && !/^[1-9][0-9]*$/u.test(duration)) throw new Error("invalid maximum retention duration");
  const captured = captureMemoryRetentionPolicy({ schema: MEMORY_RETENTION_POLICY_SCHEMA, authority: fields.get("authority"),
    purposes: fields.get("purposes")!.split(",").map(id => ({ id, maxUseMs: duration === "unlimited" ? null : Number(duration) })) });
  const { identity: _identity, ...policy } = captured;
  return { path: resolve(cwd, fields.get("profile")!), policy };
}
