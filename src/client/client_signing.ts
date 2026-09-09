import { capabilityArgsDigest, type CapabilityAuthorization, type CapabilityHub, type CapabilityInvocation } from "../ecosystem/capability_port.js";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
export type ClientSigningPlatform = "desktop" | "ios" | "android";
export interface ClientSigningReceiptStore { load(identity: string): SignedClientBinary | undefined; save(identity: string, artifact: SignedClientBinary): void; }
export class FileClientSigningReceiptStore implements ClientSigningReceiptStore {
  constructor(private readonly root: string) { mkdirSync(root, { recursive: true, mode: 0o700 }); }
  load(identity: string): SignedClientBinary | undefined {
    try {
      const parsed = JSON.parse(readFileSync(this.path(identity), "utf8")) as { identity?: unknown; artifact?: unknown };
      if (parsed.identity !== identity || parsed.artifact === null || typeof parsed.artifact !== "object") throw new Error("client signing receipt binding is invalid");
      return parsed.artifact as SignedClientBinary;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }
  save(identity: string, artifact: SignedClientBinary): void {
    const path = this.path(identity); const temporary = `${path}.${process.pid}.tmp`; let fd: number | undefined;
    try {
      fd = openSync(temporary, "wx", 0o600); writeFileSync(fd, `${JSON.stringify({ schema: "keep.client-signing-receipt/v1", identity, artifact })}\n`, "utf8"); fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temporary, path);
      if (process.platform !== "win32") { const dir = openSync(dirname(path), "r"); try { fsyncSync(dir); } finally { closeSync(dir); } }
    } finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
  }
  private path(identity: string): string { return join(this.root, `${identity}.json`); }
}
export interface ClientSigningBoundary { readonly hub: CapabilityHub; readonly capabilityId: string; readonly authorizationFor?: (invocation: CapabilityInvocation) => CapabilityAuthorization | undefined; readonly verifyAuthorization: (authorization: CapabilityAuthorization) => boolean; readonly receipts: ClientSigningReceiptStore; readonly verifySignedBinary: (artifact: { readonly signedBinaryBase64: string; readonly keyId: string; readonly signature: string }, input: { readonly platform: ClientSigningPlatform; readonly artifactDigest: string }) => boolean | Promise<boolean>; }
export interface SignedClientBinary { readonly platform: ClientSigningPlatform; readonly distribution: "private-development-only"; readonly artifactDigest: string; readonly signedBinaryBase64: string; readonly keyId: string; readonly signature: string; }
function validBase64(value: string): boolean { if (value.length === 0 || value.length > Math.ceil((4 * 1024 * 1024) / 3) * 4 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) return false; try { return Buffer.from(value, "base64").toString("base64") === value; } catch { return false; } }
export async function signClientBinary(boundary: ClientSigningBoundary, input: { readonly platform: ClientSigningPlatform; readonly binaryBase64: string; readonly distribution: "private-development-only" }): Promise<SignedClientBinary> {
  if (!validBase64(input.binaryBase64)) throw new Error("client binary must be canonical base64 within the 4 MiB bound");
  if (input.distribution !== "private-development-only") throw new Error("public/store distribution is outside private-build authorization");
  const artifactDigest = capabilityArgsDigest({ binaryBase64: input.binaryBase64 }); const args = { platform: input.platform, distribution: input.distribution, artifactDigest, binaryBase64: input.binaryBase64 } as const; const invocation = { capabilityId: boundary.capabilityId, operation: "client.sign", args } as const; const authorization = boundary.authorizationFor?.(invocation);
  if (!authorization || !boundary.verifyAuthorization(authorization)) throw new Error("client signing held for exact authorization");
  const receiptIdentity = capabilityArgsDigest({ capabilityId: invocation.capabilityId, operation: invocation.operation, argsDigest: capabilityArgsDigest(invocation.args), authorizationId: authorization.id, idempotencyKey: authorization.idempotencyKey });
  const prior = boundary.receipts.load(receiptIdentity);
  if (prior !== undefined) { if (prior.platform !== input.platform || prior.distribution !== input.distribution || prior.artifactDigest !== artifactDigest || !await boundary.verifySignedBinary(prior, { platform: input.platform, artifactDigest })) throw new Error("durable client signing receipt verification failed"); return prior; }
  const result = await boundary.hub.invoke(invocation, { requireVerified: true, ...(authorization ? { authorization } : {}) });
  if (result.held) throw new Error(result.error ?? "client signing held for exact authorization");
  if (!result.ok || result.output === null || typeof result.output !== "object") throw new Error(result.error ?? "client signing failed");
  const output = result.output as Record<string, unknown>; if (!validBase64(String(output["signedBinaryBase64"] ?? "")) || typeof output["keyId"] !== "string" || output["keyId"].length === 0 || typeof output["signature"] !== "string" || output["signature"].length === 0) throw new Error("signing adapter returned a malformed signed binary");
  const artifact = { signedBinaryBase64: String(output["signedBinaryBase64"]), keyId: output["keyId"], signature: output["signature"] }; let verified = false; try { verified = await boundary.verifySignedBinary(artifact, { platform: input.platform, artifactDigest }); } catch { verified = false; } if (!verified) throw new Error("platform verification rejected the signed client binary");
  const signed = { platform: input.platform, distribution: input.distribution, artifactDigest, ...artifact } as const; boundary.receipts.save(receiptIdentity, signed); return signed;
}
