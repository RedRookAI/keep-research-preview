import { createHash } from "node:crypto";

export interface NativeProductionRootIdentity {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mountId: bigint;
  readonly filesystemType: bigint;
  readonly uid: bigint;
  readonly gid: bigint;
  readonly permissions: bigint;
  readonly readOnly: boolean;
}

export interface NativeProductionLeafIdentity {
  readonly device: bigint;
  readonly inode: bigint;
  readonly uid: bigint;
  readonly gid: bigint;
  readonly mode: bigint;
  readonly size: bigint;
}

export interface NativeProductionArtifactObservation {
  readonly artifactId: string;
  readonly kind: "helper" | "trampoline" | "prober" | "provisioner" | "role";
  readonly digest: string;
  readonly leaf: NativeProductionLeafIdentity & { readonly links: bigint };
  readonly byteLength: bigint;
}

export interface NativeProductionResolutionObservation {
  readonly authorityRoot: NativeProductionRootIdentity;
  readonly payloadRoot: NativeProductionRootIdentity;
  readonly manifestLeaf: NativeProductionLeafIdentity;
  readonly deploymentId: string;
  readonly manifestDigest: string;
  readonly artifacts: readonly NativeProductionArtifactObservation[];
}

export class NativeProductionObservationError extends Error {
  constructor(message: string) { super(`native production observation: ${message}`); }
}

const identifier = (value: unknown): string => {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || !/^[A-Za-z0-9._-]+$/.test(value))
    throw new NativeProductionObservationError("identifier is malformed");
  return value;
};
const artifactIdentifier = (value: unknown): string => {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value))
    throw new NativeProductionObservationError("artifact identifier is malformed");
  return value;
};
const digest = (value: unknown): string => {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    throw new NativeProductionObservationError("digest is malformed");
  return value;
};
const uint = (value: unknown): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn)
    throw new NativeProductionObservationError("integer is outside uint64");
  return value;
};
const text = (value: string): Buffer => {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([length, bytes]);
};
const word = (value: bigint): Buffer => { const out = Buffer.alloc(8); out.writeBigUInt64BE(uint(value)); return out; };

export function nativeProductionResolutionTranscriptDigest(input: NativeProductionResolutionObservation): string {
  const deploymentId = identifier(input.deploymentId);
  const manifestDigest = digest(input.manifestDigest);
  if (!Array.isArray(input.artifacts) || input.artifacts.length < 3 || input.artifacts.length > 128)
    throw new NativeProductionObservationError("artifact projection is not bounded");
  const allowedKinds = new Set(["helper", "trampoline", "prober", "provisioner", "role"]);
  let priorId = "";
  const cardinality = new Map<string, number>();
  for (const artifact of input.artifacts) {
    const artifactId = artifactIdentifier(artifact.artifactId);
    if (!allowedKinds.has(artifact.kind) || (priorId !== "" && priorId >= artifactId))
      throw new NativeProductionObservationError("artifact projection is not exact or ordered");
    priorId = artifactId;
    cardinality.set(artifact.kind, (cardinality.get(artifact.kind) ?? 0) + 1);
  }
  for (const kind of ["helper", "trampoline", "prober"])
    if (cardinality.get(kind) !== 1) throw new NativeProductionObservationError("artifact cardinality is invalid");
  const chunks: Buffer[] = [Buffer.from("keep.native-production-resolution-observation/v2\0")];
  for (const root of [input.authorityRoot, input.payloadRoot]) {
    if (typeof root.readOnly !== "boolean")
      throw new NativeProductionObservationError("root read-only state is malformed");
    for (const value of [root.device, root.inode, root.mountId, root.filesystemType, root.uid, root.gid,
      root.permissions, root.readOnly ? 1n : 0n])
      chunks.push(word(value));
  }
  for (const value of [input.manifestLeaf.device, input.manifestLeaf.inode, input.manifestLeaf.uid,
    input.manifestLeaf.gid, input.manifestLeaf.mode, input.manifestLeaf.size]) chunks.push(word(value));
  chunks.push(text(deploymentId), Buffer.from(manifestDigest, "ascii"));
  const ids = new Set<string>();
  for (const artifact of input.artifacts) {
    if (ids.has(artifact.artifactId)) throw new NativeProductionObservationError("artifact ID is duplicated");
    ids.add(artifactIdentifier(artifact.artifactId));
    chunks.push(text(artifact.artifactId), text(artifact.kind), text(digest(artifact.digest)));
    for (const value of [artifact.leaf.device, artifact.leaf.inode, artifact.leaf.uid, artifact.leaf.gid,
      artifact.leaf.mode, artifact.leaf.links, artifact.leaf.size]) chunks.push(word(value));
    chunks.push(word(artifact.byteLength));
  }
  return createHash("sha256").update(Buffer.concat(chunks)).digest("hex");
}
