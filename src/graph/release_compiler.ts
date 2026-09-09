/** A4 build/release compiler: installed/package bytes + pinned scanners -> one signed release closure. */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { verifyAuthorityClosure, scannerRuntimeDigest, scannerRuntimeReadOnly, type SignedWaiver } from "../effect/authority_gate.js";
import type { SignedEffectManifest } from "../effect/effect_manifest.js";
import { bundlePayloadDigest, type SignedBundle } from "../policy/compiler.js";
import type { TrustPolicy } from "../bom/bom_signing.js";
import type { CapturedCapabilityGraphV2, ObservedWorld } from "./capability_graph_v2.js";
import { compileInstalledCapabilityGraph, type InstalledCapabilityBlueprint } from "./installed_capability_compiler.js";
import { compileReleaseClosureV2, type ReleaseClosureBindings, type ReleaseClosureSigner, type ReleaseLineageExpectation, type ReleaseProfile, type ReleaseSecurityPosture, type SignedReleaseClosureV2 } from "./release_closure_v2.js";
import { captureReleaseSnapshot } from "./release_snapshot.js";
import { scanEffects } from "../effect/effect_scan_port.js";


export interface AuthorityCompilerInputs {
  readonly manifest: SignedEffectManifest;
  readonly policyBundle: SignedBundle;
  readonly trust: { readonly manifestTrust: TrustPolicy; readonly policyTrust?: TrustPolicy };
  readonly waiver: SignedWaiver;
  readonly baseline: SignedWaiver;
  readonly boundWaiverDigest: string;
  readonly previousReleaseHead: string;
  readonly waiverTrust: TrustPolicy;
}

export interface ReleaseCompilerInput {
  readonly sourceRoot: string;
  readonly packageRoot: string;
  readonly profile: ReleaseProfile;
  readonly capabilityBlueprint: InstalledCapabilityBlueprint;
  readonly releaseEpoch: bigint;
  readonly context: unknown;
  readonly authority: AuthorityCompilerInputs;
  readonly providerDescriptorDigest: string;
  readonly lineage: ReleaseLineageExpectation;
  readonly security: ReleaseSecurityPosture;
  readonly issuedAtMs: bigint;
  readonly expiresAtMs: bigint;
  readonly keyEpoch: bigint;
  readonly signers: readonly ReleaseClosureSigner[];
  readonly threshold?: number;
}

export interface CompiledReleaseV2 {
  readonly closure: SignedReleaseClosureV2;
  readonly bindings: ReleaseClosureBindings;
  readonly artifactInventoryDigest: string;
  readonly artifactGraphDigest: string;
  readonly scannerToolDigest: string;
  readonly waivedSites: number;
  readonly graph: CapturedCapabilityGraphV2;
  readonly world: ObservedWorld;
}

export class ReleaseCompilerError extends Error {
  constructor(message: string) { super(`release compiler: ${message}`); this.name = "ReleaseCompilerError"; }
}

const HEX64 = /^[0-9a-f]{64}$/;
const FORBIDDEN_RELEASE_MODULE = /(?:^|\/)(?:test|tests|fixtures?|mocks?|fakes?)(?:\/|$)|(?:^|\/)[^/]*(?:fake|mock|fixture)[^/]*\.[cm]?[jt]sx?$/i;
const sha256File = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");
export function releaseRootReadOnly(path: string): boolean {
  if (process.platform !== "linux") return false;
  try {
    const unescape = (value: string): string => value.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\012/g, "\n").replace(/\\134/g, "\\");
    const mounts = readFileSync("/proc/self/mountinfo", "utf8").split("\n").filter(Boolean).map((line) => { const fields = line.split(" - ")[0]!.split(" "); return { point: unescape(fields[4]!), options: new Set(fields[5]!.split(",")) }; }).filter((row) => path === row.point || path.startsWith(row.point === "/" ? "/" : `${row.point}/`)).sort((a, b) => b.point.length - a.point.length);
    return mounts[0]?.options.has("ro") === true;
  } catch { return false; }
}

function realDirectory(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0 || !isAbsolute(value)) throw new ReleaseCompilerError(`${label} must be an absolute directory`);
  let real: string; try { real = realpathSync(value); if (!statSync(real).isDirectory()) throw new Error("not directory"); } catch { throw new ReleaseCompilerError(`${label} is not a readable directory`); }
  return real;
}

function assertWithin(child: string, parent: string, label: string): void {
  const rel = relative(parent, child); if (rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) return;
  throw new ReleaseCompilerError(`${label} escapes packageRoot`);
}

/**
 * Compile from actual package/source bytes. The authority gate itself re-runs the pinned effect scanner and verifies the
 * signed owner map/waiver; this wrapper never accepts a caller-supplied scan result or digest.
 */
export function compileInstalledReleaseV2(input: ReleaseCompilerInput): CompiledReleaseV2 {
  const packageRoot = realDirectory(input.packageRoot, "packageRoot"); const sourceRoot = realDirectory(input.sourceRoot, "sourceRoot"); assertWithin(sourceRoot, packageRoot, "sourceRoot");
  if (sourceRoot !== packageRoot) throw new ReleaseCompilerError("sourceRoot must equal packageRoot so the effect scan covers the complete governed release tree");
  if ((input.profile === "production" || input.profile === "restricted") && !releaseRootReadOnly(packageRoot)) throw new ReleaseCompilerError("production/restricted compilation requires the governed package on a mechanically observed read-only mount");
  if ((input.profile === "production" || input.profile === "restricted") && !scannerRuntimeReadOnly()) throw new ReleaseCompilerError("production/restricted compilation requires the scanner runtime closure on mechanically observed read-only mounts");
  const snapshot = captureReleaseSnapshot(packageRoot);
  try {
    const artifactInventoryDigest = snapshot.digest; if (!HEX64.test(artifactInventoryDigest)) throw new ReleaseCompilerError("artifact inventory digest is malformed");
    const discoveryScan = scanEffects({ root: snapshot.root });
    const capability = compileInstalledCapabilityGraph({ snapshotRoot: snapshot.root, snapshotEntries: snapshot.entries, discoveredEffects: discoveryScan.findings, discoveryGraphDigest: discoveryScan.graphDigest, subjectDigest: artifactInventoryDigest, releaseEpoch: input.releaseEpoch, blueprint: input.capabilityBlueprint });
    const graph = capability.graph; const world = capability.world;
    for (const node of graph.nodes) if (node.module !== "") {
      if (FORBIDDEN_RELEASE_MODULE.test(node.module)) throw new ReleaseCompilerError(`release graph contains fixture/fake/mock module ${node.module}`);
      let moduleFile: string; try { moduleFile = realpathSync(join(snapshot.root, ...node.module.split("/"))); assertWithin(moduleFile, snapshot.root, `module ${node.module}`); if (!statSync(moduleFile).isFile()) throw new Error("not file"); } catch { throw new ReleaseCompilerError(`release graph module is absent or escapes packageRoot: ${node.module}`); }
      if (sha256File(moduleFile) !== node.moduleDigest) throw new ReleaseCompilerError(`release graph module digest mismatch: ${node.module}`);
    }

    const scannerToolDigest = scannerRuntimeDigest(); if (!HEX64.test(scannerToolDigest)) throw new ReleaseCompilerError("scanner runtime digest failed");
    const authority = verifyAuthorityClosure({ root: snapshot.root, manifest: input.authority.manifest, policyBundle: input.authority.policyBundle, trust: input.authority.trust, waiver: input.authority.waiver, baseline: input.authority.baseline, boundWaiverDigest: input.authority.boundWaiverDigest, previousReleaseHead: input.authority.previousReleaseHead, waiverTrust: input.authority.waiverTrust });
    if (!authority.valid) throw new ReleaseCompilerError(`authority closure refused release: ${authority.reason}`);
    if (authority.graphDigest !== input.authority.manifest.payload.artifactGraphDigest) throw new ReleaseCompilerError("authority graph digest disagrees with signed effect manifest");
    if (scannerToolDigest !== input.authority.manifest.payload.scannerToolDigest) throw new ReleaseCompilerError("running scanner bytes disagree with signed effect manifest");

    const bindings = Object.freeze({ artifactInventoryDigest, effectManifestDigest: input.authority.manifest.payloadDigest, policyBundleDigest: bundlePayloadDigest(input.authority.policyBundle), scannerToolDigest, authorityWaiverDigest: input.authority.boundWaiverDigest, providerDescriptorDigest: input.providerDescriptorDigest });
    // Feed closure compilation the already-captured owned graph, excluding only its derived digest field. This prevents a
    // second read of hostile caller-owned input while retaining the closure compiler's independent schema/digest check.
    const { digest: _capturedDigest, ...ownedGraphInput } = graph;
    const closure = compileReleaseClosureV2({ profile: input.profile, graph: ownedGraphInput, world, context: input.context, bindings, lineage: input.lineage, security: input.security, issuedAtMs: input.issuedAtMs, expiresAtMs: input.expiresAtMs, keyEpoch: input.keyEpoch, signers: input.signers, ...(input.threshold === undefined ? {} : { threshold: input.threshold }) });
    return Object.freeze({ closure, bindings, artifactInventoryDigest, artifactGraphDigest: authority.graphDigest, scannerToolDigest, waivedSites: authority.waivedSites, graph, world });
  } finally { snapshot.dispose(); }
}
