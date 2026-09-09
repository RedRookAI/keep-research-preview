/** A4 installed boot consumer: recapture the exact executing root before any restricted provider is constructed. */
import { realpathSync } from "node:fs";
import { types } from "node:util";
import { captureReleaseSnapshot } from "./release_snapshot.js";
import { releaseRootReadOnly, type AuthorityCompilerInputs } from "./release_compiler.js";
import { verifyReleaseAdmissionToken, verifyReleaseClosureV2, type ReleaseAdmissionToken, type ReleaseClosureVerificationInput } from "./release_closure_v2.js";
import { captureSignedWaiver, verifyAuthorityClosure } from "../effect/authority_gate.js";
import { captureEffectManifest, type SignedEffectManifest } from "../effect/effect_manifest.js";
import { bundlePayloadDigest, captureBundle, type SignedBundle } from "../policy/compiler.js";
import type { TrustPolicy } from "../bom/bom_signing.js";
import type { CapturedCapabilityGraphV2 } from "./capability_graph_v2.js";
import type { EffectiveCapabilityLedgers } from "./release_closure_v2.js";

export interface RestrictedReleaseAdmission {
  readonly token: ReleaseAdmissionToken;
  readonly expected: Omit<ReleaseAdmissionToken, "expiresAtMs">;
  readonly nowMs: () => bigint;
}
interface VerifiedRuntimeAuthority { readonly manifest: SignedEffectManifest; readonly policyBundle: SignedBundle; readonly trust: { readonly manifestTrust: TrustPolicy; readonly policyTrust: TrustPolicy }; }
export interface RestrictedReleaseRuntime { readonly admission: RestrictedReleaseAdmission; readonly authority: VerifiedRuntimeAuthority; readonly providerDescriptorDigest: string; readonly installedRoot: string; }
export interface ReleaseBootResult { readonly runtime: RestrictedReleaseRuntime; readonly admission: RestrictedReleaseAdmission; readonly artifactInventoryDigest: string; readonly graph: CapturedCapabilityGraphV2; readonly ledgers: EffectiveCapabilityLedgers; }
export class ReleaseBootError extends Error { constructor(message: string) { super(`release boot: ${message}`); this.name = "ReleaseBootError"; } }
const restrictedAdmissions = new WeakSet<object>();
const restrictedRuntimes = new WeakSet<object>();
const composedRuntimes = new WeakSet<object>();
const lastVerifiedTimes = new WeakMap<object, bigint>();

function plain(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new ReleaseBootError(`${label} must be plain inert data`);
  const names = Reflect.ownKeys(value); if (names.some((key) => typeof key !== "string") || [...names as string[]].sort().join("\0") !== [...keys].sort().join("\0")) throw new ReleaseBootError(`${label} keys are not exact`);
  const descriptors = Object.getOwnPropertyDescriptors(value); const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) { const descriptor = descriptors[key]; if (descriptor === undefined || descriptor.get || descriptor.set || descriptor.enumerable !== true || !("value" in descriptor)) throw new ReleaseBootError(`${label}.${key} is not inert data`); out[key] = descriptor.value; }
  return out;
}
function trustPolicy(value: unknown, label: string): TrustPolicy {
  const row = plain(value, ["trustedKeys", "threshold"], label); const source = row.trustedKeys;
  if (!(source instanceof Map) || types.isProxy(source) || Object.getPrototypeOf(source) !== Map.prototype) throw new ReleaseBootError(`${label}.trustedKeys must be a plain Map`);
  const entries: [string, string][] = []; for (const [key, material] of source) { if (typeof key !== "string" || typeof material !== "string") throw new ReleaseBootError(`${label}.trustedKeys is malformed`); entries.push([key, material]); }
  if (!Number.isInteger(row.threshold) || (row.threshold as number) < 1 || (row.threshold as number) > entries.length) throw new ReleaseBootError(`${label}.threshold is invalid`);
  return Object.freeze({ trustedKeys: new Map(entries), threshold: row.threshold as number });
}
function captureAuthority(value: unknown): AuthorityCompilerInputs & { readonly trust: { readonly manifestTrust: TrustPolicy; readonly policyTrust: TrustPolicy } } {
  const row = plain(value, ["manifest", "policyBundle", "trust", "waiver", "baseline", "boundWaiverDigest", "previousReleaseHead", "waiverTrust"], "authority");
  const trustRow = plain(row.trust, ["manifestTrust", "policyTrust"], "authority.trust");
  if (typeof row.boundWaiverDigest !== "string" || typeof row.previousReleaseHead !== "string") throw new ReleaseBootError("authority release-head bindings are malformed");
  return Object.freeze({ manifest: captureEffectManifest(row.manifest), policyBundle: captureBundle(row.policyBundle), trust: Object.freeze({ manifestTrust: trustPolicy(trustRow.manifestTrust, "authority.trust.manifestTrust"), policyTrust: trustPolicy(trustRow.policyTrust, "authority.trust.policyTrust") }), waiver: captureSignedWaiver(row.waiver), baseline: captureSignedWaiver(row.baseline), boundWaiverDigest: row.boundWaiverDigest, previousReleaseHead: row.previousReleaseHead, waiverTrust: trustPolicy(row.waiverTrust, "authority.waiverTrust") });
}

export function verifyInstalledReleaseAtBoot(input: { readonly installedRoot: string; readonly verification: ReleaseClosureVerificationInput; readonly authority: AuthorityCompilerInputs; readonly providerDescriptorDigest: string; readonly trustedNowMs: () => bigint; readonly scannerEnginePath?: string }): ReleaseBootResult {
  const boot = plain(input, ["installedRoot", "verification", "authority", "providerDescriptorDigest", "trustedNowMs", ...(input.scannerEnginePath === undefined ? [] : ["scannerEnginePath"])], "boot input");
  if (typeof boot.installedRoot !== "string" || typeof boot.providerDescriptorDigest !== "string" || typeof boot.trustedNowMs !== "function") throw new ReleaseBootError("boot input values are malformed");
  if (boot.scannerEnginePath !== undefined && (typeof boot.scannerEnginePath !== "string" || boot.scannerEnginePath.length === 0)) throw new ReleaseBootError("scanner engine path is malformed");
  const verification = plain(boot.verification, ["closure", "graph", "world", "context", "bindings", "trust", "lineage", "expectedProfile", "observedSecurity", "bootNonce"], "verification");
  const root = realpathSync(boot.installedRoot);
  const snapshot = captureReleaseSnapshot(root);
  try {
    let lastClockSample: bigint | undefined;
    const trustedClock = boot.trustedNowMs as () => bigint;
    const sampleClock = (): bigint => { const value = trustedClock(); if (typeof value !== "bigint" || value < 0n || (lastClockSample !== undefined && value <= lastClockSample)) throw new ReleaseBootError("trusted release clock did not advance monotonically"); lastClockSample = value; return value; };
    const bootNow = sampleClock();
    const verdict = verifyReleaseClosureV2({ closure: verification.closure, graph: verification.graph, world: verification.world, context: { trustedNowMs: bootNow }, bindings: verification.bindings as ReleaseClosureVerificationInput["bindings"], trust: verification.trust as ReleaseClosureVerificationInput["trust"], lineage: verification.lineage as ReleaseClosureVerificationInput["lineage"], expectedProfile: verification.expectedProfile as ReleaseClosureVerificationInput["expectedProfile"], observedSecurity: verification.observedSecurity as ReleaseClosureVerificationInput["observedSecurity"], bootNonce: verification.bootNonce as string }); if (!verdict.valid) throw new ReleaseBootError(`signed closure refused: ${verdict.reason}`);
    const profile = verdict.closure.payload.profile;
    if ((profile === "production" || profile === "restricted") && !releaseRootReadOnly(root)) throw new ReleaseBootError("restricted workload root is not on a mechanically observed read-only mount");
    if (snapshot.digest !== verdict.graph.subjectDigest || snapshot.digest !== verdict.closure.payload.artifactInventoryDigest) throw new ReleaseBootError("installed artifact, graph subject and signed inventory are not one identity");
    const ownedAuthority = captureAuthority(boot.authority);
    const authority = verifyAuthorityClosure({ root: snapshot.root, ...ownedAuthority, ...(boot.scannerEnginePath === undefined ? {} : { scannerEnginePath: boot.scannerEnginePath as string }) });
    if (!authority.valid) throw new ReleaseBootError(`installed authority closure refused: ${authority.reason}`);
    const signedBindings = verdict.closure.payload;
    if (authority.graphDigest !== ownedAuthority.manifest.payload.artifactGraphDigest || ownedAuthority.manifest.payloadDigest !== signedBindings.effectManifestDigest || bundlePayloadDigest(ownedAuthority.policyBundle) !== signedBindings.policyBundleDigest || ownedAuthority.manifest.payload.scannerToolDigest !== signedBindings.scannerToolDigest || ownedAuthority.boundWaiverDigest !== signedBindings.authorityWaiverDigest || boot.providerDescriptorDigest !== signedBindings.providerDescriptorDigest) throw new ReleaseBootError("runtime authority/provider artifacts are not exactly the ones bound by the release closure");
    if ((profile !== "production" && profile !== "restricted") || verdict.admission.claimCeiling !== "Load-bearing") throw new ReleaseBootError("restricted dispatch requires a production/restricted Load-bearing closure");
    const expected = Object.freeze({ closureDigest: verdict.admission.closureDigest, graphDigest: verdict.admission.graphDigest, subjectDigest: verdict.admission.subjectDigest, releaseEpoch: verdict.admission.releaseEpoch, profile: verdict.admission.profile, claimCeiling: verdict.admission.claimCeiling, bootNonce: verdict.admission.bootNonce, issuedAtMs: verdict.admission.issuedAtMs });
    const admission = Object.freeze({ token: verdict.admission, expected, nowMs: sampleClock }); restrictedAdmissions.add(admission);
    if (!verifyRestrictedReleaseAdmission(admission)) throw new ReleaseBootError("boot admission was not current after installed verification");
    const authoritySnapshot = Object.freeze({ manifest: ownedAuthority.manifest, policyBundle: ownedAuthority.policyBundle, trust: ownedAuthority.trust });
    const runtime = Object.freeze({ admission, authority: authoritySnapshot, providerDescriptorDigest: signedBindings.providerDescriptorDigest, installedRoot: root }); restrictedRuntimes.add(runtime);
    return Object.freeze({ runtime, admission, artifactInventoryDigest: snapshot.digest, graph: verdict.graph, ledgers: verdict.effectiveLedgers });
  } finally { snapshot.dispose(); }
}

export function verifyRestrictedReleaseRuntime(runtime: RestrictedReleaseRuntime): boolean {
  return runtime !== null && typeof runtime === "object" && restrictedRuntimes.has(runtime as object) && verifyRestrictedReleaseAdmission(runtime.admission);
}

/** Single-use composition join: a valid runtime cannot be transferred from verified artifact A into executing code B. */
export function consumeRestrictedReleaseRuntimeForComposition(runtime: RestrictedReleaseRuntime, executingRoot: string, providerDescriptorDigest: string): boolean {
  try {
    if (!verifyRestrictedReleaseRuntime(runtime) || composedRuntimes.has(runtime as object) || runtime.installedRoot !== realpathSync(executingRoot) || runtime.providerDescriptorDigest !== providerDescriptorDigest) return false;
    composedRuntimes.add(runtime as object); return true;
  } catch { return false; }
}

export function verifyRestrictedReleaseAdmission(admission: RestrictedReleaseAdmission): boolean {
  try {
    if (admission === null || typeof admission !== "object" || !restrictedAdmissions.has(admission as object)) return false;
    const now = admission.nowMs(); const prior = lastVerifiedTimes.get(admission as object); if (prior !== undefined && now < prior) return false;
    const valid = (admission.expected.profile === "production" || admission.expected.profile === "restricted") && admission.expected.claimCeiling === "Load-bearing" && verifyReleaseAdmissionToken(admission.token, { ...admission.expected, nowMs: now });
    if (valid) lastVerifiedTimes.set(admission as object, now); return valid;
  } catch { return false; }
}
