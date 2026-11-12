/**
 * Bind an effect-ownership scan to a signed source manifest and a shrinking legacy waiver.
 * The gate verifies the manifest, derives its owner map, checks the scanner runtime identity and
 * runs the scan against the supplied root. The observed graph digest must match artifactGraphDigest.
 *
 * A waiver records allowed occurrences by file, family and construct. Its generation and predecessor
 * bind it to the prior release, and each occurrence count must stay within that baseline. The trusted
 * boundWaiverDigest and previousReleaseHead prevent substituting an older, larger allowance.
 *
 * The binding covers the source files scanned by the walker. Native addons, WebAssembly and other
 * non-source loader targets need separate artifact protection. The gate trusts the pinned scanner's
 * semantics, configured keys and release-state bindings. Its reference signature verifier uses the
 * shared-key stub from bom_signing.ts; asymmetric verification and protected key custody are separate
 * implementation work.
 *
 * The host must bind root to the actual workload and keep both the workload and scanner runtime
 * immutable between verification and use. Scanner dependency and executable bytes are measured;
 * the native loader and shared-library closure remain part of the trusted host. A valid ownership
 * scan also leaves authority passed through exported helpers or globals outside its routing checks.
 * Complete mediation requires confinement of those handles and a separate workload boundary.
 *
 * The design uses artifact-to-attestation binding from SLSA/in-toto, content-addressed identity and
 * an allowlist whose accepted counts can only decrease.
 */
import { readFileSync, realpathSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { stubSign, type Signature, type Signer, type TrustPolicy } from "../bom/bom_signing.js";
import { verifyEffectManifest, ownersOf, type SignedEffectManifest } from "./effect_manifest.js";
import { scanEffects, type EffectScanResult } from "./effect_scan_port.js";
import type { SignedBundle } from "../policy/compiler.js";

const HEX64 = /^[0-9a-f]{64}$/;
/**
 * Default scanner entry path. The gate checks its execution closure against the manifest's
 * scannerToolDigest before accepting scan results.
 */
export const defaultEnginePath = (): string => realpathSync(join(process.cwd(), "tools", "effect_sweep.mjs"));
function pathOnReadOnlyMount(path: string): boolean {
  if (process.platform !== "linux") return false;
  try { const unescape = (value: string): string => value.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\012/g, "\n").replace(/\\134/g, "\\"); const rows = readFileSync("/proc/self/mountinfo", "utf8").split("\n").filter(Boolean).map((line) => { const fields = line.split(" - ")[0]!.split(" "); return { point: unescape(fields[4]!), options: new Set(fields[5]!.split(",")) }; }).filter((row) => path === row.point || path.startsWith(row.point === "/" ? "/" : `${row.point}/`)).sort((a, b) => b.point.length - a.point.length); return rows[0]?.options.has("ro") === true; } catch { return false; }
}
function scannerRuntimePaths(enginePath = defaultEnginePath()): readonly string[] {
  const canonicalEngine = realpathSync(enginePath); const engineRequire = createRequire(pathToFileURL(canonicalEngine).href); const paths = [canonicalEngine, process.execPath, engineRequire.resolve("typescript")].map((path) => realpathSync(path));
  if (paths.some((path) => !statSync(path).isFile())) throw new AuthorityGateError("scanner runtime component is not a regular file");
  return Object.freeze(paths);
}
/** Production precondition: every directly executed/read scanner component is on a kernel-observed read-only mount.
 * The loader/shared-library closure remains explicitly part of the attested host OS TCB. */
export function scannerRuntimeReadOnly(enginePath = defaultEnginePath()): boolean { return scannerRuntimePaths(enginePath).every(pathOnReadOnlyMount); }
/** Identity of the actual hermetic scanner execution closure, not merely its entry script. TypeScript is a monolithic
 * runtime here; Node executable bytes, TS runtime bytes, entry bytes and fixed interpreter flags are all committed. */
export function scannerRuntimeDigest(enginePath = defaultEnginePath()): string {
  const [engine, nodeExecutable, tsRuntime] = scannerRuntimePaths(enginePath);
  const hashFile = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");
  return eirDigest("keep.effect-scanner-runtime/v1", { engine: hashFile(engine!), nodeExecutable: hashFile(nodeExecutable!), typescriptRuntime: hashFile(tsRuntime!), interpreterFlags: ["--disable-proto=throw"], environmentPolicy: "empty-except-windows-systemroot-v1", nativeLoaderClosure: "attested-host-os-tcb" });
}

export class AuthorityGateError extends Error { constructor(m: string) { super(`authority gate: ${m}`); this.name = "AuthorityGateError"; } }
function safeMsg(e: unknown): string { try { const s = String((e as { message?: unknown })?.message ?? e); return s.length > 200 ? s.slice(0, 200) : s; } catch { return "unknown"; } }

/**
 * A permitted legacy unowned-effect site. count bounds occurrences of this file/family/construct;
 * an additional occurrence exceeds the waiver.
 */
export interface WaiverEntry { readonly file: string; readonly family: string; readonly construct: string; readonly count: number; readonly reason: string; }
export interface WaiverPayload { readonly version: 1; readonly generation: number; readonly predecessorDigest: string; readonly entries: readonly WaiverEntry[]; }
export interface SignedWaiver { readonly payload: WaiverPayload; readonly payloadDigest: string; readonly signatures: readonly Signature[]; }
export interface WaiverSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }

export type AuthorityClosureVerdict =
  | { readonly valid: true; readonly generation: number; readonly waivedSites: number; readonly graphDigest: string }
  | { readonly valid: false; readonly reason: string };

const isTextField = (s: unknown): s is string => typeof s === "string" && s.length > 0 && s.length <= 1024 && isWellFormedText(s) && s.normalize("NFC") === s;
const isCount = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 1_000_000;
const isGen = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 1_000_000_000;
/** The stable identity of a waiver site / finding: file+family+construct (line/occurrence-independent; multiplicity is the count). */
const siteKey = (e: { file: string; family: string; construct: string }): string => eirDigest("keep.authority.waiver-site/v1", { file: e.file, family: e.family, construct: e.construct });

function waiverPayloadCanonical(p: WaiverPayload): CanonicalValue {
  return {
    version: BigInt(p.version), generation: BigInt(p.generation), predecessorDigest: p.predecessorDigest,
    entries: [...p.entries].map((e) => ({ file: e.file, family: e.family, construct: e.construct, count: BigInt(e.count), reason: e.reason })).sort((a, b) => (siteKey(a) < siteKey(b) ? -1 : siteKey(a) > siteKey(b) ? 1 : 0)),
  };
}
const waiverPayloadDigest = (p: WaiverPayload): string => eirDigest("keep.authority.waiver/v1", waiverPayloadCanonical(p));
const waiverSignPreimage = (payloadDigest: string): string => eirDigest("keep.authority.waiver.signature-preimage/v1", { payloadDigest });

/** Compile + sign a waiver (mirrors the effect manifest's signing discipline). `predecessorDigest` "" ⇒ genesis (generation 0). */
export function compileWaiver(chain: { generation: number; predecessorDigest: string }, entries: readonly WaiverEntry[], signers: readonly WaiverSigner[], threshold = signers.length): SignedWaiver {
  if (signers.length === 0) throw new AuthorityGateError("at least one signer is required");
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) throw new AuthorityGateError(`threshold must be in [1, ${signers.length}]`);
  if (!isGen(chain.generation)) throw new AuthorityGateError("generation must be a non-negative integer");
  if (chain.predecessorDigest !== "" && !HEX64.test(chain.predecessorDigest)) throw new AuthorityGateError("predecessorDigest must be 64-hex or \"\"");
  if ((chain.predecessorDigest === "") !== (chain.generation === 0)) throw new AuthorityGateError("genesis ⇔ (generation 0 AND predecessorDigest \"\")");
  const keyids = new Set<string>();
  for (const s of signers) { if (keyids.has(s.keyid)) throw new AuthorityGateError(`duplicate signer keyid "${s.keyid}"`); keyids.add(s.keyid); }
  const seen = new Set<string>();
  for (const e of entries) { if (!isTextField(e.file) || !isTextField(e.family) || !isTextField(e.construct) || !isTextField(e.reason) || !isCount(e.count)) throw new AuthorityGateError("a waiver entry field is malformed"); const k = siteKey(e); if (seen.has(k)) throw new AuthorityGateError(`duplicate waiver site ${e.file} ${e.family} (${e.construct})`); seen.add(k); }
  const payload: WaiverPayload = { version: 1, generation: chain.generation, predecessorDigest: chain.predecessorDigest, entries: [...entries].map((e) => ({ file: e.file, family: e.family, construct: e.construct, count: e.count, reason: e.reason })) };
  const payloadDigest = waiverPayloadDigest(payload);
  const preimage = waiverSignPreimage(payloadDigest);
  const signatures = signers.map((s) => {
    const sig = s.signer.sign(preimage);
    if (sig === null || typeof sig !== "object" || sig.keyid !== s.keyid || typeof sig.sig !== "string") throw new AuthorityGateError(`signer for "${s.keyid}" returned a malformed/foreign signature`);
    if (sig.sig !== stubSign(s.verifyKey, s.keyid, preimage).sig) throw new AuthorityGateError(`signer for "${s.keyid}" produced an invalid signature`);
    return { keyid: sig.keyid, sig: sig.sig };
  }).sort((a, b) => (a.keyid < b.keyid ? -1 : a.keyid > b.keyid ? 1 : 0));
  return { payload, payloadDigest, signatures };
}

const exactKeys = (o: unknown, allowed: readonly string[]): boolean =>
  o !== null && typeof o === "object" && !Array.isArray(o) && (() => { const k = Object.keys(o).sort(); const a = [...allowed].sort(); return k.length === a.length && k.every((x, i) => x === a[i]); })();

/** Validate and copy a waiver so later caller mutations cannot change the checked snapshot. */
export function captureSignedWaiver(signed: unknown): SignedWaiver {
  if (signed === null || typeof signed !== "object") throw new AuthorityGateError("waiver must be an object");
  const s = signed as Record<string, unknown>;
  if (!exactKeys(s, ["payload", "payloadDigest", "signatures"])) throw new AuthorityGateError("malformed waiver envelope");
  if (typeof s.payloadDigest !== "string") throw new AuthorityGateError("payloadDigest must be a string");
  if (!Array.isArray(s.signatures) || s.signatures.length === 0) throw new AuthorityGateError("signatures must be a non-empty array");
  const signatures = s.signatures.map((x) => { if (!exactKeys(x, ["keyid", "sig"])) throw new AuthorityGateError("malformed signature"); const so = x as Record<string, unknown>; if (typeof so.keyid !== "string" || typeof so.sig !== "string") throw new AuthorityGateError("malformed signature"); return Object.freeze({ keyid: so.keyid, sig: so.sig }); });
  const p = s.payload;
  if (!exactKeys(p, ["version", "generation", "predecessorDigest", "entries"])) throw new AuthorityGateError("malformed waiver payload");
  const po = p as Record<string, unknown>;
  if (po.version !== 1) throw new AuthorityGateError("unsupported waiver version");
  if (!isGen(po.generation)) throw new AuthorityGateError("malformed generation");
  if (typeof po.predecessorDigest !== "string" || (po.predecessorDigest !== "" && !HEX64.test(po.predecessorDigest))) throw new AuthorityGateError("malformed predecessorDigest");
  if ((po.predecessorDigest === "") !== (po.generation === 0)) throw new AuthorityGateError("genesis inconsistency");
  if (!Array.isArray(po.entries)) throw new AuthorityGateError("entries must be an array");
  const seen = new Set<string>();
  const entries = po.entries.map((e) => {
    if (!exactKeys(e, ["file", "family", "construct", "count", "reason"])) throw new AuthorityGateError("malformed waiver entry");
    const eo = e as Record<string, unknown>;
    if (!isTextField(eo.file) || !isTextField(eo.family) || !isTextField(eo.construct) || !isTextField(eo.reason) || !isCount(eo.count)) throw new AuthorityGateError("malformed waiver entry field");
    const k = siteKey({ file: eo.file as string, family: eo.family as string, construct: eo.construct as string });
    if (seen.has(k)) throw new AuthorityGateError("duplicate waiver site"); seen.add(k);
    return Object.freeze({ file: eo.file as string, family: eo.family as string, construct: eo.construct as string, count: eo.count as number, reason: eo.reason as string });
  });
  return Object.freeze({ payload: Object.freeze({ version: 1 as const, generation: po.generation as number, predecessorDigest: po.predecessorDigest, entries: Object.freeze(entries) }), payloadDigest: s.payloadDigest, signatures: Object.freeze(signatures) });
}

/** Verify a signed waiver's signatures + self-consistent digest against a trust policy. Total; returns an owned snapshot or null. */
function verifyWaiverSigned(signed: unknown, trust: TrustPolicy): SignedWaiver | null {
  let snap: SignedWaiver;
  try { snap = captureSignedWaiver(signed); } catch { return null; }
  if (waiverPayloadDigest(snap.payload) !== snap.payloadDigest) return null;
  const rawKeys = trust?.trustedKeys; if (!(rawKeys instanceof Map)) return null;
  const trustedKeys = new Map(rawKeys); const threshold = trust.threshold;
  if (!Number.isInteger(threshold) || threshold < 1) return null;
  if (snap.signatures.some((s, i) => i > 0 && s.keyid <= snap.signatures[i - 1]!.keyid)) return null; // sorted / no dup
  const preimage = waiverSignPreimage(snap.payloadDigest);
  let valid = 0; const seen = new Set<string>();
  for (const s of snap.signatures) { const key = trustedKeys.get(s.keyid); if (key === undefined || seen.has(s.keyid)) continue; if (s.sig === stubSign(key, s.keyid, preimage).sig) { seen.add(s.keyid); valid++; } }
  return valid >= threshold ? snap : null;
}

const countMap = (entries: readonly WaiverEntry[]): Map<string, number> => { const m = new Map<string, number>(); for (const e of entries) m.set(siteKey(e), e.count); return m; };

/**
 * Scan the supplied source tree and check its manifest binding and generation-linked waiver.
 * Malformed inputs, verification failures, scanner errors, digest mismatches, excess findings and
 * growing waivers return valid:false. Acceptance covers the scanned source and declared owner map.
 */
export function verifyAuthorityClosure(opts: {
  root: string;                                              // the DEPLOYED src dir the gate RE-scans itself
  manifest: SignedEffectManifest;                            // signed effect manifest (verified here) — owner map + artifactGraphDigest
  policyBundle: SignedBundle;
  trust: { manifestTrust: TrustPolicy; policyTrust?: TrustPolicy };
  waiver: unknown;                                           // current signed waiver (PINNED by boundWaiverDigest)
  baseline: unknown;                                         // predecessor signed waiver (the chain link)
  boundWaiverDigest: string;                                 // trusted release binding of the CURRENT waiver's digest
  previousReleaseHead: string;                               // trusted release binding of the PREVIOUS waiver's digest ("" = one-time genesis bootstrap)
  waiverTrust: TrustPolicy;                                  // who may sign a waiver
  scannerEnginePath?: string;                                // deployment verifier; its complete runtime digest is signed
}): AuthorityClosureVerdict {
  try {
    // [1] MANIFEST — verify + derive the SIGNED owner map and the bound artifact digest (a poisoned owner map needs a key).
    if (typeof opts.root !== "string" || opts.root.length === 0) return { valid: false, reason: "root must be a non-empty path" };
    if (typeof opts.boundWaiverDigest !== "string" || !HEX64.test(opts.boundWaiverDigest)) return { valid: false, reason: "boundWaiverDigest is not 64-hex" };
    if (typeof opts.previousReleaseHead !== "string" || (opts.previousReleaseHead !== "" && !HEX64.test(opts.previousReleaseHead))) return { valid: false, reason: "previousReleaseHead must be 64-hex or \"\"" };
    const mv = verifyEffectManifest(opts.manifest, opts.policyBundle, opts.trust);
    if (!mv.valid) return { valid: false, reason: `effect manifest does not verify: ${mv.reason}` };
    const owners = ownersOf(mv.manifest);
    const boundGraphDigest = mv.manifest.payload.artifactGraphDigest;
    if (!HEX64.test(boundGraphDigest)) return { valid: false, reason: "manifest artifactGraphDigest is not 64-hex" };
    // [1a] SCANNER ENGINE — the engine the gate is about to run MUST be the one the manifest pinned (scannerToolDigest),
    //      so a tampered/foreign engine cannot fabricate a clean scan. Not caller-overridable.
    const scannerToolDigest = mv.manifest.payload.scannerToolDigest;
    if (!HEX64.test(scannerToolDigest)) return { valid: false, reason: "manifest scannerToolDigest is not 64-hex" };
    const enginePath = opts.scannerEnginePath === undefined ? defaultEnginePath() : realpathSync(opts.scannerEnginePath);
    let engineD: string;
    try { engineD = scannerRuntimeDigest(enginePath); } catch (e) { return { valid: false, reason: `cannot identify the scanner runtime (fail-closed): ${safeMsg(e)}` }; }
    if (engineD !== scannerToolDigest) return { valid: false, reason: `scanner engine mismatch: running ${engineD.slice(0, 12)}… ≠ signed ${scannerToolDigest.slice(0, 12)}… (tampered/foreign scanner)` };

    // [2] CURRENT WAIVER — verify + PIN to the trusted release binding (a substituted current waiver is rejected).
    const waiver = verifyWaiverSigned(opts.waiver, opts.waiverTrust);
    if (waiver === null) return { valid: false, reason: "current waiver does not verify (signature/trust/shape)" };
    if (waiver.payloadDigest !== opts.boundWaiverDigest) return { valid: false, reason: "current waiver is not the one pinned by boundWaiverDigest" };

    // [3] BASELINE — anchored to the TRUSTED PREVIOUS RELEASE HEAD (not a caller-chosen predecessor), so a fresh genesis
    //     or an older/larger signed baseline cannot re-open paid-down debt: the ratchet binds across the ACTUAL release
    //     history, even the signer. `previousReleaseHead` is the deployment's monotonic release-state head ("" bootstraps once).
    const baseline = verifyWaiverSigned(opts.baseline, opts.waiverTrust);
    if (baseline === null) return { valid: false, reason: "baseline waiver does not verify (signature/trust/shape)" };
    if (opts.previousReleaseHead === "") {
      if (waiver.payload.predecessorDigest !== "" || waiver.payload.generation !== 0) return { valid: false, reason: "genesis bootstrap requires generation 0 and predecessorDigest \"\"" };
      if (baseline.payloadDigest !== waiver.payloadDigest) return { valid: false, reason: "genesis waiver must be its own baseline" };
    } else {
      if (baseline.payloadDigest !== opts.previousReleaseHead) return { valid: false, reason: "baseline is not the TRUSTED previous release head" };
      if (waiver.payload.predecessorDigest !== opts.previousReleaseHead) return { valid: false, reason: "current waiver does not name the trusted previous release head as its predecessor" };
      if (waiver.payload.generation !== baseline.payload.generation + 1) return { valid: false, reason: `generation must increment by exactly 1 (got ${waiver.payload.generation} after ${baseline.payload.generation})` };
    }
    const waiverCounts = countMap(waiver.payload.entries);
    const baselineCounts = countMap(baseline.payload.entries);
    // [4] MONOTONE SHRINK — every current waiver SITE must be in the baseline with a count that did not grow.
    for (const e of waiver.payload.entries) { const k = siteKey(e); const b = baselineCounts.get(k); if (b === undefined) return { valid: false, reason: `waiver grew: ${e.file} ${e.family} (${e.construct}) is not in the baseline — new debt must go behind an owner, not the waiver` }; if (e.count > b) return { valid: false, reason: `waiver count grew for ${e.file} ${e.family} (${e.construct}): ${e.count} > baseline ${b}` }; }

    // [5] SCAN — the gate RE-scans the deployed tree ITSELF with the SIGNED owner map, via the PINNED engine (fail-closed).
    let scan: EffectScanResult;
    try { scan = scanEffects({ root: opts.root, owners, enginePath }); }
    catch (e) { return { valid: false, reason: `effect scan failed (fail-closed): ${safeMsg(e)}` }; }
    if (!HEX64.test(scan.graphDigest)) return { valid: false, reason: "scan graph digest is not 64-hex" };
    // [6] ARTIFACT BINDING — the deployed source graph must be EXACTLY the one the signed manifest committed to (a scan of
    //     an IMMUTABLE deployed artifact — RO-mount/sealed image is the substrate seam that keeps it immutable to execution).
    if (scan.graphDigest !== boundGraphDigest) return { valid: false, reason: `artifact mismatch: deployed graph ${scan.graphDigest.slice(0, 12)}… ≠ signed ${boundGraphDigest.slice(0, 12)}… (sign-clean-deploy-dirty / tampered tree)` };

    // [7] EXACT COVERAGE — the waiver must EXACTLY mirror the observed unowned-effect debt: every observed SITE is waived
    //     with count === its occurrence count, AND every waiver SITE actually occurs that many times. Exact (not ≤) so a
    //     paid-down allowance leaves NO headroom for a later occurrence to regrow into (the ratchet binds even the signer).
    const occ = new Map<string, number>();
    for (const f of scan.findings) { const k = siteKey(f); occ.set(k, (occ.get(k) ?? 0) + 1); }
    for (const [k, n] of occ) { const w = waiverCounts.get(k); if (w !== n) { const f = scan.findings.find((x) => siteKey(x) === k)!; return { valid: false, reason: `unwaived/miscounted unowned effect: ${f.file} ${f.family} (${f.construct}) occurs ×${n}${w === undefined ? " (not waived)" : ` but waived ×${w}`} — route it through its family's broker owner, or waive it EXACTLY (within the baseline)` }; } }
    for (const e of waiver.payload.entries) { const n = occ.get(siteKey(e)) ?? 0; if (n !== e.count) return { valid: false, reason: `stale waiver entry: ${e.file} ${e.family} (${e.construct}) waived ×${e.count} but occurs ×${n} — a paid-down site must be REMOVED from the waiver (no dormant allowance)` }; }
    return { valid: true, generation: waiver.payload.generation, waivedSites: waiver.payload.entries.length, graphDigest: scan.graphDigest };
  } catch (e) {
    return { valid: false, reason: `authority closure error: ${safeMsg(e)}` };
  }
}
