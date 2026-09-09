/**
 * Measured MONITOR BOUNDARY descriptor (Mechanical-Enforcement Increment 5).
 *
 * A signed, content-addressed measurement of the exact isolated-monitor image: the read-only rootfs digest, the kernel
 * digest + command line, the seccomp-profile digest, the config digest, and the vsock CID. `verifyBootDescriptor`
 * recomputes the measurement, checks it against the verifier's PINNED expected measurement (the appraisal — this is
 * what makes "alter the monitor image ⇒ attestation failure" true), and verifies the descriptor signature. The
 * descriptor's payload digest is the `bootDigest` the authenticated channel binds its session key to (channel.ts), so
 * a channel established against a different image cannot produce a single valid frame.
 *
 * SCOPE: this module verifies a supplied canonical measurement and signed descriptor.
 * Producing an actual measured image, applying seccomp/read-only mounts, and establishing
 * a hardware attestation quote require separately qualified deployment/attestation paths.
 * A valid descriptor alone does not prove those protections were active on a host.
 *
 * Grounding: measured boot; reference-monitor tamper resistance; SLSA-style signed measurement; content-addressed
 * identity (Increment 1); domain separation.
 */
import { timingSafeEqual } from "node:crypto";
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { stubSign, type Signature, type Signer, type TrustPolicy } from "../bom/bom_signing.js";

/** Constant-time equality of two ascii signatures (avoids leaking match progress via early-exit string ===). */
function ctEq(a: string, b: string): boolean { const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b); return x.length === y.length && timingSafeEqual(x, y); }

export const BOOT_DESCRIPTOR = { name: "keep.monitor.boot", version: "5.0.0" } as const;
const HEX64 = /^[0-9a-f]{64}$/;

export class BoundaryError extends Error { constructor(m: string) { super(`monitor boundary: ${m}`); this.name = "BoundaryError"; } }
function safeMsg(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; } }

/** The measured components of the isolated monitor image. Every field is part of its identity. */
export interface MonitorMeasurement {
  readonly rootfsDigest: string;   // 64-hex; the read-only rootfs
  readonly kernelDigest: string;   // 64-hex
  readonly cmdline: string;        // NFC kernel command line
  readonly seccompDigest: string;  // 64-hex; the applied seccomp profile
  readonly configDigest: string;   // 64-hex; the Firecracker machine config
  readonly vsockCid: bigint;       // the guest CID (>=3)
}

const isHex64 = (x: unknown): x is string => typeof x === "string" && HEX64.test(x);

/** Validate a measurement against its closed schema. Throws BoundaryError. */
export function validateMeasurement(m: unknown): MonitorMeasurement {
  if (m === null || typeof m !== "object" || Array.isArray(m)) throw new BoundaryError("measurement must be an object");
  const o = m as Record<string, unknown>;
  const allowed = ["rootfsDigest", "kernelDigest", "cmdline", "seccompDigest", "configDigest", "vsockCid"];
  for (const k of Object.keys(o)) if (!allowed.includes(k)) throw new BoundaryError(`unknown field "${k}"`);
  for (const k of ["rootfsDigest", "kernelDigest", "seccompDigest", "configDigest"]) if (!isHex64(o[k])) throw new BoundaryError(`${k} must be 64-hex`);
  if (typeof o.cmdline !== "string" || o.cmdline.length === 0 || !isWellFormedText(o.cmdline) || o.cmdline.normalize("NFC") !== o.cmdline) throw new BoundaryError("cmdline must be non-empty NFC text");
  if (typeof o.vsockCid !== "bigint" || o.vsockCid < 3n) throw new BoundaryError("vsockCid must be an int >= 3");
  return { rootfsDigest: o.rootfsDigest as string, kernelDigest: o.kernelDigest as string, cmdline: o.cmdline, seccompDigest: o.seccompDigest as string, configDigest: o.configDigest as string, vsockCid: o.vsockCid };
}

function measurementCanonical(m: MonitorMeasurement): CanonicalValue {
  const v = validateMeasurement(m);
  return { rootfsDigest: v.rootfsDigest, kernelDigest: v.kernelDigest, cmdline: v.cmdline, seccompDigest: v.seccompDigest, configDigest: v.configDigest, vsockCid: v.vsockCid };
}
/** Content-derived digest of a measurement — the value the verifier pins as its appraisal. */
export function measurementDigest(m: MonitorMeasurement): string { return eirDigest("keep.monitor.measurement.v1", measurementCanonical(m)); }

export interface BootDescriptorPayload {
  readonly descriptorVersion: 1;
  readonly builder: { readonly name: string; readonly version: string };
  readonly measurement: MonitorMeasurement;
  readonly measurementDigest: string; // self-consistent = measurementDigest(measurement)
}
export interface SignedBootDescriptor {
  readonly payload: BootDescriptorPayload;
  readonly payloadDigest: string;
  readonly signatures: readonly Signature[];
}
export interface BootSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }
export type BootVerdict = { readonly valid: true; readonly signerCount: number; readonly bootDigest: string; readonly descriptor: SignedBootDescriptor } | { readonly valid: false; readonly reason: string };

const payloadDigestOf = (p: BootDescriptorPayload): string => eirDigest("keep.monitor.boot.payload/v1", payloadCanonical(p));
const signPreimageOf = (payloadDigest: string): string => eirDigest("keep.monitor.boot.signature-preimage/v1", { payloadDigest });

/** Compile a signed boot descriptor for a measurement. Self-verifies (fail-closed). */
export function compileBootDescriptor(measurement: MonitorMeasurement, signers: readonly BootSigner[], threshold = signers.length): SignedBootDescriptor {
  if (signers.length === 0) throw new BoundaryError("at least one signer is required");
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) throw new BoundaryError(`threshold must be in [1, ${signers.length}]`);
  const keyids = new Set<string>();
  for (const s of signers) { if (keyids.has(s.keyid)) throw new BoundaryError(`duplicate signer keyid "${s.keyid}"`); keyids.add(s.keyid); }
  const m = validateMeasurement(measurement);
  const payload: BootDescriptorPayload = {
    descriptorVersion: 1, builder: { name: BOOT_DESCRIPTOR.name, version: BOOT_DESCRIPTOR.version },
    measurement: m, measurementDigest: measurementDigest(m),
  };
  const payloadDigest = payloadDigestOf(payload);
  const preimage = signPreimageOf(payloadDigest);
  const signatures = signers.map((s) => {
    const sig = s.signer.sign(preimage);
    if (sig === null || typeof sig !== "object" || sig.keyid !== s.keyid || typeof sig.sig !== "string") throw new BoundaryError(`signer for "${s.keyid}" returned a malformed/foreign signature`);
    if (sig.sig !== stubSign(s.verifyKey, s.keyid, preimage).sig) throw new BoundaryError(`signer for "${s.keyid}" produced an invalid signature`);
    return { keyid: sig.keyid, sig: sig.sig };
  }).sort((a, b) => (a.keyid < b.keyid ? -1 : a.keyid > b.keyid ? 1 : 0));
  const descriptor: SignedBootDescriptor = { payload, payloadDigest, signatures };
  const trust: TrustPolicy = { trustedKeys: new Map(signers.map((s) => [s.keyid, s.verifyKey] as const)), threshold };
  const v = verifyBootDescriptor(descriptor, { trust, expectedMeasurementDigest: payload.measurementDigest });
  if (!v.valid) throw new BoundaryError(`compiler produced a descriptor that does not verify: ${v.reason}`);
  return descriptor;
}

const exactKeys = (o: unknown, allowed: readonly string[]): boolean =>
  o !== null && typeof o === "object" && !Array.isArray(o) && (() => { const k = Object.keys(o).sort(); const a = [...allowed].sort(); return k.length === a.length && k.every((x, i) => x === a[i]); })();

/** Capture the caller descriptor into an owned read-once snapshot (TOCTOU-safe). */
function captureDescriptor(signed: unknown): SignedBootDescriptor {
  if (signed === null || typeof signed !== "object") throw new BoundaryError("descriptor must be an object");
  const s = signed as Record<string, unknown>;
  if (!exactKeys(s, ["payload", "payloadDigest", "signatures"])) throw new BoundaryError("malformed descriptor envelope");
  if (typeof s.payloadDigest !== "string") throw new BoundaryError("payloadDigest must be a string");
  if (!Array.isArray(s.signatures) || s.signatures.length === 0) throw new BoundaryError("signatures must be a non-empty array");
  const signatures = s.signatures.map((x) => {
    if (!exactKeys(x, ["keyid", "sig"])) throw new BoundaryError("malformed signature entry");
    const so = x as Record<string, unknown>;
    if (typeof so.keyid !== "string" || typeof so.sig !== "string") throw new BoundaryError("malformed signature entry");
    return Object.freeze({ keyid: so.keyid, sig: so.sig });
  });
  const p = s.payload as Record<string, unknown>;
  if (!exactKeys(p, ["descriptorVersion", "builder", "measurement", "measurementDigest"])) throw new BoundaryError("payload has unexpected or missing fields");
  if (!exactKeys(p.builder, ["name", "version"])) throw new BoundaryError("builder has unexpected fields");
  const bo = p.builder as Record<string, unknown>;
  const payload: BootDescriptorPayload = Object.freeze({
    descriptorVersion: p.descriptorVersion as 1,
    builder: Object.freeze({ name: bo.name as string, version: bo.version as string }),
    measurement: Object.freeze(validateMeasurement(p.measurement)),
    measurementDigest: p.measurementDigest as string,
  });
  return Object.freeze({ payload, payloadDigest: s.payloadDigest, signatures: Object.freeze(signatures) });
}

/**
 * Verify a signed boot descriptor: recompute the measurement digest, require it to equal the payload's claim AND the
 * verifier's PINNED expected measurement (the appraisal — altering the image changes the measurement and fails here),
 * recompute the payload digest, and count valid signatures against the threshold. TOTAL + fail-safe. On success
 * returns `bootDigest` (= the verified payload digest) to seed the authenticated channel's session key.
 */
export function verifyBootDescriptor(signed: SignedBootDescriptor, opts: { trust: TrustPolicy; expectedMeasurementDigest: string }): BootVerdict {
  try {
    // Capture every opts field ONCE into an immutable local (getter/Proxy-backed opts must not present one value to
    // validation and another to the check — a TOCTOU bypass of the pin / threshold).
    const trust = opts?.trust;
    const rawKeys = trust?.trustedKeys; // read ONCE before validating/cloning (a getter must not swap the map)
    if (!(rawKeys instanceof Map)) return { valid: false, reason: "trust.trustedKeys must be a Map" };
    const trustedKeys = new Map(rawKeys); // owned snapshot of the captured map
    const threshold = trust.threshold;
    if (!Number.isInteger(threshold) || threshold < 1) return { valid: false, reason: "invalid-threshold" };
    const expectedMeasurementDigest = opts.expectedMeasurementDigest;
    if (typeof expectedMeasurementDigest !== "string" || !HEX64.test(expectedMeasurementDigest)) return { valid: false, reason: "expectedMeasurementDigest must be 64-hex (the pinned appraisal)" };
    let snap: SignedBootDescriptor;
    try { snap = captureDescriptor(signed); } catch (e) { return { valid: false, reason: safeMsg(e) }; }
    if (snap.signatures.some((s, i) => i > 0 && s.keyid <= snap.signatures[i - 1]!.keyid)) return { valid: false, reason: "signatures not canonically sorted / duplicate keyid" };
    const p = snap.payload;
    if (p.descriptorVersion !== 1) return { valid: false, reason: "unsupported descriptorVersion" };
    if (p.builder.name !== BOOT_DESCRIPTOR.name || p.builder.version !== BOOT_DESCRIPTOR.version) return { valid: false, reason: "unsupported builder identity" };
    // APPRAISAL: the measured image must match the pinned expected measurement, and the payload's own claim.
    const recomputed = measurementDigest(p.measurement);
    if (recomputed !== p.measurementDigest) return { valid: false, reason: "measurementDigest does not match the measurement" };
    if (recomputed !== expectedMeasurementDigest) return { valid: false, reason: "monitor image measurement does not match the pinned appraisal (image altered)" };
    const recomputedPayload = payloadDigestOf(p);
    if (recomputedPayload !== snap.payloadDigest) return { valid: false, reason: "payload digest mismatch" };
    const preimage = signPreimageOf(recomputedPayload);
    let valid = 0;
    const seen = new Set<string>();
    for (const s of snap.signatures) {
      const key = trustedKeys.get(s.keyid);
      if (key === undefined || seen.has(s.keyid)) continue;
      if (ctEq(s.sig, stubSign(key, s.keyid, preimage).sig)) { seen.add(s.keyid); valid++; }
    }
    if (valid < threshold) return { valid: false, reason: `threshold-not-met:${valid}<${threshold}` };
    return { valid: true, signerCount: valid, bootDigest: recomputedPayload, descriptor: snap };
  } catch (e) {
    return { valid: false, reason: `verify error: ${safeMsg(e)}` };
  }
}

function payloadCanonical(p: BootDescriptorPayload): CanonicalValue {
  return {
    descriptorVersion: BigInt(p.descriptorVersion),
    builder: { name: p.builder.name, version: p.builder.version },
    measurement: measurementCanonical(p.measurement),
    measurementDigest: p.measurementDigest,
  };
}
