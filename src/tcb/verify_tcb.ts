/**
 * verify-minimal-TCB (Core Addition A) — check that the trusted computing base is EXACTLY the
 * enumerated, minimal set and has not drifted.
 *
 * The TCB is "the minimal set of components that must function correctly to uphold the security
 * guarantees" — the deny-capable barriers + their composition. Per the definition, the TCB must be
 * assumed trustworthy because nothing else measures it; so the least we can do is verify the SET is
 * exactly what we signed off on, pin each member by content hash, and detect any drift.
 *
 * DRIFT = any of: an UNEXPECTED trusted module (the TCB grew — minimality violated), a MISSING trusted
 * module (the TCB shrank — a barrier removed), a CHANGED content hash (a trusted module was altered),
 * or a NEW dependency into a trusted module (the TCB silently expanded through an import). Any drift
 * fails safe.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - Minimal TCB / seL4: "exclude as much code as possible from the TCB"; smaller is verifiable. The
 *    manifest is the enumerated minimal set; an unexpected member is itself a finding.
 *  - Measured boot / TPM-PCR: "a hash computed on the observed sequence is validated against a known
 *    uncorrupted hash; a deviation indicates corruption." Here: pin each module's content hash; a
 *    recomputed hash that differs is drift.
 *  - Supply-chain integrity: "no unexpected import into the trusted core" — a new dependency expands
 *    the TCB, so allowed-deps are enumerated and a new one is drift.
 *
 * BUILT vs SEAM: BUILT is the in-env manifest + hash-pinned drift detection (the measured-boot analog,
 * over the source modules) + a spine-recorded self-check. The real EXTERNAL ATTESTATION of the RUNNING
 * binary — a TPM/TEE-signed measurement of the loaded code plus a remote verifier challenge (SGX/DICE/
 * TPM-quote class) — is a SEAM (R37), the same hardware-RoT / key-custody family as R25/R34. In-env we
 * measure the source, not the in-memory binary, and there is no signed remote attestation.
 *
 * WHAT WOULD CHANGE IT: adding a barrier to the TCB is a deliberate manifest change (re-pin), not a
 * silent drift; a real TEE quote upgrades measurement to attested. Neither lets a drift verify.
 */

import { createHash } from "node:crypto";

export interface TcbModule {
  readonly path: string;
  /** The pinned content hash (sha256 of the module source). */
  readonly pinnedHash: string;
  /** The dependencies (import specifiers) this trusted module is allowed to have. */
  readonly allowedDeps: readonly string[];
}

export interface TcbManifest {
  readonly modules: readonly TcbModule[];
}

/** An actual measurement of a module: its content hash + its real import specifiers. */
export interface MeasuredModule {
  readonly hash: string;
  readonly imports: readonly string[];
}

export type TcbVerification =
  | { readonly verified: true }
  | { readonly verified: false; readonly drifts: readonly string[] };

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Measure one module's source: content hash + import specifiers. Pure over the given source text. */
export function measureModule(source: string): MeasuredModule {
  const imports: string[] = [];
  const re = /^\s*import\s[^"']*["']([^"']+)["']/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) imports.push(m[1]!);
  return { hash: sha256Hex(source), imports };
}

/**
 * Verify the actual measured TCB against the pinned manifest. Total + pure. Any drift (unexpected /
 * missing module, changed hash, or new dependency) fails safe. `actual` maps path → measurement.
 */
export function verifyTcb(manifest: TcbManifest, actual: ReadonlyMap<string, MeasuredModule>): TcbVerification {
  const drifts: string[] = [];
  const manifestPaths = new Set(manifest.modules.map((m) => m.path));

  // Unexpected trusted module present in the measurement but not enumerated ⇒ the TCB grew.
  for (const path of actual.keys()) {
    if (!manifestPaths.has(path)) drifts.push(`unexpected-tcb-module:${path}`);
  }

  for (const mod of manifest.modules) {
    const meas = actual.get(mod.path);
    if (meas === undefined) {
      drifts.push(`missing-tcb-module:${mod.path}`); // a barrier was removed
      continue;
    }
    if (meas.hash !== mod.pinnedHash) {
      drifts.push(`changed-hash:${mod.path}`); // a trusted module was altered
    }
    const allowed = new Set(mod.allowedDeps);
    for (const dep of meas.imports) {
      if (!allowed.has(dep)) drifts.push(`new-dependency:${mod.path}->${dep}`); // TCB silently expanded
    }
  }

  if (drifts.length === 0) return { verified: true };
  return { verified: false, drifts };
}

/** A stable digest of the manifest (for pinning to the hash-chain). */
export function tcbManifestDigest(manifest: TcbManifest): string {
  const canon = manifest.modules
    .map((m) => `${m.path}|${m.pinnedHash}|${[...m.allowedDeps].sort().join(",")}`)
    .sort()
    .join("\n");
  return sha256Hex(canon);
}

/** Build a pinned manifest from a golden measurement + the allowed-deps per path. */
export function pinTcb(measured: ReadonlyMap<string, MeasuredModule>, allowedDepsByPath: Readonly<Record<string, readonly string[]>>): TcbManifest {
  const modules: TcbModule[] = [];
  for (const [path, meas] of measured) {
    modules.push({ path, pinnedHash: meas.hash, allowedDeps: allowedDepsByPath[path] ?? [...meas.imports] });
  }
  return { modules };
}

/** The enumerated minimal TCB: the eight gate barriers + their composition (nine modules). */
export const TCB_MODULE_PATHS: readonly string[] = [
  "src/floor/structural_floor.ts",
  "src/budget/budget_ledger.ts",
  "src/gate/composed_gate.ts",
  "src/optimizer/raise_only_clamp.ts",
  "src/ree/reversible_envelope.ts",
  "src/provenance/effect_provenance.ts",
  "src/twin/digital_twin.ts",
  "src/bom/ai_bom.ts",
  "src/identity/agent_identity.ts",
];

export interface TcbSelfCheckSpine {
  stage(input: { type: "identity.action"; actor: string; payload: Record<string, unknown> }): string;
}

/**
 * Startup self-check: verify the measured TCB against the manifest and record the result to the spine.
 * Returns `intact` (false on any drift) so a drifted TCB can become a deny-capable gate signal.
 */
export function runTcbSelfCheck(
  manifest: TcbManifest,
  actual: ReadonlyMap<string, MeasuredModule>,
  spine?: TcbSelfCheckSpine,
): { intact: boolean; drifts: readonly string[] } {
  const v = verifyTcb(manifest, actual);
  const drifts = v.verified ? [] : v.drifts;
  spine?.stage({
    type: "identity.action",
    actor: "tcb-self-check",
    payload: { event: v.verified ? "tcb.verified" : "tcb.drift", manifestDigest: tcbManifestDigest(manifest), drifts },
  });
  return { intact: v.verified, drifts };
}
