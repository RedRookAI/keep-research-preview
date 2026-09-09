/**
 * Backup: verifyRestore + off-machine target prompt (Increment 9b).
 *
 * SOTA basis (2026-08-04): the "0" in 3-2-1-1-0 = zero unverified restores — "a backup that has never
 * been tested is not a backup" (AvePoint/CISA 2026). So verifyRestore is a first-class CHECKED
 * property, not polish: it re-verifies the restored hash-chain (catching truncation/tampering via the
 * existing verifyChain) AND confirms the recomputed content root matches the snapshot's expected
 * root. A restore that cannot be proven complete FAILS loudly rather than silently returning partial
 * data (the Eon "backups deleted in nine seconds" failure surfaces here as a verification failure).
 *
 * The off-machine prompt surfaces FREE options first (no lock-in, air-gap default): a private git
 * repo, then any S3-compatible/rsync target the operator controls, then paid only if materially
 * better. It is IGNORABLE and re-surfaced on a cadence — never blocking, never nagging. Zero deps.
 */

import type { SealedBlock, VerifyResult } from "../spine/hashchain.js";
import { verifyChain } from "../spine/hashchain.js";
import type { Snapshot, BackupPort, Hasher } from "./backup_port.js";
import { buildSnapshot } from "./backup_port.js";

export interface RestoreVerification {
  readonly ok: boolean;
  /** The recomputed content root of the restored blocks. */
  readonly recomputedRoot: string;
  /** The expected content root from the snapshot. */
  readonly expectedRoot: string;
  /** Whether the recomputed root matched the expected root. */
  readonly rootMatches: boolean;
  /** The chain-integrity result (seq/link/tamper checks). */
  readonly chain: VerifyResult;
  readonly reason: string;
}

/**
 * Verify a restore is provably complete + untampered (the +0 property). Runs BOTH checks:
 *  1. chain integrity via verifyChain (seq gaps/truncation, broken links, event & block tampering);
 *  2. content-root match: recompute the snapshot from the restored blocks and confirm its root equals
 *     the expected root. A mismatch means the restore is incomplete or altered → NOT ok.
 */
export function verifyRestore(restored: readonly SealedBlock[], expectedRoot: string, hasher: Hasher, now = Date.now()): RestoreVerification {
  const chain = verifyChain(restored);
  const recomputed = buildSnapshot(restored, hasher, now);
  const rootMatches = recomputed.contentRoot === expectedRoot;

  const ok = chain.ok && rootMatches;
  let reason: string;
  if (!chain.ok) {
    reason = `chain integrity FAILED at block ${chain.failedAt}: ${chain.reason}`;
  } else if (!rootMatches) {
    reason = `content root mismatch: restored ${recomputed.contentRoot.slice(0, 16)}… ≠ expected ${expectedRoot.slice(0, 16)}… (incomplete or altered restore)`;
  } else {
    reason = `restore verified: ${restored.length} blocks, chain intact, content root matches`;
  }
  return { ok, recomputedRoot: recomputed.contentRoot, expectedRoot, rootMatches, chain, reason };
}

/**
 * Round-trip verify: take a snapshot from a backup target, restore + verify it against its own
 * recorded root. This is the "test your restore" discipline made automatic.
 */
export async function verifySnapshotRoundTrip(port: BackupPort, snapshotId: string, hasher: Hasher): Promise<RestoreVerification> {
  const snap = await port.get(snapshotId);
  if (!snap) {
    return { ok: false, recomputedRoot: "", expectedRoot: "", rootMatches: false, chain: { ok: false, reason: "snapshot not found" }, reason: `snapshot ${snapshotId} not found on ${port.name}` };
  }
  return verifyRestore(snap.blocks, snap.contentRoot, hasher);
}

// ── Off-machine target prompt (free-first, ignorable) ────────────────────────

export type OffMachineOptionKind = "git-private" | "s3-compatible" | "rsync" | "paid-managed";

export interface OffMachineOption {
  readonly kind: OffMachineOptionKind;
  readonly label: string;
  readonly free: boolean;
  readonly requiresAccount: boolean;
  readonly note: string;
}

/** The free-first ordered options for an off-machine copy #2. Paid appears last, only if chosen. */
export const OFF_MACHINE_OPTIONS: readonly OffMachineOption[] = [
  { kind: "git-private", label: "Private Git repository", free: true, requiresAccount: true, note: "free on major hosts; most projects fit; content-addressed like the spine" },
  { kind: "s3-compatible", label: "S3-compatible / MinIO bucket you control", free: true, requiresAccount: true, note: "free with self-hosted MinIO; add Object-Lock for immutable (3-2-1-1-0 +1)" },
  { kind: "rsync", label: "rsync/SSH to a machine you control", free: true, requiresAccount: false, note: "no third-party account; air-gap friendly" },
  { kind: "paid-managed", label: "Paid managed backup", free: false, requiresAccount: true, note: "only if materially better for your case — surfaced last" },
];

export interface OffMachinePromptState {
  /** Whether copy #2 is already configured (if so, don't prompt). */
  readonly configured: boolean;
  /** When the prompt was last shown (epoch ms), or undefined if never. */
  readonly lastPromptedAt?: number;
  /** How many times the operator has dismissed it (backs off, never nags). */
  readonly dismissedCount: number;
}

export interface OffMachinePromptDecision {
  readonly shouldPrompt: boolean;
  readonly options: readonly OffMachineOption[];
  readonly reason: string;
}

/**
 * Decide whether to (re-)surface the off-machine prompt. Never prompts if copy #2 is configured.
 * Otherwise re-surfaces on a cadence that BACKS OFF with each dismissal (1d, then 3d, 7d, 14d, capped)
 * — present but never nagging. Free options first, always.
 */
export function offMachinePrompt(state: OffMachinePromptState, now = Date.now()): OffMachinePromptDecision {
  if (state.configured) {
    return { shouldPrompt: false, options: OFF_MACHINE_OPTIONS, reason: "off-machine copy already configured" };
  }
  if (state.lastPromptedAt === undefined) {
    return { shouldPrompt: true, options: OFF_MACHINE_OPTIONS, reason: "off-machine copy #2 not yet configured (local copy #1 is already protecting you)" };
  }
  // Back-off schedule in days by dismissal count (capped at 14d) — present, not naggy.
  const backoffDays = [1, 3, 7, 14][Math.min(state.dismissedCount, 3)]!;
  const dueAt = state.lastPromptedAt + backoffDays * 86_400_000;
  if (now >= dueAt) {
    return { shouldPrompt: true, options: OFF_MACHINE_OPTIONS, reason: `re-surfacing after ${backoffDays}d (dismissed ${state.dismissedCount}×) — copy #1 local backup is still active` };
  }
  return { shouldPrompt: false, options: OFF_MACHINE_OPTIONS, reason: `next surface in ${((dueAt - now) / 86_400_000).toFixed(1)}d` };
}
