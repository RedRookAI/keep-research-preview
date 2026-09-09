/**
 * LIFECYCLE / BACKUP / INTEGRITY composition root — makes the backup-verification, off-machine backup guidance,
 * clean-uninstall, and TCB-verification capabilities REACHABLE on the composed app (`app.lifecycle`), rather than
 * only barrel-exported. The owner's concern — "no one ever has their hard work lost" — is served by exposing
 * backup verification + free-first off-machine options as a first-class capability.
 *
 * BUILT: the pure logic (root-match + chain-integrity verification, the free-first option catalog, the uninstall
 * manifest sequencing, the TCB drift check). SEAM: the ports a deployment injects — the backup target, the removal
 * port (filesystem), the keystore, the snapshot source.
 */

import { verifyRestore, verifySnapshotRoundTrip, OFF_MACHINE_OPTIONS, type RestoreVerification, type OffMachineOption } from "../backup/verify_restore.js";
import { OffboxShipDriver, OFFBOX_DURABILITY_CAVEAT, type ChainSource } from "../backup/offbox_ship.js";
import type { SealedBlock } from "../spine/hashchain.js";
import type { BackupPort, Hasher } from "../backup/backup_port.js";
import { uninstall, renderUninstallSummary, FileOwnedRemovalPort, type UninstallRequest, type UninstallManifest, type RemovalPort, type RemovalOwnership, type FinalBackupReceipt } from "../backup/uninstall.js";
import { verifyTcb, measureModule, type TcbManifest, type MeasuredModule, type TcbVerification } from "../tcb/verify_tcb.js";
import type { Spine } from "../spine/spine.js";
import type { CryptoShredKeyStore } from "../keystore/keystore.js";
import { createProtectedBackup, verifyProtectedBackup } from "../backup/supply_chain_backup.js";
import { captureInstalledBackup, verifyInstalledBackup } from "../backup/installed_backup_capture.js";
import { restoreInstalledBackup } from "../backup/installed_backup_restore.js";
import { PassphraseBackupCredentialProtector } from "../backup/backup_secret_protection.js";

export interface UninstallDeps {
  readonly spine: Spine;
  readonly keystore: CryptoShredKeyStore;
  readonly removal: RemovalPort;
  readonly ownership: RemovalOwnership;
  readonly finalBackup: () => Promise<FinalBackupReceipt>;
}

export interface KeepLifecycle {
  /** Off-machine backup targets, FREE options first (a private git repo before any paid option). Advisory. */
  readonly offMachineBackupOptions: readonly OffMachineOption[];
  /** Verify a restored backup: recomputed content-root matches the expected root AND the chain integrity holds. */
  verifyBackupRestore(restored: readonly SealedBlock[], expectedRoot: string, hasher: Hasher): RestoreVerification;
  /** Verify a snapshot round-trips through a backup port (the port is the SEAM). */
  verifyBackupRoundTrip(port: BackupPort, snapshotId: string, hasher: Hasher): Promise<RestoreVerification>;
  /**
   * Build a CONTINUOUS off-box ship driver (BUILD-ORDER 8.5a): on a cadence it ships the latest sealed
   * snapshot to the injected sink, then re-fetches and re-verifies the copy with the SAME verifyRestore
   * predicate — fail-closed-and-visible (UNHEALTHY on any ship/verify failure). The sink is the SEAM.
   */
  makeOffboxShipDriver(sink: BackupPort, source: ChainSource, hasher: Hasher, intervalMs: number, clock?: () => number): OffboxShipDriver;
  /** What a verified restore proves — and what it does NOT (WORM/witness/credential-separation are NEEDS-8.5b). */
  readonly offboxDurabilityCaveat: string;
  /** Clean uninstall: final backup first (refuses if it fails unless forced), crypto-shred keys, remove home/runfiles. */
  uninstall(req: UninstallRequest, deps: UninstallDeps): Promise<UninstallManifest>;
  renderUninstallSummary(m: UninstallManifest): string;
  /** Verify the trusted computing base against a manifest — reports drift, never silently. */
  verifyTcb(manifest: TcbManifest, actual: ReadonlyMap<string, MeasuredModule>): TcbVerification;
  measureModule(source: string): MeasuredModule;
  readonly createProtectedBackup: typeof createProtectedBackup;
  readonly verifyProtectedBackup: typeof verifyProtectedBackup;
  readonly captureInstalledBackup: typeof captureInstalledBackup;
  readonly verifyInstalledBackup: typeof verifyInstalledBackup;
  readonly restoreInstalledBackup: typeof restoreInstalledBackup;
  readonly FileOwnedRemovalPort: typeof FileOwnedRemovalPort;
  readonly PassphraseBackupCredentialProtector: typeof PassphraseBackupCredentialProtector;
}

/** Assemble the lifecycle bundle. Pure logic wired now; the ports are injected per-call (deployment seams). */
export function composeLifecycle(): KeepLifecycle {
  return {
    offMachineBackupOptions: OFF_MACHINE_OPTIONS,
    verifyBackupRestore: (restored, expectedRoot, hasher) => verifyRestore(restored, expectedRoot, hasher),
    verifyBackupRoundTrip: (port, snapshotId, hasher) => verifySnapshotRoundTrip(port, snapshotId, hasher),
    makeOffboxShipDriver: (sink, source, hasher, intervalMs, clock) => new OffboxShipDriver(sink, source, hasher, intervalMs, clock),
    offboxDurabilityCaveat: OFFBOX_DURABILITY_CAVEAT,
    uninstall: (req, deps) => uninstall(req, deps),
    renderUninstallSummary: (m) => renderUninstallSummary(m),
    verifyTcb: (manifest, actual) => verifyTcb(manifest, actual),
    measureModule: (source) => measureModule(source),
    createProtectedBackup,
    verifyProtectedBackup,
    captureInstalledBackup,
    verifyInstalledBackup,
    restoreInstalledBackup,
    FileOwnedRemovalPort,
    PassphraseBackupCredentialProtector,
  };
}
