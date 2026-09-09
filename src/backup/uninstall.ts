/**
 * Backup: clean uninstall routine (Increment 9c).
 *
 * SOTA basis (2026-08-04): sovereignty / no-lock-in — uninstall must leave the operator's WORK
 * intact and prove what it removed. The Eon 2026 war story (an AI agent deleted production AND its
 * backups) makes step 4 load-bearing: uninstall crypto-shreds KEYS and removes the INSTANCE, but it
 * NEVER deletes the backup target — the operator's work survives the uninstall by construction.
 *
 * Exact spec order (master plan §6): (1) offer a final backup; (2) remove instance home + registry +
 * runfiles; (3) crypto-shred keys (existing keystore); (4) leave work intact at the backup target;
 * (5) print exactly what was removed. Filesystem/registry removal is behind a RemovalPort so the real
 * instance functions plug in and tests use fakes. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { CryptoShredKeyStore } from "../keystore/keystore.js";
import { existsSync, lstatSync, realpathSync, rmSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

/** Abstracts the destructive filesystem/registry operations (real instance funcs plug in). */
export interface RemovalPort {
  /** Pure preflight: enumerate every path before deletion authority is exercised. */
  plan(instanceId: string): Promise<RemovalPlan>;
  /** Apply exactly the validated plan. Implementations must be idempotent and refuse additional paths. */
  apply(plan: RemovalPlan, progress: (event: RemovalProgress) => void): Promise<readonly RemovalResult[]>;
}
export interface RemovalResult { readonly path: string; readonly status: "removed" | "already-absent" | "failed"; readonly error?: string }
export interface RemovalProgress { readonly phase: "attempting" | "removed" | "failed"; readonly path: string; readonly error?: string }

export interface RemovalPlan {
  readonly instanceHome: string;
  readonly registryEntries: readonly string[];
  readonly runfiles: readonly string[];
}

export interface RemovalOwnership {
  /** Exact paths this uninstall invocation owns; parent-directory authority is deliberately insufficient. */
  readonly ownedPaths: readonly string[];
  /** Repository/workspace roots that must not overlap any removal path in either direction. */
  readonly preservedRepositories: readonly string[];
}

export interface FinalBackupReceipt {
  readonly id: string;
  readonly inventoryDigest: string;
  readonly target: string;
  readonly verified: true;
}

/** Filesystem implementation with no ambient discovery: it can remove only its frozen, preconfigured plan. */
export class FileOwnedRemovalPort implements RemovalPort {
  readonly #instanceId: string;
  readonly #plan: RemovalPlan;
  readonly #ownership: RemovalOwnership;
  constructor(instanceId: string, plan: RemovalPlan, ownership: RemovalOwnership) {
    if (!validToken(instanceId)) throw new Error("removal instance id must be a bounded canonical token");
    this.#instanceId = instanceId;
    this.#plan = freezePlan(plan);
    this.#ownership = Object.freeze({ ownedPaths: Object.freeze([...ownership.ownedPaths]), preservedRepositories: Object.freeze([...ownership.preservedRepositories]) });
    validateRemovalPlan(this.#plan, this.#ownership);
  }
  async plan(instanceId: string): Promise<RemovalPlan> {
    if (instanceId !== this.#instanceId) throw new Error("removal port is bound to a different instance");
    return this.#plan;
  }
  async apply(plan: RemovalPlan, progress: (event: RemovalProgress) => void): Promise<readonly RemovalResult[]> {
    if (!samePlan(plan, this.#plan)) throw new Error("removal port refused a plan other than its admitted exact plan");
    validateRemovalPlan(plan, this.#ownership);
    const paths = [...plan.runfiles, ...plan.registryEntries, plan.instanceHome];
    for (const path of paths) assertNoSymlinkTraversal(path);
    const results: RemovalResult[] = [];
    for (const path of paths) {
      progress({ phase: "attempting", path });
      const existed = existsSync(path);
      try { rmSync(path, { recursive: true, force: false }); const status = existed ? "removed" as const : "already-absent" as const;
        const result = Object.freeze({ path, status }); results.push(result); progress({ phase: "removed", path }); }
      catch (cause) { if (!existed && !existsSync(path)) { const result = Object.freeze({ path, status: "already-absent" as const }); results.push(result); progress({ phase: "removed", path }); continue; }
        const error = String(cause); const result = Object.freeze({ path, status: "failed" as const, error }); results.push(result); progress({ phase: "failed", path, error }); }
    }
    return Object.freeze(results);
  }
}

export interface UninstallRequest {
  readonly instanceId: string;
  /** The key subjects to crypto-shred (e.g. project ids). */
  readonly keySubjects: readonly string[];
  /** Take a final backup before removing anything (default true). */
  readonly finalBackup?: boolean;
  /** Proceed even if the final backup fails (default false — safer to refuse). */
  readonly force?: boolean;
}

export interface UninstallManifest {
  readonly instanceId: string;
  readonly completed: boolean;
  /** The final backup ref (if taken). */
  readonly finalBackupId?: string;
  readonly finalBackupRoot?: string;
  /** Exactly what was removed (step 5: print what was removed). */
  readonly removed: {
    readonly instanceHome?: string;
    readonly runfiles: readonly string[];
    readonly registryDeregistered: boolean;
    readonly registryEntries: readonly string[];
    readonly keysShredded: readonly string[];
  };
  /** What was deliberately PRESERVED (the operator's work). */
  readonly preserved: {
    readonly backupTarget: string;
    readonly note: string;
  };
  readonly abortedReason?: string;
  readonly removalFailures?: readonly { readonly path: string; readonly error: string }[];
}

/**
 * Run a clean uninstall. Ordered + auditable. If a final backup is requested and fails (and not
 * forced), the whole uninstall ABORTS before removing anything — never destroy the instance if we
 * couldn't secure the work first.
 */
export async function uninstall(
  req: UninstallRequest,
  deps: { spine: Spine; keystore: CryptoShredKeyStore; removal: RemovalPort; ownership: RemovalOwnership; finalBackup: () => Promise<FinalBackupReceipt> },
): Promise<UninstallManifest> {
  const { spine, keystore, removal } = deps;
  const wantBackup = req.finalBackup !== false;
  validateInstanceAndSubjects(req);

  // Resolve and validate the complete destructive write-set before backup or deletion.
  const removalPlan = freezePlan(await removal.plan(req.instanceId));
  validateRemovalPlan(removalPlan, deps.ownership);

  spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "uninstall_begin", instanceId: req.instanceId, finalBackup: wantBackup } });

  // (1) Offer + take a final backup. Abort if it fails and not forced.
  let finalBackupId: string | undefined;
  let finalBackupRoot: string | undefined;
  let finalBackupTarget = "not requested";
  if (wantBackup) {
    try {
      const receipt = await deps.finalBackup();
      if (!validToken(receipt.id) || !/^[a-f0-9]{64}$/.test(receipt.inventoryDigest) || receipt.target.trim() === "" || receipt.verified !== true) throw new Error("final backup receipt is invalid or unverified");
      finalBackupId = receipt.id;
      finalBackupRoot = receipt.inventoryDigest;
      finalBackupTarget = receipt.target;
      spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "final_backup_taken", id: receipt.id, inventoryDigest: receipt.inventoryDigest } });
    } catch (err) {
      if (!req.force) {
        spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "uninstall_aborted", reason: `final backup failed: ${String(err)}` } });
        return {
          instanceId: req.instanceId,
          completed: false,
          removed: { runfiles: [], registryEntries: [], registryDeregistered: false, keysShredded: [] },
          preserved: { backupTarget: finalBackupTarget, note: "nothing removed — aborted because the final backup failed (use force to override)" },
          abortedReason: `final backup failed: ${String(err)}`,
        };
      }
    }
  }

  // (2) Remove instance home + registry + runfiles.
  let removalResults: readonly RemovalResult[];
  try {
    removalResults = await removal.apply(removalPlan, (event) => spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: `removal_${event.phase}`, path: event.path, ...(event.error ? { error: event.error } : {}) } }));
  } catch (cause) {
    spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "uninstall_removal_port_failed", reason: String(cause) } });
    return { instanceId: req.instanceId, completed: false, removed: { runfiles: [], registryEntries: [], registryDeregistered: false, keysShredded: [] },
      preserved: { backupTarget: finalBackupTarget, note: "key shredding was refused because removal did not complete" }, abortedReason: `removal port failed: ${String(cause)}` };
  }
  const expectedPaths = [...removalPlan.runfiles, ...removalPlan.registryEntries, removalPlan.instanceHome];
  const resultPaths = removalResults.map((result) => result.path);
  const structurallyValid = resultPaths.length === expectedPaths.length && new Set(resultPaths).size === resultPaths.length &&
    expectedPaths.every((path) => resultPaths.includes(path)) && removalResults.every((result) => ["removed", "already-absent", "failed"].includes(result.status));
  if (!structurallyValid) {
    spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "uninstall_invalid_removal_evidence" } });
    return { instanceId: req.instanceId, completed: false, removed: { runfiles: [], registryEntries: [], registryDeregistered: false, keysShredded: [] },
      preserved: { backupTarget: finalBackupTarget, note: "key shredding refused because removal evidence was incomplete or invalid" }, abortedReason: "removal port returned incomplete or invalid evidence" };
  }
  const failures = removalResults.filter((result) => result.status === "failed").map((result) => ({ path: result.path, error: result.error ?? "unknown removal failure" }));
  const removedPaths = new Set(removalResults.filter((result) => result.status === "removed").map((result) => result.path));
  const terminalPaths = new Set(removalResults.filter((result) => result.status !== "failed").map((result) => result.path));
  const instanceHome = removedPaths.has(removalPlan.instanceHome) ? removalPlan.instanceHome : undefined;
  const runfiles = removalPlan.runfiles.filter((path) => removedPaths.has(path));
  const registryEntries = removalPlan.registryEntries.filter((path) => removedPaths.has(path));
  if (failures.length > 0) {
    spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "uninstall_partial_failure", removed: removedPaths.size, failed: failures.length } });
    return { instanceId: req.instanceId, completed: false, ...(finalBackupId ? { finalBackupId } : {}), ...(finalBackupRoot ? { finalBackupRoot } : {}),
      removed: { ...(instanceHome ? { instanceHome } : {}), runfiles, registryEntries, registryDeregistered: registryEntries.length === removalPlan.registryEntries.length, keysShredded: [] },
      preserved: { backupTarget: finalBackupTarget, note: "final backup preserved; key shredding refused after a partial removal failure" },
      abortedReason: "one or more exact owned paths could not be removed", removalFailures: Object.freeze(failures) };
  }
  spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "instance_removed", instanceHome, runfiles: runfiles.length, registryEntries: registryEntries.length, terminalPaths: terminalPaths.size } });

  // (3) Crypto-shred keys (existing keystore). Records key_shredded via the keystore's auditors.
  const keysShredded: string[] = [];
  for (const subject of req.keySubjects) {
    if (keystore.shred(subject)) keysShredded.push(subject);
  }
  spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "keys_shredded", count: keysShredded.length } });

  // (4) Leave work intact at the backup target — NEVER deleted here (by construction).
  // (5) Return the manifest (print exactly what was removed + preserved).
  spine.stage({ type: "identity.action", actor: "uninstall", payload: { event: "uninstall_complete", instanceId: req.instanceId, removedHome: instanceHome, keysShredded: keysShredded.length } });

  return {
    instanceId: req.instanceId,
    completed: true,
    ...(finalBackupId !== undefined ? { finalBackupId } : {}),
    ...(finalBackupRoot !== undefined ? { finalBackupRoot } : {}),
    removed: { ...(instanceHome ? { instanceHome } : {}), runfiles, registryEntries, registryDeregistered: true, keysShredded },
    preserved: {
      backupTarget: finalBackupTarget,
      note: `your work and repositories were outside the validated removal plan${finalBackupId ? `; final backup ${finalBackupId} is at '${finalBackupTarget}'` : ""}; only exact owned paths and selected keys were removed`,
    },
  };
}

/** Render the manifest as the human-facing "exactly what was removed" summary (step 5). */
export function renderUninstallSummary(m: UninstallManifest): string {
  if (!m.completed) {
    const removedCount = (m.removed.instanceHome ? 1 : 0) + m.removed.runfiles.length + m.removed.registryEntries.length;
    return removedCount === 0 ? `Uninstall aborted: ${m.abortedReason}\nNothing was removed.` :
      `Uninstall incomplete: ${m.abortedReason}\nRemoved before failure: ${removedCount} exact owned path(s). Keys crypto-shredded: ${m.removed.keysShredded.length}.`;
  }
  const lines = [
    `Uninstalled instance ${m.instanceId}. Removed:`,
    `  - instance home: ${m.removed.instanceHome}`,
    `  - runfiles: ${m.removed.runfiles.length} file(s)`,
    `  - registry entry: ${m.removed.registryDeregistered ? "deregistered" : "not found"}`,
    `  - keys crypto-shredded: ${m.removed.keysShredded.length} subject(s)`,
    `Preserved: ${m.preserved.note}`,
  ];
  return lines.join("\n");
}

const TOKEN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
function validToken(value: string): boolean { return TOKEN.test(value); }
function validateInstanceAndSubjects(req: UninstallRequest): void {
  if (!validToken(req.instanceId)) throw new Error("uninstall instance id must be a bounded canonical token");
  if (new Set(req.keySubjects).size !== req.keySubjects.length || req.keySubjects.some((subject) => !validToken(subject)))
    throw new Error("uninstall key subjects must be unique bounded canonical tokens");
}
function freezePlan(plan: RemovalPlan): RemovalPlan {
  return Object.freeze({ instanceHome: plan.instanceHome, registryEntries: Object.freeze([...plan.registryEntries]), runfiles: Object.freeze([...plan.runfiles]) });
}
export function validateRemovalPlan(plan: RemovalPlan, ownership: RemovalOwnership): void {
  const removals = [plan.instanceHome, ...plan.registryEntries, ...plan.runfiles].map(canonicalAbsolute);
  if (new Set(removals).size !== removals.length) throw new Error("uninstall removal plan contains duplicate paths");
  for (let left = 0; left < removals.length; left++) for (let right = left + 1; right < removals.length; right++) {
    if (within(removals[left]!, removals[right]!) || within(removals[right]!, removals[left]!)) throw new Error("uninstall removal plan contains overlapping paths");
  }
  const owned = new Set(ownership.ownedPaths.map(canonicalAbsolute));
  if (owned.size !== ownership.ownedPaths.length || removals.some((path) => !owned.has(path))) throw new Error("uninstall removal plan contains a path not exactly owned by Keep");
  const repositories = ownership.preservedRepositories.map(canonicalExistingOrLexical);
  for (const removal of removals.map(canonicalExistingOrLexical)) for (const repository of repositories) {
    if (removal === repository || within(removal, repository) || within(repository, removal)) throw new Error("uninstall removal plan overlaps a preserved repository");
  }
}
function canonicalAbsolute(path: string): string {
  if (!isAbsolute(path) || path.includes("\0")) throw new Error("uninstall paths must be canonical absolute paths");
  const canonical = resolve(path);
  if (canonical !== path) throw new Error("uninstall paths must be canonical absolute paths");
  return canonical;
}
function canonicalExistingOrLexical(path: string): string { const lexical = canonicalAbsolute(path); return existsSync(lexical) ? realpathSync(lexical) : lexical; }
function within(parent: string, child: string): boolean { const r = relative(parent, child); return r !== "" && r !== ".." && !r.startsWith(`..${sep}`) && !isAbsolute(r); }
function samePlan(a: RemovalPlan, b: RemovalPlan): boolean {
  return a.instanceHome === b.instanceHome && JSON.stringify(a.registryEntries) === JSON.stringify(b.registryEntries) && JSON.stringify(a.runfiles) === JSON.stringify(b.runfiles);
}
function assertNoSymlinkTraversal(path: string): void {
  let cursor = path;
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`no existing ancestor for owned removal path: ${path}`);
    cursor = parent;
  }
  if (lstatSync(cursor).isSymbolicLink() || realpathSync(cursor) !== cursor) throw new Error(`owned removal path traverses a symbolic link: ${path}`);
  if (existsSync(path) && realpathSync(path) !== path) throw new Error(`owned removal path is not canonical: ${path}`);
}
