# Backup interfaces and compatibility

Keep exposes backup capture, signing and restoration through its trusted lifecycle
and library interfaces. These are not a qualified unattended backup service or a
new backup CLI. Maintain a separate, tested offline backup of operational data.

Stop writers before capture. The two reads compare file contents, modes,
directories, exclusions and deterministic protected-content identities. They
detect changes between the observed inventories; they are not an atomic snapshot
of an actively changing application or external services.

The existing `maxFiles` limit counts all inventory entries: regular and protected
files, directories, and exclusions. A larger directory-heavy archive may require
an explicitly larger limit both when captured and when restored. Archive encoding
is unchanged; exceeding the limit refuses the operation rather than truncating it.

Protected capture encrypts state using an externally retained recovery authority.
Keep that recovery secret and its configuration outside the archive. Restoration
does not undo effects in outside services or apply permissions revoked after the
backup was taken. Later authority changes need separate reconciliation.

## Signing and existing archives

The version-1 archive and signature encodings are unchanged. Properly signed
archives using two different Ed25519 public keys retain the same verification
path. Different key labels are insufficient: creation and verification compare
the underlying public keys. This does not prove different people control them.

The built-in signer supplies its public key automatically. Custom
`SupplyChainSigner` implementations must provide `publicKey` matching their
signature; absent or mismatched keys cause creation to fail before storage.

An older archive signed twice by the same key is refused by signed restoration.
Its stored data is not rewritten or deleted. An operator may explicitly choose
the existing unsigned recovery path for unprivileged content, retaining the
decryption authority where required. That path reports authenticity and overall
operational recovery as unverified and cannot publish privileged file modes.
There is no automatic fallback from failed signature checks to unsigned recovery.

`LocalBackup` stores validated copies only for the lifetime of its process.
Fetching or modifying a returned object does not edit the retained copy. These
interfaces accept plain persisted event data; shared-memory buffers, typed arrays and other
non-plain JavaScript objects are rejected instead of retained as mutable aliases.
Shipping checks the fetched chain and metadata against the identity retained before the
target call. A successful write acknowledgment alone is insufficient; a failed
acknowledgment check may still leave an object at an append-only target.

Restoration reserves a fresh destination, stages and checks files, renames the
product and state directories separately, then writes a completion marker.
Handled-error cleanup is not proof of recovery from every possible process crash.

## Recovering the OpenClaw client candidate

The 0.0.16 development candidate adds client state outside Keep's data directory.
Its combined installed recovery is not yet qualified. The existing capture API
accepts one installed product root and one state root; it does not discover an
OpenClaw profile, external repositories or recovery keys. A successful capture or
`RESTORE_COMPLETE.json` therefore describes that capture's roots, not the whole
deployment. Likewise, `operationalRecoveryComplete` does not establish that later
revocations or remote effects have been reconciled.

Before capture, identify these components using the owned instance and client
configuration. Record paths, package versions/checksums and which backup contains
each component in a private recovery inventory. Do not put credential values in it.

| Component | What must be retained |
| --- | --- |
| Keep product | Exact installed package and its dependency/runtime identities; retain the previous immutable release separately. |
| Keep instance | `instance.json`, its actual `KEEP_DATA_DIR`, all journals/Spine sidecars, job and decision records, model invocation claims and worker lifecycle records. Referenced files outside these roots need separate capture. |
| Restricted client | The issued profile referenced by `KEEP_OPENCLAW_CLIENT_PROFILE` and the restricted token file selected by the plugin's `tokenFile`; preserve the existing grant and binding rather than issuing replacements during recovery. |
| Owned OpenClaw profile | Its configuration, agent/session state and installed plugin identity. Retain the logical session key and configured agent identity used by the pending conversation. |
| Plugin journal | The complete configured `stateDirectory`, including `keep-submissions.sqlite` and any SQLite `-wal`, `-shm` or `-journal` sidecars present. It contains private goal text and saved request keys. |
| Repository and workspaces | The pinned source commit, local changes and proposal workspace contents through the repository owner's backup mechanism. Keep's capture excludes Git control directories and nested repositories; it is not a repository backup. |
| External recovery authority | Decryption/signing authority and current authority-reconciliation evidence retained separately from the captured files. Codex authentication remains under its existing owner-controlled recovery procedure; it is not passed to OpenClaw. |

Capture a consistent set:

1. Stop new submissions and quiesce only the owned Keep and OpenClaw writers.
   Keep's normal shutdown refuses active or queued work; pausing dispatch alone
   does not establish quiescence. If work cannot stop safely, retain its uncertain
   status and defer this capture rather than killing another process or deleting
   lifecycle records.
2. Use Keep's existing protected capture/signing interfaces for its product and
   state roots. Preserve configuration outside those roots and the owned OpenClaw
   components with the operator's existing private offline backup mechanism while
   their writers remain stopped. Copy the complete SQLite directory as one
   stopped set, not just the main database while a client is active. No second
   Keep backup service or archive format is required.
3. Review every exclusion against the inventory. Sensitive material belongs in
   protected private storage; a best-effort capture with omitted credentials is
   incomplete. Retain the original permissions and the external recovery keys.
   Resume only the affected original instances after the set is safely retained.

Restore into fresh private destinations with writers stopped. Require the existing
integrity/signature/decryption checks and completion marker for each Keep capture;
retain failed copies for diagnosis rather than falling back silently. Restore the
matching client journal, profile/session state, configuration and repository data
before attempting client recovery. Reconcile absolute paths, endpoint, source
revision and permissions deliberately. A binding or credential change can hold
unresolved plugin work; do not erase the journal to make a new submission succeed.

Before activation, reconcile grant expiry and revocations against current
authority evidence outside the old snapshot. Restored local records cannot reveal
a revocation that happened after capture. If that evidence is unavailable, leave
the restored worker/client offline; automatic recovery with current authority is
not established. Keep original uncertain invocation charges and pending human
decisions intact. Restoring files cannot prove a remote request stopped, authorize
a retry, approve generation or land a proposal.

After those conditions are met, inspect the retained project through the owner
console and use the original conversation's `keep_status` to recover its existing
job. That tool may resend the original saved POST with its original key if the
acknowledgement was lost. It must not be treated as a new goal. Missing original
state, incompatible journal versions and unresolved authority require operator
reconciliation; a fresh directory, session or key is not a recovery shortcut.

## Filesystem Spine history capacity

FileSpineStore defaults to maxHistoryBytes = 64 * 1024 * 1024 per staging and
chain log. Trusted callers may configure a larger positive finite safe integer
through its constructor options. The same byte cap applies before descriptor
reads and prospective append/recovery framing. The cursor has a separate
32-byte bound; recovery sidecar comparison cannot exceed the expected tail size.
KEEP_SPINE_HISTORY_CAPACITY refuses admission without deleting history or silently
advancing the cursor. Preserve staging.jsonl, chain.jsonl, staging.cursor and
.torn-* / .append-lock sidecars together. Stop only affected writers before
reconciling copies or choosing a larger explicit capacity for restored state.
This cap does not compact logs, bound aggregate state/parsed-object memory or
make lifetime scans constant-time. Retain the configured capacity with backup
configuration; restoration alone does not prove the reader can admit that history.
