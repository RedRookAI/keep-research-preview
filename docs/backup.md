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
