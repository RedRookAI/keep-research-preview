# Captured native patch application

`publishPackagedNativePatchApplicationV1` applies a canonical overlay to one
captured archive and publishes an evidence-bearing candidate in a separate,
explicitly selected workspace. The SDK is exported from `keep`; the native
consumer is an explicit request on `keep-native-patch-capture`.

The supported package is the codec's frozen `curve25519-dalek@5.0.0` profile.
Inputs are a digest-bound tar or gzip archive, canonical overlay, original byte
carrier set, audit plan and review-input record. Supply all inputs locally and
prepare a separate output directory owned by the invoking user with mode 0700.
The consumer rejects directory-source declarations for application, overlapping
input paths, symlinks and input/output root containment.

Native root acquisition refuses mount crossings from `/`. Select roots on that
filesystem; a bind-mounted temporary directory does not satisfy this profile.

```ts
import { publishPackagedNativePatchApplicationV1 } from "keep";

const captured = await publishPackagedNativePatchApplicationV1({
  schema: "keep.patch-input-capture", version: 1n,
  root: inputRoot, sourceKind: "tar-gzip", sourcePath: "base.crate",
  sourceStreamDigest: archiveSha256,
  overlayPath: "overlay.cbor", overlayByteDigest: overlaySha256,
  carrierPath: "carriers.cbor", carrierByteDigest: carriersSha256,
}, {
  auditPath: "audit.cbor", auditByteDigest: auditSha256,
  reviewPath: "review.cbor", reviewByteDigest: reviewInputsSha256,
  outputRoot, attemptId: "review-001",
});

const application = captured.application;
console.log(application.evidenceDigest, application.result.resultTreeDigest);
```

The output contains `attemptId/request.cbor` and `attempt.cbor` before input
acquisition or candidate writes. The native consumer reads each input payload
once, checks the source and overlay/carrier byte equations, validates the audit
plan against the overlay commitment and checks the derived result tree. It
rechecks input path identities before publication. A captured snapshot is a set
of owned, digest-bound bytes with acquisition and identity checks. Concurrent
changes elsewhere in the filesystem remain outside that snapshot.

Each successful attempt publishes a new `attemptId/candidate` directory using
atomic no-replace rename. A reused attempt ID refuses and preserves earlier
files. Candidate versions contain:

- `tree/`: the resulting files and generated `.cargo-checksum.json`.
- `inputs/`: the exact source archive, overlay, carriers, audit plan and review record.
- `result-tree.cbor` and `evidence.cbor`: canonical result and application evidence.

The Cargo checksum adapter records every result file in byte-sorted path order,
with `package: null` for the patched local directory. Generated checksum metadata
is separate from the semantic result tree. Namespace conflicts, including a file
used as a parent directory or a generated-checksum alias, refuse publication.

The publisher verifies staged descendant identities and byte commitments before
publication and again before writing `published.cbor`. Candidate files use mode
0400 and directories 0500. The owner can change these permissions later; the
immutable receipt and SDK byte accessors preserve the observed snapshot. These
checks do not establish protection against a hostile host or permanent filesystem
immutability.

Publication requires exclusive ownership with cooperating writers and a trusted
host administrator. `renameat2` resolves the staging source by name; a hostile
same-user writer can race that name after the precheck. The postcheck then records
`unknown` and withholds a successful SDK result. A visible candidate path alone
confers no admission, and the consumer preserves uncertain files for inspection.

The SDK receives the same captured source rows and original patch inputs. It
recomputes the result, audit join, checksum and canonical application evidence,
then compares those bytes with the native receipt before returning the result.
Build execution and reviewer validation are separate steps.

The canonical review-input record has this shape:

```ts
{
  schema: "keep.p2-d2-review-inputs", version: 1n,
  toolchain: toolchainInputSha256, unsafeCode: null, license: null,
  advisory: null, reproducibility: null, provenance: null,
}
```

Each reference is a nonzero lowercase SHA-256 or `null` for unavailable input.
The exact record is retained and bound into the receipt. References remain
unverified, and review status is `unverified`. Audit-plan validation checks the
existing registry, threshold and separation schema; live reviewer custody,
signatures and semantic dependency approval require their own evidence.
Application evidence confers no build, admission or launch authority.

`outcome.cbor` records a known pre-publication failure as `failed`. A failure after
rename dispatch or while confirming publication is `unknown`; a candidate may
already exist. An `attempted` record with no terminal record also requires
inspection. Cancellation, process death or a lost response can leave this state.
Inspect the retained attempt and candidate before deciding what to do next.
The API does not automatically retry, overwrite or clean up an unresolved attempt.

Focused fixtures cover native tar/gzip application, TS/Rust receipt agreement,
actual offline SDK installation and unprivileged publication. They also exercise
stale inputs, invalid checksums, escaping links, namespace conflicts, source and
destination replacement, and uncertain publication. Full installed Keep artifact
qualification, maximum application resource use and production authority remain
separate acceptance conditions.
