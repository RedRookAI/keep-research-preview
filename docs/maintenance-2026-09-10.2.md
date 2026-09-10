# Maintenance preview — September 10.2, 2026

Keep 0.0.3-preview.1 publishes the completed correction work through audit Segment
13A, with regression tests and useful-work controls. The audit continues against
the original September 9 release. This update is builder-tested, not independently
audit-verified or qualified for unattended production use.

## What changed

- Fleet admission now binds the checked operation and tenant identity to the
  invocation. Ordinary settlement cannot grant itself reconciliation authority.
- Event history includes all admitted own JSON keys in hashing. Logical appends
  are serialized, interrupted tails are preserved for recovery, and queued events
  drain into bounded blocks without weakening size limits.
- Adaptation records distinguish preparation from delivered treatment and preserve
  completed monitoring windows across restart so old outcomes do not count again.
- Model transports refuse redirects, keep deadlines through response consumption,
  handle stream errors/completion and count byte limits correctly. Metered routes
  reserve projected cost durably and retain uncertainty when usage is missing.
- Gateway MCP preserves caller identity and underlying refusal status. Direct MCP
  dispatch uses the same captured invocation that was checked. Process and stdio
  output preserve UTF-8 across chunk boundaries.
- Client requests match the gateway's resume, job-list and exact-proposal contracts.
  Project creation, selection, sibling discovery and finalization preserve durable
  session identity and report unavailable state instead of inventing empty history.
- Process cancellation reports actual termination or uncertainty. An explicit
  required Linux command boundary refuses unsupported setup. Path checks accept
  legitimate dot-prefixed children while rejecting actual escapes; failed evaluation
  setup does not delete a pre-existing destination.
- Signed profile checks reject invalid schemas before consuming a challenge.
  Native transport failures retain bounded setup diagnostics. Large canonical
  byte values avoid the reproduced decoder memory amplification.

The earlier maintenance fixes remain included: tenant-scoped grant revocation,
nonempty skill-validation evidence, prior counterexample checks, content-bound
skill admission, retirement/promotion consistency, static adoption metadata, and
accurate repository refusal/delivery reporting. These are engineering corrections;
passing their tests does not establish a learning or security research advance.

## Upgrade and recovery

Stop all Keep writers and make a private offline backup of the complete data
directory, including keys, session snapshots, event files and lock/recovery sidecars.
Do not run old and new writers against the same state. This release does not migrate
an operational installation automatically. Restoring a backup discards newer work.

- Read the [skill-registry upgrade guide](skill-registry.md#upgrading-data-from-the-september-9-research-preview).
  Legacy content is retained, but absent content-bound approval is not inferred.
  Retired skills stay retired. Older software cannot read the newer saved registry
  format; returning to it requires matching older data.
- Missing or malformed project snapshots remain unavailable/quarantined. Restore
  known-good matching state with writers stopped, or create a new project identity
  with explicit settings. Metadata alone cannot reconstruct lost limits or history.
- Historical event records with own `__proto__` keys may fail corrected verification
  because the old encoder omitted those keys. Preserve and investigate the original
  bytes; do not silently rehash, downgrade verification or assume a cause.
- Logical append recovery adds private lock/quarantine sidecars. Preserve them with
  the data. Incomplete tails are retained before repair; invalid complete history
  is refused, not silently discarded. Full-prefix checking has a cost that grows
  with history size.
- [Monetary accounting](monetary-accounting.md) now requires durable storage and
  awaited mutation calls. Legacy allowances with unknown consumption remain held;
  a new run ID cannot erase that uncertainty. This is not a universal billing cap.
- Client merge/veto requests must carry the exact proposal digest. Resume forwards
  the additional-step budget; job queries honor their project filter. A successful
  HTTP response alone is not proof that a requested operation completed.
- Ordinary `/fleet/settle` cannot release a claimed uncertain effect. Reconciliation
  requires the explicit human-authorized route and matching tenant. Do not retry an
  uncertain operation under a new identity to bypass its retained obligation.

## Evidence and limits

The [release record](../KEEP_RELEASE.md) supplies the exact source and package
identities, checks performed on this distribution, and checks carried from earlier
artifacts. Regression fixtures and expected answers are public development material,
not unseen evaluation tasks. Failures and unresolved coverage stay identified in
the [evidence history](evidence.md#known-test-status).

The introductory demonstration uses local synthetic effects and no model account.
Tested organization configurations do not establish production identity-provider
qualification. Arbitrary interruption, backup restoration and cross-component
coverage remain under audit. Undefined client multi-run interfaces are not claimed
as supported workflows. See [Security](../SECURITY.md) for the required command
boundary's host assumptions, launcher advisory and native custody limitations.

The original release tags/assets and earlier research results remain unchanged.
The [security research brief](security-experiments.md) remains the proposed research
agenda; this maintenance release does not report those studies as completed.
