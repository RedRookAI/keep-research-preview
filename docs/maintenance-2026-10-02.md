# Historical maintenance preview: October 2, 2026

This note records the historical 0.0.4-preview.1 binary. The current source is
0.0.5-preview.1; see [October 4 changes](maintenance-2026-10-04.txt) and
[the checkpoint record](../KEEP_RELEASE.md). The older binary retains its affected
launcher pin.

Keep 0.0.4-preview.1 (`keep-preview-2026-10-02.1`) is a maintenance research preview. It combines a prebuilt Linux x64 install path and newcomer quickstart with completed corrections not included in the September 10 public maintenance export. Earlier public releases and assets remain unchanged.

## Install and first run

- The binary archive bundles compiled JavaScript, the existing TypeScript runtime dependency and all three native executables produced by the source-build transport packager. A consumer with Node 22 and npm needs no Rust or C toolchain, and can install the archive offline.
- `keep demo recovery` runs the shipped local recovery experiment and reports 24 checks with zero model calls. Detailed reports and process logs are preserved in its generated temporary results directory.
- The README leads with installation and a first-run outcome. The new [quickstart](quickstart.md) includes checksum verification, a user-local PATH option and exact expected output.

## Completed implementation improvements

- Candidate selection owns fidelity measurements rather than accepting mutable caller-owned values. Execution evidence stays bound to the evaluated candidate and owned result; empty or skipped-only populations cannot establish successful execution. Selection workers drain before completion.
- Backup operations bound inventory size, preserve the captured inventory and checked snapshot identity, and reuse owned plain-data snapshots. Regression coverage includes changed inputs and rejected excess inventories.
- Required-jail setup preserves configured semantics and useful setup diagnostics. Isolation regressions exercise the supported directory layout, symlink boundaries, unsupported setup and useful permitted work. These checks do not establish a patched launcher or general host isolation.
- Native transport error reporting preserves bounded setup diagnostics. Independent native tampering fixtures avoid confusing installed harness aliases with independent coverage.
- The corrected source also retains the earlier transport, accounting, event-history, skill lifecycle and repository-delivery fixes. Source and installed evidence are reported separately rather than treating a printed success label as proof of an effect.

The development input is canonical revision `0e80a3269a760bb47b087a2ff08b9d153100c49e`. These are completed changes carried from that revision, not work newly performed on the publication date.

## Export hygiene

This is a selected public snapshot with no private Git history, planning/handoff documents, audit finding records, recovery archives or credential directories. The selection follows the existing public export rules. Public code uses generic host terminology and configurable build/fixture paths. A historical non-authorizing P2 inventory explicitly identifies normalized maintainer paths rather than pretending to be fresh qualification evidence.

## Upgrade and recovery

Stop writers and retain a verified private backup of the complete data directory before upgrading existing state. Read [the registry upgrade guide](skill-registry.md#upgrading-data-from-the-september-9-research-preview) and [backup documentation](backup.md). Earlier changes introduced content-bound registry approvals and state readers with stricter validation; simply switching versions is not a downgrade plan. Restore the matching old backup when reverting, with the corresponding loss of subsequent work clearly understood.

## Evidence and limitations

The [release record](../KEEP_RELEASE.md) identifies the exact artifacts, current portable-profile results, clean-room installation and installed recovery checks. Verification is builder-administered. Independent verification of the development corrections is not claimed.

Portable qualification excludes native-specific tests and the designated-host complete-artifact test. The clean-room experiment validates the binary installation and local synthetic recovery behavior. It does not qualify production identity, universal spending enforcement, arbitrary provider effects, outside replication or unattended consequential production operation. Required-jail launcher limitations remain in [Security](../SECURITY.md).

## Maintenance cadence

The October 4 instruction supersedes the earlier biweekly plan: while development
is active, publish a public checkpoint at least daily with actual results and
artifact limitations. Preserve historical release identities. This documentation
does not install a background publisher or host timer.
