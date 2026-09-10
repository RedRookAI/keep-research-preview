# Keep release record

## Maintenance research preview 2026-09-10.2

**Keep 0.0.3-preview.1 — `keep-preview-2026-09-10.2`.**

[Release and downloads](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-09-10.2) ·
[Corrections and upgrade notes](docs/maintenance-2026-09-10.2.md)

This update publishes completed corrections through audit Segment 13A. The audit
continues on the original release. Builder testing is not independent audit
verification. Existing public history, tags and release assets remain intact.

## Exact artifacts

| Item | Identity |
| --- | --- |
| Originating development revision | `3767d847180a3596827ea0bea7a3be2dcaf17be2` |
| Frozen public source export | `4a103fb1ee890fcb3885a02c8de2587a86a5c045` |
| Source archive | `keep-source-preview-2026-09-10.2.tar.gz` — 16,471,624 bytes; 3,998 files |
| Source SHA-256 | `b522804f6543bd37c277bd86225e65e98ace4f6adc2a52f14a4fb1b9774e3755` |
| Installable package | `keep-0.0.3-preview.1.tgz` — 6,359,301 bytes; 2,102 files |
| Package SHA-256 | `3aa332d738947df3aaf87704632be880af66f68204f5446a9cde0361bbb24dd4` |

The public export includes the corrected runtime, public-safe tests/build tools,
version metadata and public guides. Private Git history is not imported. The tagged
tree adds only this companion record to the export. This record is outside both
archives so their checksums do not refer to themselves.

For the checksum-gated installation in the [preview guide](docs/research-preview.md):

~~~sh
export KEEP_RELEASE_SHA256='3aa332d738947df3aaf87704632be880af66f68204f5446a9cde0361bbb24dd4'
~~~

Compare against the expected value before installing. A checksum calculated only
from the downloaded archive does not establish that it is the intended release.
Matching bytes do not independently authenticate the publisher.

## Checks on this distribution

- Ordinary scripts-enabled offline `npm ci` and `npm pack` succeeded with the
  existing pinned Rust toolchain and npm cache. TypeScript compiled, notices
  matched, and native release binaries were built/staged. No new dependencies.
- The broad ordinary portable run recorded **5,019 passes and one failure** across
  5,020 tests. The failed documentation fixture created the old archive filename.
  It now uses the package version and checks that the guide agrees. The whole
  workflow-test file then passed **6/6**, including matching and refusal controls.
  The initial run is retained as a failure, not relabeled as a clean full-suite run.
- Portable release/security checks passed **32 cases**, with two explicit
  designated-host skips. This is not full native or all-platform qualification.
- A fresh consumer installed the archive with lifecycle scripts enabled and
  networking disabled. All **2,102** files matched archive and source/build bytes
  before and after verification.
- The installed regression run recorded **737 passes and six failures** across
  743 cases. All six were optional native-transport tests: ordinary npm metadata
  did not meet their strict custody prerequisites, and the fixture lacked a
  protocol oracle. These are preserved failed configuration checks.
- In a separate byte-identical administrator-controlled copy, with documented native
  custody permissions and the existing protocol test oracle, both native test files
  passed **17/17**, including those six cases. An intermediate staging run passed
  16 and failed one missing source-path fixture; that alias was corrected without
  altering product bytes or assertions. An ordinary npm install is not thereby
  qualified as a native deployment. The oracle is a test helper, not a runtime
  requirement for binary-package users.
- The installed no-model demonstration passed **16 accounting and eight single-entry
  cases**, using local durable effects and fresh child processes. Native staging
  left the ordinary installation unchanged.
- The source archive was extracted and all **3,998** files byte-compared with the
  frozen export. MIT, required notices, vendored contents and dependency versions
  are unchanged. The development dependency inventory changes only the reviewed
  collector/helper provenance.
- Public documentation was rendered and local links, code-block syntax and the
  installation checksum guard's matching, mismatched, malformed and missing-value
  controls were checked.

These are builder-administered synthetic checks on Linux x64, Node.js 22.23.2 and
npm 10.9.8. Tests ran serially with private networking and bounded CPU, memory and
tasks. Regression tests could see host paths; this is not hidden-source, hostile-host,
real-model performance or outside-replication evidence. Counts overlap and must not
be added into a distinct-experiment total. No paid model calls were made.

## Earlier evidence and unfinished work

The private predecessor `ecffbad8c6bc27706457b25afc6930e8e67c4f5c` passed a complete
132-case native phase and its recorded broader checks. Subsequent native diagnostic
and required-jail changes have focused installed evidence. The older full-native
result is not a full-native rerun on this export. Historical results and failures
retain their original artifacts in the [evidence record](docs/evidence.md#known-test-status).

Segment 13B arrived during preparation with additional backup-component findings;
those repairs are **not included**. Automated backup capture, signing/verification
and shipping are not qualified by this release. Do not rely on Keep-reported
backup success as the sole protection for existing data. Stop writers and retain
a separately captured private offline backup before upgrading. Restoration and
cross-component coverage remain under audit.

Review the [upgrade notes](docs/maintenance-2026-09-10.2.md#upgrade-and-recovery)
before opening existing state. Missing legacy history is not invented, old
allowances with unknown consumption remain held, and restoring old backups loses
newer work. Do not run old and new writers on the same data.

The required Linux command layout has bounded evidence, not general security
clearance or a patched Bubblewrap dependency. Its advisory, trusted-host and resource
limits are in [Security](SECURITY.md). Arbitrary crash recovery, native custody,
production identity providers and undefined client multi-run workflows remain
separate qualifications. [Spending coverage](docs/monetary-accounting.md) is incomplete.

## Publication boundaries

September 9.2 and September 10.1 remain available under their original identities.
No npm-registry publication, operational deployment or private repository visibility
change accompanies this update. GitHub private vulnerability reporting is enabled;
maintainer notification delivery remains unverified. No response-time or bounty
commitment is made.

The [security research brief](docs/security-experiments.md) is unchanged. Its studies
remain proposed; this maintenance release claims neither their results nor outside adoption.
