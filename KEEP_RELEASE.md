# Keep release record

## Maintenance research preview: October 2, 2026

**Keep 0.0.4-preview.1**, release `keep-preview-2026-10-02.1`.

[Release and downloads](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-02.1) · [Five-minute quickstart](docs/quickstart.md) · [Changes and upgrade notes](docs/maintenance-2026-10-02.md)

This release adds a prebuilt Linux x64 install, an accessible first-run recovery experiment and completed maintenance corrections. Security and recovery controls remain intact. Verification is builder-administered; independent audit verification and unattended consequential production operation are not claimed.

## Exact artifacts

| Item | Identity |
| --- | --- |
| Originating development revision | `0e80a3269a760bb47b087a2ff08b9d153100c49e` |
| Public source export commit | `c15f0295b8013109cbf465225b2b63704b88018b` |
| Source archive | `keep-source-preview-2026-10-02.1.tar.gz`; 16,418,192 bytes; 4,009 files |
| Source SHA256 | `42f91ac2266ff532c3775387632e4cf0ab55e139838e38eec8ff9fce28c25218` |
| Linux x64 binary package | `keep-0.0.4-preview.1.tgz`; 10,754,603 bytes; 2,249 files |
| Package SHA256 | `fb872c193b32b496cb2fd17cdc25ed26503d6022f78a34134e54acec3efb9e26` |

The source export uses only public repository history. The release tag adds this companion record to the public export. This record is supplied alongside both archives and is excluded from them, avoiding circular checksums. Earlier public tags and assets remain unchanged.

## Install and first run

With Node.js 22 and npm (qualified version 22.23.2):

```sh
export KEEP_RELEASE_SHA256='fb872c193b32b496cb2fd17cdc25ed26503d6022f78a34134e54acec3efb9e26'
printf '%s  %s\n' "$KEEP_RELEASE_SHA256" 'keep-0.0.4-preview.1.tgz' | sha256sum -c -
npm i -g ./keep-0.0.4-preview.1.tgz
keep demo recovery
```

Continue past verification only when the archive is reported `OK`. The [quickstart](docs/quickstart.md) also covers a writable user-local installation. Expected demo output:

```text
Recovery experiment passed: 24 checks; 0 model calls.
Detailed results: /tmp/keep-installed-fleet-uncertainty-<generated-id>/report.json
```

## Qualification of this distribution

- TypeScript compilation and attribution checks passed on Node.js 22.23.2. The existing source-build transport packager verified the pinned Rust 1.97.1 toolchain and produced three genuine static Linux x64 PIE binaries: client, supervisor and patch capture. No replacement or stub transport is used.
- The complete selected portable profile passed **5,095/5,095 ordinary tests** and **32/34 release/security tests**, with **two explicit designated-host skips** and zero failures. Its existing exclusions are the native-specific files and one designated-host complete-artifact file; this is not the full native or all-platform profile.
- The test runtime files were extracted from the exact binary archive and byte-compared with the compiled candidate before the full portable run. The source test harness and existing profile exclusions were preserved.
- A fresh, unprivileged Linux x64 consumer installed the package with npm lifecycle scripts enabled, networking disabled, an empty npm cache and no Rust/C toolchain. The installed version, help and recovery command worked. Native manifest hashes, sizes and static ELF identities matched all three genuine binaries.
- The installed recovery experiment passed **16 accounting and eight single-entry dispatch cases**, using durable synthetic outbox effects and fresh processes, with **zero model calls**. These cases exercise both personal and injected-tenant configurations; an injected tenant is not a production identity provider.
- Local documentation links and the checksum gate's matching, mismatch, malformed, missing-value and missing-archive controls passed. Changed optional native host-fixture source also passed pinned-toolchain compilation; its host execution is not claimed.
- Source and package scans found no owner credentials, private infrastructure details, excluded development archives or imported private Git history. Intentional synthetic rejection fixtures and unchanged upstream attribution/test material were reviewed separately from real credentials.

The full portable run used a bounded, network-disabled Ubuntu Linux x64 test container with the existing pinned Bubblewrap binary, permitted test namespaces and a real KVM character device. The binary clean-room installation used a separate ordinary Node 22 Debian container without those contributor prerequisites. The portable environment had two CPUs, 4 GiB RAM, no swap expansion and a 512-process limit. These are local, builder-administered checks, not outside replication or a security clearance.

The initial portable attempt failed because its environment lacked required isolation prerequisites and two publication fixtures needed correction. Those failures are retained in the private qualification evidence; they are not relabeled as passing. The corrected final profile above was rerun in full. Counts overlap with focused and installed checks and should not be added into a distinct-experiment total.

## Boundaries and upgrade guidance

The introductory experiment qualifies the documented local synthetic recovery behavior. The shipped native exchange remains optional refusal-only development functionality with separate custody prerequisites. Native inclusion does not establish arbitrary workload execution, production identity, remote-effect finality or universal spending enforcement. Required-jail launcher advisory and trusted-host limits remain in [Security](SECURITY.md).

Before opening existing state with this version, stop writers and retain a separately verified private backup of the complete data directory. Review the [maintenance upgrade guidance](docs/maintenance-2026-10-02.md#upgrade-and-recovery), [registry migration notes](docs/skill-registry.md#upgrading-data-from-the-september-9-research-preview) and [backup guide](docs/backup.md). Do not mix old/new writers or silently downgrade state formats.

Historical results remain attached to their original artifacts in [Evidence](docs/evidence.md#known-test-status). This release is distributed through GitHub assets, not the npm registry. No operational deployment, visibility change or new automatic maintenance service accompanies it.
