# Keep 0.0.30-preview.1 — Linux x64 reviewer appliance

Version 0.0.30 fixes proposal approval so unreviewed files cannot be included in a merge. Keep checks the staged diff and candidate commit against the retained proposal before merge or publication. It also updates source comments and the browser wording.

Download the appliance archive and its matching checksum from this release:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.4

The release contains the exact candidate descriptor, consumer receipt, installed inventory, notices, source companion and checksums. Its manifest identifies the source revision, guest image and bundled components.

Use Linux x64 with Python 3.8+, OpenSSH, QEMU tools and existing read/write KVM access. The Debian 13 guest supplies Node 22.23.5, the required sandbox helper and the generation engine. Profile: pc-q35-8.2, 2 vCPU, 2 GiB RAM, 8 GiB virtual disk. First start requires at least 8 GiB of free host storage after extraction.

Start/stop guide:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

The browser sample uses authored responses with real edits, executable checks and proposal decisions. Fresh live-account generation and other host platforms remain outside the qualified reviewer profile.

## Historical releases

<details>
<summary>Earlier archives, checksums and observations</summary>

## Historical 0.0.29-preview.1 reviewer appliance

This archive predates the exact-proposal correction in 0.0.30. Its original identities and observations are retained below.

Download:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.3

The exact archive passed a clean-machine browser consumer: both veto and approval, four real checks, verified evidence exports, graceful stop/start and retained original jobs. Two fresh instances had distinct machine IDs, SSH identities and credentials. The sample uses authored responses and makes zero paid model calls.

Archive: `keep-reviewer-0.0.29-preview.1-linux-x64-73fabd7a9897-43184645622-repack.tar.xz`. Bytes: 588952968. SHA256: `b4a0208da9ff6e713a624b0eca034ba4d6d70090f8a88f6c456474f44fc0ec51`.

Guest image SHA256: `0ec8468c91ebf2afabeb88c149e8d48fc85e1485211c6c8849085b52900f1897`. Runtime source: `253fbca62133bef33ecc7d0c4b2192541cb55918`. Host assembly source: `73fabd7a98971335153590193ac9235140d5fbe3`. The release tag adds external qualification documentation without rebuilding those bytes.

Use Linux x64 with Python 3.8+, OpenSSH, qemu-system-x86_64, qemu-img and existing read/write KVM access. The Debian 13 guest supplies Node 22.23.5, the required sandbox helper and measured generation engine. Profile: pc-q35-8.2, 2 vCPU, 2 GiB RAM, 8 GiB virtual disk. Allow disk space for the archive, 1979252736-byte base image and growing instance overlays. First start additionally requires at least 8 GiB of free host storage after extraction. No host Node/npm/Rust is used.

Start/stop guide:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

Exact consumer receipt, scope and source-closure result:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/appliance-29-2026-11-12.md

All 289 required source/version pairs were acquired. The release includes the source archive, installed inventory, notices/support and source-index.json. KEEP-RELEASE-SHA256SUMS covers the selected release assets; SHA256SUMS covers the source companion. The source companion and public assets were checked against their complete hashes.

Fresh live-account generation, current OpenClaw-to-Keep handover, independent operator acceptance and full-platform completion remain open. ARM64 and other host profiles are unqualified for this appliance. The earlier combined archive retains its historical qualification below.

## Historical 0.0.21-preview.1 combined archive

# Keep 0.0.21-preview.1 — offline preparation and governed execution

The November 11 update adds organization code/PKCE login, pinned key refresh, session-bound project dispatch and captured native patch application. Real offline preparation now copies Git objects independently and uses separate private npm configuration files.

Download:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-11-11.2

Frozen source: `83a67b04fa03e6fd1a1564b6b93cc1c3f19deb24`. TypeScript and the three native release executables were freshly built; the measured generation engine is carried unchanged.

| Artifact | SHA256 | Bytes |
|---|---|---|
| `keep-0.0.21-preview.1.tgz` | `2845794f4b64691a9cb3669c3dee1ca4f605334cfb350f2ef3b5c57213a86b73` | 11499916 |
| `keep-combined-0.0.21-preview.1-linux-x64.tar.gz` | `7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca` | 122478133 |
| `keep-source-0.0.21-preview.1.tar.gz` | `7fab467e627fbb262ff2cff2dfa613ab53790741aa649c46a09255b4b992eba2` | 19207527 |
| `redrookai-openclaw-keep-0.0.21-preview.1.tgz` | `0572b46761d6c4c228a88d6c4bcb911b8fa40f7816802d641094942d59a658b1` | 12837 |

The unprivileged runtime consumer passed both account-free demos, saved instance/console lifecycle and authenticated exact-patch export. The project demo uses two scripted responses and simulated approval/veto. A fresh saved instance also observed an empty-cache hold, an explicit cache retry, TypeScript installation and a passing transpilation checker inside the required jail. Original source stayed unchanged; preparation made zero model calls.

Final assembly includes the local plugin archive named by the install guide. Complete archive comparison proved all 2615 prior payload entries unchanged; only the checked plugin was added. Incremental extraction, plugin metadata, CLI version and public API import passed as uid65534. Earlier runtime/preparation observations retain their original archive subject and are reused for identical payload bytes. Core npm portable packing normalizes native-peer modes; the qualified direct combined route preserves the gated staging modes.

The locked Rust toolchain and exact unsafe-site gate built three fresh static PIE executables. Scoped native/SDK checks passed. An unprivileged full-package publisher produced matching candidate, checksum, original-input and evidence readback. Its earlier archive identity is retained; all native files and publisher-relevant runtime files were verified unchanged in the final payload. Publication assumes cooperating owned writers and a trusted administrator. Uncertain outcomes remain for inspection; review status is unverified and grants no admission or launch authority.

Hosted CI passed 150 tests on Node22.23.4 after locked installation, emitting compilation and notices. This is a partial source profile. Live organization identity/custody, broader effect-path integration, production-native authority, a fresh genuine owner trial and full-platform completion remain open.

Exact scoped subjects and evidence reuse:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/combined-preview-2026-11-11.2.json

Current checksum-first installation guide:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/quickstart.md

Internal documentation reflects the frozen source snapshot. This external companion records final identities and current installation instructions. Historical assets, tags and receipts remain unchanged.

## Historical 0.0.20-preview.1 record

# Keep 0.0.20-preview.1 — saved setup and portable proposal evidence

The November 11 Linux x64 checkpoint adds explicit saved Codex setup, repository-check readiness, portable retained-proposal export and evaluation admission safeguards. The exact combined archive passed the scoped unprivileged consumer below.

Download:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-11-11.1

Frozen source commit: `08e196f987563f88fb13c4224c0c75c272e1a794`.

Qualification and reproducible consumer script:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/combined-preview-2026-11-11.json

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/installed-preview-2026-11-11.mjs

| Artifact | SHA256 | Bytes |
|---|---|---|
| `keep-0.0.20-preview.1.tgz` | `10275d8ca17cbb09b37a79e5e808ed41b2241cf35fd31f68302b9663fc24b651` | 11378616 |
| `redrookai-openclaw-keep-0.0.20-preview.1.tgz` | `68717b139b732ed1b15c7419deb780f05f5e2c0d109a5ecbf34e087cfc9ddb16` | 12760 |
| `keep-source-0.0.20-preview.1.tar.gz` | `e8d5522ad84c73b356a0f11281f54d4325f2d88e61e69377d3f60bfeeac05480` | 19161960 |
| `keep-combined-0.0.20-preview.1-linux-x64.tar.gz` | `41756eed35c1ef4c7c317ef9b3c86ac15494e370d1471b1e235d3722df55f1b8` | 123619463 |

The exact combined SHA-bound archive passed direct extraction/startup as uid65534 in a fresh directory with spaces and an initially empty HOME. Checks covered package import, the two-response scripted project demo, authenticated CLI/console proposal export, exact patch bytes, clean pinned-source verification, wrong-token/digest and dirty-source refusal, retained veto attribution, the24-check synthetic recovery demo, saved instance setup, prepared no-install readiness, paused startup, authenticated console/status and owned shutdown. Export added zero model calls; the entire consumer made zero paid calls.

TypeScript was freshly emitted from the frozen source. Native source/locks/build-tool identities and extracted native/engine bytes match the retained .19 inputs. Their prior evidence remains dated; this checkpoint adds scoped installed TypeScript evidence. Core packaging deliberately bypassed lifecycle scripts to carry those unchanged native inputs. The source snapshot and archive contain the release documentation available at the frozen commit; this external companion records the final identities after packaging.

Positive required-jail offline preparation, a new genuine account/owner trial, new OpenClaw installation/load, a fresh full/native suite and broader platform completion remain unverified. Source CI is configured; GitHub's hosted runs were queued at the last observation. Local and installed results above stand independently.

## Historical 0.0.19-preview.1 record


The combined Linux x64 archive includes Keep, bundled TypeScript, the restricted
OpenClaw plugin and the measured Codex generation.2 engine with source support.
[Run from the archive](docs/combined-preview.md) · [Real result](docs/genuine-codex-walkthrough.md) · [Matching release and qualification](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-20.1).

## October 21 portfolio example correction

The runtime/download version remains **0.0.19-preview.1**. Current source repairs the Unicode example patch's missing final newline and adds a fresh, explicitly scripted [console recording](docs/portfolio-demo.md). The October 20 combined, core and source archives retain the defective example; the plugin and native source-support archives do not contain it. Their hashes and historical qualification below remain unchanged. Use the [current corrected example](docs/genuine-codex-walkthrough.md#example-export-correction) or the separately identified example download in the [portfolio checkpoint](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-portfolio-2026-10-21.1). This is an example/docs correction, not a newly built or qualified Keep runtime.

Qualified combined preview source: `74e12f4235fb30b51179396b94a5dc7c14d2541d`.

[Qualification record](docs/qualification/combined-preview-2026-10-20.json) · [Download](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-20.1).

| Artifact | SHA256 | Bytes |
|---|---|---|
| `keep-combined-0.0.19-preview.1-linux-x64.tar.gz` | `42625af9b7be8a493f9309f6822e137f2365c4ae3accfe869750e4be535c53c7` | 123426124 |
| `keep-0.0.19-preview.1.tgz` | `bd29dde78ae59cdbc194507dead3d16eec3633dc203a355d303294fa2f16e972` | 11329178 |
| `redrookai-openclaw-keep-0.0.19-preview.1.tgz` | `fe0fc6ac9ac3feef99173c12c3321f4415745510cb6c5d9352d07206a6ce9e0d` | 12692 |
| `keep-source-preview-2026-10-20.1.tar.gz` | `1d61b632be931fdfcb2de2981b52edca89970fcbc90d612bf7c1b103b7fa0de4` | 17121360 |
| `native2-distribution-support-20261020.tar.gz` | `c319b4804408ec2ed9e90e9a6966f227a0905342ddebbf64538e1d68d079cd60` | 1288678 |

The exact combined archive passed unprivileged extraction, direct CLI startup,
both disclosed demos, instance start/status/console/stop and native OpenClaw
plugin install/configuration/load. The check made zero account requests, npm
calls or native builds. The generation.2 engine and production runtime match the
recorded genuine follow-up at the scope described in the qualification record.

The archive contains a source-snapshot copy of this companion from before these
external receipts. Checksums here refer to the exact written assets; neither
the archive nor its source snapshot claims to checksum or qualify itself. The
release tag adds these receipts without changing the archived source identity.
Historical full-suite results remain bound to their original versions.

Supported profile: Linux x64 / Ubuntu24.04 library baseline, patched Node22 for
Keep and supported patched Node24 for OpenClaw2026.10.5. The archive runs directly;
Node22's advisory-matched bundled npm10 installer is not part of this route.
The local plugin has no runtime dependencies. Required-jail work additionally
needs the measured Bubblewrap0.13.0 helper and working host namespaces.

The native generation.2 identity is
`fdd9a1a3e86fc2213e4c0bd9c9b278080f38d756a5256e3217092a30e48d98c1`.
Its included source-support archive is
`c319b4804408ec2ed9e90e9a6966f227a0905342ddebbf64538e1d68d079cd60`.
The genuine developer-administered case used this engine with actual Keep and
native OpenClaw dispatch; tool selection was scripted and Codex generation real.
It is one observed integration case, not a model-quality benchmark or production
enterprise certification. See [dependency conditions](docs/dependency-status.md).

---

# Keep 0.0.12-preview.1 — inspect a tested repository proposal

Release: `keep-preview-2026-10-05.1` · Linux x64 · Node.js 22.23.2/npm/Git.

[Download](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-05.1) · [Historical checksum-first quickstart](docs/quickstart.md#historical-0012-installation) · [Walkthrough](docs/portfolio-walkthrough.md) · [Qualification](docs/qualification/preview-2026-10-05.json).

Run `keep demo project` to see an actual separate-workspace edit, passing repository and goal tests, and a reviewable diff. Two authored local responses and sample approval/veto decisions are clearly disclosed before work. The approval gate holds before dispatch; restart retains the proposal without replay; a wrong token refuses and veto leaves original source unchanged. No account or paid call is needed. Inspect the printed report and artifacts, then follow the configured-solve guide for your own repository.

| Artifact | Exact identity |
|---|---|
| Qualified public source | `3e4e3e3990fcc6262d6a20491d067f2563b95bb1` |
| Linux x64 package | `keep-0.0.12-preview.1.tgz`; 10,820,623 bytes; 2,273 files |
| Package SHA256 | `df188e14685a3a21e422d113bbfcd8241ee293d5e3a38cebbd186e5c9c4d92d7` |
| Matching source archive | `keep-source-preview-2026-10-05.1.tar.gz`; 16,743,058 bytes; 4,070 files |
| Source SHA256 | `04596cb015086a8c11ef9eadd6441514115f580b24946f92d6965385c9d538df` |

Set `KEEP_RELEASE_SHA256` to the trusted package SHA256 above before using the quickstart. Ordinary offline installation needs no Rust/C compiler; the existing TypeScript dependency is bundled. The package contains three genuine native executables. Required-jail operations still require the measured Bubblewrap 0.13.0 launcher; installation does not install a host launcher or change security policy.

All selected source phases passed across the recorded unchanged-source runs: **5,295 ordinary + 34 release/security + 139 native = 5,468 tests**, zero failures/skips. Scripts-enabled prepack reproduced the tested runtime. A fresh unprivileged offline installation byte-matched all **1,560** production runtime files, resolved package exports and passed both actual demos, useful/refused required-jail controls and two protected backup/restore tracks. The complete native phase was rerun after an owned filesystem correction; earlier failed full reports remain failed, with their passing ordinary/security phases explicitly reused for this same source. The exact written default-layout quickstart passed; wrong checksum refused before installation/state writes. Failures and corrections remain recorded.

The research preview includes the recent source work on installed solve, model-call/provider diagnostics and manual memory/query monetary admission. Older checkpoint receipts retain their original identities. The new package is separately qualified; results are not silently inherited from those narrower checkpoints.

This is same-agent evidence on one owned Linux host, with network disabled, existing 2CPU/4GiB/0swap/512PID controls and the inherited finite test allowance. The walkthrough reports best-effort isolation; required-jail evidence is separate. No real-model success rate, live organization custody, independently rebuilt artifact, offsite disaster survival, universal spending ceiling, production PROBER/D3 authority or macOS/Windows qualification is established. The [completion map](docs/completion-map.md) keeps broader obligations open.

Archives bind the qualified source above. The release tag adds external receipts and reconciled documentation; full source results do not become results for that later documentation commit. This companion is outside both archives to avoid circular checksums. Archived documentation records the source snapshot before publication; use this companion and the release-tag documentation for current download identities. Original releases/tags/assets are unchanged.

## Historical source checkpoint: 0.0.18-preview.1

Source **0.0.18-preview.1** introduced the recovered generation route, literal patch/application checks, browser form compatibility and native-plugin exclusion, with a genuine Codex/OpenClaw follow-up. That checkpoint had no matching qualified download. The current **0.0.19-preview.1** combined release above carries those repairs and its own exact-archive qualification. Use the [current dependency guidance](docs/dependency-status.md); the original Node 22.23.2 qualification above remains historical. Existing releases, tags and assets are unchanged.

---

# Previous release records

# Keep 0.0.5-preview.1 — qualified security preview

Release: `keep-preview-2026-10-04.1` · Linux x64 · Node.js 22.23.2/npm.

[Release and downloads](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-04.1) · [Quickstart](docs/quickstart.md) · [Completion map](docs/completion-map.md) · [Qualification receipt](docs/qualification/preview-2026-10-04.json)

This replacement preview carries the completed scoped audit fixes and measured Bubblewrap 0.13.0 identity. The older 0.0.4-preview.1 archive retains an affected launcher pin. Installing this package does not install a host launcher or change host security policy; required jail operations refuse absent/mismatched bytes.

| Artifact | Exact identity |
|---|---|
| Qualified public source | `fca232810f6c2309ed0a9e5c5090577fc7112fee` |
| Linux x64 package | `keep-0.0.5-preview.1.tgz`; 10,776,583 bytes; 2,256 files |
| Package SHA256 | `d6b9dc25abc878616c04030655550c8587fca58c47d7ed571c3439567ea79091` |
| Matching source archive | `keep-source-preview-2026-10-04.1.tar.gz`; 16,481,217 bytes; 4,031 files |
| Source SHA256 | `612d07a4dd37197e50cd30098ee1f4993ec9d4171f96457a9ee16110f237878a` |

Use the trusted package SHA256 above as `KEEP_RELEASE_SHA256`, then follow the checksum-first, unprivileged offline quickstart. The binary includes JavaScript, its existing bundled TypeScript dependency and three genuine static Linux x64 native executables; ordinary installation needs no Rust/C compiler.

The complete selected source profile passed **5,168 ordinary + 34 release/security + 139 native = 5,341 tests**, zero failures/skips. Scripts-enabled packaging reproduced the tested runtime; all 1,554 included runtime files matched. Compiled tests are intentionally excluded from distribution. A clean unprivileged consumer with no accessible contributor checkout/compiler passed version/exports, 24 synthetic accounting/restart cases and actual useful/refused required-project-boundary controls. Protected capture/restore passed two synthetic tracks with all restored product bytes, sidecars, uncertain claims and fresh-process sink readbacks; tampered, missing-key and occupied targets refused. The exact documented quickstart shell block also passed with npm’s default layout and the installed CLI. Wrong SHA refused before installation/state writes.

Qualification ran in owned process namespaces with actual two-ID mapping, a private manager, network disabled, 2CPU/4GiB/0swap/512PID and a shared finite allowance. No new VM, account, host policy, global launcher installation or unrelated workload was changed. The evidence is same-agent/single-host. It does not qualify production PROBER/D3 authority, live organization identity/custody, offsite disaster survival, arbitrary exactly-once remote effects, universal spend control or macOS/Windows native distribution.

The archives bind the exact tested source above. The release tag adds external evidence, the completion map and reconciled prose without changing qualified product code. This companion is excluded from both archives to avoid circular checksums. Do not attribute the full source pass to the later documentation commit. Original release/tag/asset bytes remain unchanged.

The [completion map](docs/completion-map.md) retains all original objectives and open platform/product obligations; missing referenced original detail stays an explicit coverage gap. A qualified preview is not complete-product readiness. Actual failures and corrections are retained in the qualification record.

---

# Historical binary release record

## Historical maintenance preview: October 2, 2026

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

</details>
