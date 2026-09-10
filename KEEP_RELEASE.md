# Keep release record

## Maintenance research preview 2026-09-10.1

**Keep 0.0.2-preview.1 — `keep-preview-2026-09-10.1`.**

[Repository](https://github.com/RedRookAI/keep-research-preview) ·
[Release and downloads](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-09-10.1) ·
[Changes and upgrade notes](docs/maintenance-2026-09-10.md)

This is the companion record for the two immutable archives below. It is not
embedded in either archive whose hash it records. The tagged public tree contains
the same selected source plus this companion record; private development history
is not imported. The original September 9 tag and assets remain unchanged.

| Item | Exact identity |
| --- | --- |
| Frozen public source export | `59003dc9d0aff8346eb8a60d6b30fbb49fb6b589` |
| Selected development baseline | `4dcba6d4fb8e9b46255c09b3f0b97113f1abf06c` |
| Additional legacy-upgrade changes | `5cdcb0584d4d3c12f466f5d6618edbef2864593c`, `36b4db5f55cdccd70aeaab8242985a31644c309f` |
| Source archive | `keep-source-preview-2026-09-10.1.tar.gz` — 16,346,262 bytes; 3,959 selected files |
| Source archive SHA-256 | `00d08b26e9491306e5e5e95002776422f7a78434ba869b8545823d4dee57a189` |
| Installable package | `keep-0.0.2-preview.1.tgz` — 6,278,243 bytes; 2,089 files |
| Package SHA-256 | `08f96c05d5968ad7bbffe80d2f698c43ab7c38a949a07afd2162b00b1b2361dc` |

The final tag includes the companion-only successor to the frozen source export.
No runtime, test, build or packaged documentation bytes change in that successor.
The baseline and two additional revisions explain selection, not a claim that
the entire newer private development tree is published. The exact public export
above identifies the combined source, tests, version metadata and public guides.

For the checksum-gated installation block in the preview guide, set:

~~~sh
export KEEP_RELEASE_SHA256='08f96c05d5968ad7bbffe80d2f698c43ab7c38a949a07afd2162b00b1b2361dc'
~~~

Do not derive the expected checksum from the downloaded archive. Matching bytes
do not independently authenticate the publisher.

## Checks on this exact distribution

- Ordinary scripts-enabled offline `npm ci` and `npm pack` succeeded. TypeScript
  compiled, the notice check passed, and native release binaries were compiled
  and staged. Previously acquired pinned toolchain and dependency cache reused;
  no fresh toolchain acquisition or empty-cache claim.
- A fresh consumer installed the archive with lifecycle scripts enabled. Its
  isolated filesystem did not expose the private source or toolchain; networking
  was disabled. All **2,089** installed files matched the package and build bytes.
- **88/88 installed correction/validator/program regressions passed**, no skips.
  Includes tenant revocation, skill admission/promotion/translation, repository
  refusal and source delivery, and legacy-state revalidation and recovery.
- **201/201 installed related-path tests passed**, no skips: registry, canary,
  evaluator, distiller, retrieval, static adoption, project editing, project loop,
  recoverable repository flow, delegation and gateway identity controls.
- The installed no-model demonstration passed **16 accounting and eight
  single-entry cases**, using owner and injected-tenant configurations and fresh
  child processes. It ran in the isolated consumer arrangement.
- **10/10 source attribution/package-policy tests passed**, no skips.
- The actual original installed registry reader accepted a disposable v1 backup,
  rejected its v2 successor, and recovered the original history after restoring
  the copied v1 bytes. The original package and reader bytes were checked first.
- Twelve public documents rendered; 106 local links/anchors and 14 shell or
  JavaScript blocks passed checks. The installation checksum guard passed matching,
  mismatched, malformed and unset-value cases before installer invocation.
- All **3,959** selected source files were extracted and byte-compared with the
  frozen public source export. Dependency/vendor and runtime-notice inputs are
  unchanged from the reviewed release; their completed provenance work is carried
  forward, not represented as newly performed.

These are builder-administered synthetic checks on the maintainer's existing host,
not independent audit verification or real-model performance experiments. Installed
regressions ran serially in a separate private network and could see host paths;
they do not qualify nested operating-system isolation. Tests retained successful
work, negative controls, real synthetic filesystem/Git outcomes and restart cases.

Linux x64; Node.js 22.23.2, npm 10.9.8, pinned Rust 1.97.1 with the musl target.
Runs used one CPU, 2 GiB RAM, no swap and at most 128 tasks. Offline build setup
initially failed on duplicate npm configuration paths and then an incomplete reused
consumer cache; the corrected run used distinct configuration files and the prior
full build cache. Those attempts did not pass and are not hidden as successful runs.

## Upgrade behavior

**Before starting this version with existing data, stop writers and retain a
verified private copy of the complete data directory. No automatic backup is made.**

Valid v1 skill packages, counters and retirement survive loading without rewriting
the file. Missing checked-content bindings do not become assumed approvals.
Non-retired retained skills can pass the configured managed execution gate and
become eligible again; successful readmission starts new content-bound counters.
Retired legacy IDs remain held, including through bundle import and promotion.
Unconfigured or failed revalidation preserves the previous stored record.

The next managed save writes v2. The original preview rejects that format. Restoring
old software requires matching old state and omits work saved afterward; preserve
the newer state separately and reconcile external effects before recovery. Tests
on disposable registry copies demonstrate exact backup-byte restoration and the
absence of an intentionally added later skill, not lossless system-wide rollback.
See the [complete upgrade instructions](docs/skill-registry.md).

## Remaining limitations

The ongoing audit is not complete and this update does not resolve every finding.
Later private transport, event-storage, monetary-accounting, adaptation and
isolation changes are excluded. Do not use this preview with production
credentials, unrestricted paid services or unattended production workloads.

The complete experimental/native suite was not rerun for this maintenance release.
Earlier correction-checkpoint evidence includes 4,599 ordinary passes and targeted
refreshes of release and paired-journey fixtures. Those are historical results,
not cumulative passes for this candidate. Four broader native checks remained
unresolved: test-adapter allowlist expectations, native-source package-boundary
expectations, dependency-inventory agreement and a probe syscall allowlist check.
Nested-isolation qualification also remains incomplete. No full-native-suite pass,
production isolation or universal spending guarantee is claimed.

Historical coding and memory evidence retains its exact scope and original
identities in [docs/evidence.md](docs/evidence.md). A retrieved skill is not proof
that it executed; a sampled validation result is not evidence of general learning
advantage. The [security studies](docs/security-experiments.md) remain proposed.

## Publication and reporting

Lisa authorized this bounded maintenance update while the audit continues against
the unchanged `keep-preview-2026-09-09.2` baseline. This release contains reviewed
source, public regression tests, documentation and required notices under the
existing MIT license. Private repositories, private history, planning/funding
records and operational data remain private. No npm-registry publication is made.

GitHub private vulnerability reporting remains enabled; its enabled state was
read back through GitHub's API during preparation. Notification delivery has not
been verified. Lisa should review Watch → Custom → Security alerts and her personal
notification delivery settings. No new email address, response deadline, bounty
or paid service is promised.
