# Contributing to Keep

Development source is **0.0.29-preview.1**. The hosted guided demo runs
**0.0.25-preview.1**; the latest Linux x64 appliance is **0.0.29-preview.1**.
The release record identifies the appliance's frozen guest-runtime and
host-assembly sources separately from the current source checkout.

The appliance includes its Node runtime, required sandbox helper and generation
engine. Its exact archive passed the account-free browser approval/veto workflow,
four executable checks, export and stop/restart with retained jobs. The sample
uses authored responses. The current native OpenClaw SDK also passed submission
and fresh-process status against the shipped API with dispatch paused and zero
account/provider calls. Fresh live-account generation and complete owner handover
remain open.

For the appliance, use Linux x64 with Python 3.8+, OpenSSH, QEMU tools and existing
read/write KVM access. First startup requires at least **8 GiB of free host storage
after extraction**, in addition to the bundle already on disk. Other platforms
and hypervisor profiles remain unqualified for this appliance.

Download, start instructions and exact observations:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.3

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/appliance-29-2026-11-12.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/current-openclaw-api-2026-11-12.json

The hosted walkthrough requires an assigned invitation:

https://keep.redrook.ai/console

The historical **0.0.21-preview.1** combined archive remains available for the
separate [direct Node installation route](docs/quickstart.md). Use
[architecture](docs/architecture.md) to inspect the design, and
[validation evidence](docs/evidence.md) and [exact release identities](KEEP_RELEASE.md)
when assessing results. Historical receipts remain bound to their tested source.

Start with the problem, the relevant implementation and an observable acceptance
criterion. Explain significant tradeoffs, preserve unrelated work, and include
tests for changed behavior. Personal and organization configurations need separate
evidence where their authority or behavior differs.

## Build and test

Run these commands from a source checkout, not inside an installed package.

| Command | Purpose | Requirements |
| --- | --- | --- |
| npm ci | Install locked dependencies; no native compile hook | Node/npm and registry access or a populated cache |
| npm run test:fast | TypeScript typecheck only | Installed locked dependencies |
| node tools/run_ci_checks.mjs | Locked script-disabled install, TypeScript compilation, notices and fourteen focused test files; a partial profile | Supported Node from package.json, registry access or a populated cache, complete vendor trees and Linux GNU timeout |
| npm run test:notices | Check the retained attribution bundle | Complete vendor trees and installed locked dependencies |
| npm run test:portable | Compile and run the selected portable test profile | Node, Git and the qualified Linux test environment described below |
| npm run build | Compile TypeScript and verify/build native outputs | Pinned Linux x64 Rust toolchain and host C build tools |
| npm test | Build and run the selected full test profile | Native prerequisites and isolated CPU/RAM/disk capacity |
| npm pack | Check notices, build and produce an npm archive | Same source-build prerequisites |
| npm run demo:recovery -- INSTALLED_ROOT ARCHIVE SHA256 | Run the installed accounting experiment | Matching installed package/archive; follow the checksum check in the preview guide |

The [preview guide](docs/research-preview.md) describes installation; the
[evidence record](docs/evidence.md#known-test-status) identifies results and failures.
A passing introductory demonstration is not a
passing full test suite.

The public Source checks workflow runs the same partial CI command on pushes to
main and pull requests. It selects Node from package.json's supported range,
uses read-only repository permissions and runs focused tests with one worker.
The command may use the npm registry during its locked installation. It does not
build native binaries or qualify an installed release. Its final result requires
actual executed tests with zero failures, skips or cancellations.

After compilation, a focused test can be run directly:

~~~sh
node --test --test-concurrency=1 dist/test/release_licensing.test.js
~~~

Required-project-jail checks need the exact measured non-setuid Bubblewrap 0.13.0
launcher, Python 3, the supported merged `/usr` layout and permission to create
the tested namespaces. Identity and recipe are in
[the launcher guide](tools/bubblewrap/README.txt). Missing or mismatched prerequisites
must refuse; do not change shared host settings to make checks pass.

The current full runner does not implicitly boot a VM or run real KVM/Firecracker
host probes. Optional host qualification remains separately selected below. A
passing recovery demo or available kernel feature does not prove host isolation.
The [checkpoint evidence](docs/evidence.md#october-4-public-source-checkpoint)
distinguishes the complete development run from this public export's checks.

The full runner defaults to one worker. Its --phase option is a partial check,
not full qualification. The --portable profile excludes native tests and the
designated complete-artifact test. Report these exclusions and any failures rather
than silently skipping tests to obtain a passing result.

The broader installed-journey runner can consume an existing archive:

~~~sh
node tools/run_installed_golden_journeys.mjs --tarball=/absolute/keep.tgz --sha256=HEX
~~~

That runner's offline, script-disabled fixture setup does not establish ordinary
installation. Historical npm installation checks retain their original versions;
the historical .21 combined preview uses separately checked direct extraction and startup.

## Optional host-specific tests

Firecracker host tests need an explicitly prepared isolated host. They are not
part of the portable introductory demonstration. Both host tools require explicit
--vmm, --jailer, --kernel, --rootfs, --work-root, --output, --subject-manifest and
--policy paths. The host-evidence tool also requires --signed-policy and --trust-root.

Configured paths do not prove that their contents are valid. Keep the existing
measurement and isolation checks intact; do not relax them to make an arbitrary
host pass. Separate P2 qualification tools also retain documented host assumptions.

## Evidence for a contribution

Use focused checks while editing. Expand verification when changes affect shared
authority, persistence, packaging, toolchains or isolation. Avoid rebuilding unchanged
native inputs for prose edits; identify what was rerun and what was carried forward.

For consequential behavior, include an adverse case and useful permitted work.
Inspect actual repository or sink state separately from model judgments and runtime
success labels. Retain failed results and distinguish intended, dispatched,
confirmed and unresolved effects.

For research changes, state the proposed claim, relevant alternatives, outcome
measurements and limitations. An independent review can challenge a design but
does not replace execution evidence.

## Safe development

Use synthetic fixtures and isolated resources. Do not include real credentials,
private data or operational traces in contributions. New dependencies need review
of their necessity, provenance and terms. Obtain the relevant operator's permission
before paid calls, privileged operations or consequential external effects.

Set finite time, process-tree and resource limits for experiments. Investigate
failures before retrying, and do not blindly replay an operation with an uncertain
external outcome. A billing alert is not an enforced spending ceiling.

A contribution report should identify the source revision, changed behavior, commands,
results, remaining failures and environment. A local repeat is not independent
replication. See [Security](SECURITY.md) before reporting vulnerabilities and
[Licensing](docs/licensing.md) before distributing artifacts.

## Changes and releases

Contributions should contain a coherent product change, its meaningful checks and
the documentation needed to use or maintain it. Keep internal task plans, account
details, raw operational logs and development-session bookkeeping out of public
changes. A short reviewed design explanation or roadmap update can be useful;
publishing every working note is not a requirement.

Use focused checks during development and the required combined checks for the
exact source/artifact being published. Repeat a passed check when a relevant
change, failure or new concern warrants it. Preserve source-bound results and
actual limitations; a documentation-only edit does not qualify changed runtime code.

Source updates and downloadable releases are separate. Align package metadata and
user instructions when preparing a new code release, qualify its actual archive
and installed consumer, and preserve earlier versions, tags and checksums.
Documentation corrections can retain the source version. A source push alone does
not establish a new qualified download.
