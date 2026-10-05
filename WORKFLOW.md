# Contributing to Keep

The current public source checkpoint is **0.0.11-preview.1**; its narrower source
evidence is in [the evidence record](docs/evidence.md). The downloadable binary
remains **0.0.5-preview.1**, with its identities in [the release record](KEEP_RELEASE.md).

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
| node tools/run_ci_checks.mjs | Offline locked install, typecheck, notices and eight focused test files; a partial profile | Populated npm cache, Node and the isolated test environment |
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
installation; the introductory preview checks scripts-enabled installation separately.

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

## Commit, checkpoint and release protocol

Adopted October 5, 2026. Apply this cadence to future Keep work within the user's agreed scope.

- Research current primary sources and actual consumers for each ticket, implement the smallest change, then vet useful/refused/recovery outcomes and reconcile affected docs. Commit each vetted ticket and push it to private Git. During longer work, save clearly labeled incomplete checkpoints privately rather than leave the only copy on this box.
- Combine related vetted tickets into a coherent public source checkpoint. Publish at least once per active development day when there is meaningful new work. If code is not ready, a reviewed public progress/documentation update can meet that cadence without exporting unvetted code. Do not create empty commits on unchanged days. An explicit goal's publication requirement still applies at its stopping point.
- Advance the source version once per published code checkpoint, not per ticket or private commit. Align private/public package metadata, lockfiles, CLI version and current documentation before qualifying that checkpoint. Documentation-only corrections or protocol updates can retain the version; their Git commit identifies the change.
- Reuse each ticket's relevant vetting evidence. At the public batch boundary, run the necessary combined/export checks on the exact source and package metadata being published. Repeat passed checks only after relevant changes, failures or new material evidence. Preserve original source-bound receipts; never transfer them to an untested revision or binary.
- Prepare downloadable releases separately after the combined changes pass the normal exact-archive and installed-consumer qualification. A public source push is not a newly qualified binary release. Preserve earlier archive/version/checksum records and state the distinction in the docs.
- Verify successful Git publication and keep current state clear about privately completed work, pending public changes and the last published checkpoint. Publishing a batch does not activate another ticket or expand a goal.

This is a written working protocol. It installs no hook, timer, service or resource enforcement and changes no other instance's instructions or workspace.
