# Contributing to Keep

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
| npm run test:notices | Check the retained attribution bundle | Complete vendor trees and installed locked dependencies |
| npm run test:portable | Compile and run the selected portable test profile | Node and Git; see known failures in the preview guide |
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
