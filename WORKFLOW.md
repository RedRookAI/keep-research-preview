# Build and contribute

Use a Linux x64 source checkout with Node 22.23.5 or later on Node 22, npm and Git. Full native builds require the pinned Rust 1.97.1 toolchain, its musl target and host C build tools. The build verifies pinned tools rather than fetching replacements.

For the browser demo or bundled Linux x64 appliance, start with the README. The appliance supplies its own Node runtime, sandbox helper and generation engine.

<a id="build-and-test"></a>

## Commands

| Command | Result |
|---|---|
| `npm ci` | Install locked dependencies without native compilation. |
| `npm run test:fast` | TypeScript typecheck. |
| `node tools/run_ci_checks.mjs` | Locked script-disabled install, TypeScript compilation, notices and selected tests. Requires supported Node and Linux GNU timeout. |
| `npm run test:notices` | Check the retained attribution bundle against complete vendor trees. |
| `npm run test:portable` | Compile and run the portable test profile. Excludes native and designated complete-artifact checks. |
| `npm run build` | Compile TypeScript and verify/build native outputs. |
| `npm test` | Build and run the selected full test profile. Requires native prerequisites. |
| `npm pack` | Check notices, build and produce the npm archive. |

The public **Source checks** workflow runs the partial CI command on main and pull requests. It uses the Node range in package.json, read-only repository permissions and one test worker. A passing result requires executed tests with zero failures, skips or cancellations. Native builds and installed-artifact qualification have separate commands and results.

After compilation, run a focused test directly:

~~~sh
node --import ./dist/test/_netguard.js --test --test-concurrency=1 dist/test/guided_demo.test.js
~~~

Use the affected checks while editing. Broaden them when a change affects shared authority, persistence, packaging or isolation. Record the revision, commands, results and remaining failures. Reuse unchanged component evidence with its original identity.

<a id="optional-host-specific-tests"></a>

## Execution prerequisites

Required-project-jail checks need the exact measured non-setuid Bubblewrap 0.13.0 launcher, Python 3, a supported merged `/usr` layout and permission to create the tested namespaces. Missing or mismatched prerequisites refuse execution. The launcher recipe and identity are recorded here:

https://github.com/RedRookAI/keep-research-preview/blob/main/tools/bubblewrap/README.txt

The full runner defaults to one worker. Its `--phase` option selects a partial check. It excludes VM boots and actual KVM/Firecracker host probes unless those are selected separately.

Firecracker checks require an isolated prepared host. Both host tools require explicit `--vmm`, `--jailer`, `--kernel`, `--rootfs`, `--work-root`, `--output`, `--subject-manifest` and `--policy` paths. The host-evidence tool also requires `--signed-policy` and `--trust-root`. Keep the measurement checks intact; host configuration changes need the operator's authorization.

Security boundaries and native transport custody requirements:

https://github.com/RedRookAI/keep-research-preview/blob/main/SECURITY.md

<a id="evidence-for-a-contribution"></a>

## Installed checks

The installed-journey runner can consume an existing archive:

~~~sh
node tools/run_installed_golden_journeys.mjs --tarball=/absolute/keep.tgz --sha256=HEX
~~~

Its offline fixture setup and the direct-archive startup route have distinct installation receipts. The separate accounting experiment consumes its matching installed package, archive and hash:

~~~sh
npm run demo:recovery -- INSTALLED_ROOT ARCHIVE SHA256
~~~

The current supported appliance, historical archives and their exact observations are listed in the release record:

https://github.com/RedRookAI/keep-research-preview/blob/main/KEEP_RELEASE.md

<a id="safe-development"></a>
<a id="changes-and-releases"></a>

## Submit a change

Open a pull request with the problem, changed behavior and relevant check results. Use synthetic fixtures, preserve unrelated work and keep credentials/private traces out of the diff. New dependencies, paid calls and privileged operations require the relevant operator's authorization.

https://github.com/RedRookAI/keep-research-preview/pulls

For persistence or external effects, test interrupted and refused operations alongside permitted work. Retain uncertain outcomes for inspection before retrying. Personal and organization configurations need separate evidence where their authority differs.

Runtime source changes and downloadable releases have separate identities. A new release needs aligned package metadata, complete notices/source support and checks against the actual archive and installed consumer. Preserve earlier tags, hashes and receipts.

Third-party terms:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/licensing.md
