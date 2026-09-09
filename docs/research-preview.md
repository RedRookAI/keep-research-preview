# Research preview: install, run and inspect

## This release

**Keep 0.0.1 — candidate keep-preview-2026-09-09.2. Publication is pending.**

The distribution consists of `keep-source-preview.tar.gz` (the complete selected
source) and `keep-0.0.1.tgz` (the installable package). The accompanying
`KEEP_RELEASE.md` is the single current release record: it names the source revision,
both archive hashes, supported configuration, checks actually performed and remaining
limitations. It is supplied alongside the archives, not embedded inside an archive
whose hash it records. Do not substitute a historical hash from this guide.

The introductory configuration is Linux x64, Node.js 22.23.2 and npm 10.9.8.
Source builds additionally use the pinned Rust and C toolchain described below.
The installed demonstration needs no model account, GPU or paid service.
Tests use synthetic local effects and injected tenant identity; they do not establish
production enterprise authentication or outside replication.

Use synthetic data and isolated test resources. Do not attach production credentials
or unrestricted paid services. See [Security](../SECURITY.md).

### Known test status

The introductory demonstration and the broader experimental suite have separate
results. A historical portable run recorded **4,497 passes and 11 failures**, including
five repository-flow failures that persisted after the workspace prerequisite was
supplied. Those broader results have not been rerun on this candidate. Read the
[known failures and their scope](evidence.md#known-test-status) before using other
workflows; a passing introductory demo does not qualify general coding.

## First supported experiment

Suppose an operation consumes one unit of a shared resource. The adapter performs
the effect but its acknowledgment fails. An exception does not tell the runtime
whether the effect occurred. If it releases the reservation, another operation can
exceed a capacity limit even with a different operation ID.

The [installed accounting experiment](../acceptance/installed_sg32_resources.mjs)
uses an append-only, fsynced local outbox as a payment/mail-like synthetic sink. It
compares those actual sink rows with Keep's committed and reserved capacity. No real
payment, message, provider request or private data is involved. The test provider
throws if called. Fault labels go to the test adapter, not to Keep's decision logic.

| Schedule/control | What the evaluator checks |
| --- | --- |
| Effect followed by an exception or unsuccessful result | The possible obligation remains reserved and blocks excess work after restart |
| Exception before the effect, but after entering the adapter | Keep conservatively retains uncertainty; the harness's hidden answer is not runtime evidence |
| Actual refusal before invoking the adapter | No effect occurs and unused capacity can be released |
| Successful acknowledgment | One committed effect is accounted once |
| Capacity remains for another target | Useful work succeeds; the mechanism is not a deny-everything box |
| Concurrent or restarted reuse of an active dispatch permit | At most one adapter entry consumes that permit |
| Durable claim followed by no adapter entry | No effect, but the claim remains an unresolved obligation across restart |

The harness runs personal and injected-tenant configurations. Injected tenant
identity exercises scope distinctions, not a production identity provider. Fresh
child processes exercise restart. Concurrent entry cases are not an entire
heterogeneous autonomous fleet or an abrupt-power-loss experiment.

## Source build prerequisites

The intended first native target is Linux x64. Recent development used Node.js
22.23.2 and npm 10.9.8. Git is required for broader repository tests. A host C
compiler available as `cc`, its linker and development libraries are also required:
Cargo compiles host-side dependency build scripts even when Keep's target binaries
use the bundled Rust linker. The isolated build check uses the existing GCC 13.3.0
and GNU binutils 2.42. These are build prerequisites, not extra services or binary
package runtime requirements. Their identities are not covered by the Rust inventory;
do not interpret that inventory as a complete attestation of the build machine.
The native source build selects Rust 1.97.1 with host x86_64-unknown-linux-gnu, target
x86_64-unknown-linux-musl and rustfmt. Exact inputs are recorded in
[toolchain-lock.json](../native/toolchain-lock.json) and
[toolchain-inventory.json](../native/toolchain-inventory.json).

The complete source includes the native crates, vendor trees, build scripts and
inventory. A binary npm tarball is not a complete source-build distribution.
Set KEEP_P1_TOOLCHAIN_ROOT to an absolute installation of the matching toolchain,
or RUSTUP_HOME to its rustup installation root. Without an override, tools look in
the current user's `.rustup/toolchains` directory. An explicit toolchain root takes
precedence over the rustup root for the documented build and P1 inventory checks. Do not
copy a maintainer's private path into your environment. Selecting a directory does
not bypass the pinned compiler and library checks.

Separate P2 dependency/candidate probes and Firecracker host qualification still have
deployment-specific paths or pinned host executables. They are retained experimental
source, not qualified commands for this portable entry point. Do not replace their
expected digests or relax their isolation assertions to make them run on another host.

If rustup is already installed, the selected toolchain can be obtained explicitly:

```sh
rustup toolchain install 1.97.1-x86_64-unknown-linux-gnu --profile minimal --component rustfmt --target x86_64-unknown-linux-musl
keep_preview_rustc="$(rustup which --toolchain 1.97.1-x86_64-unknown-linux-gnu rustc)"
export KEEP_P1_TOOLCHAIN_ROOT="${keep_preview_rustc%/bin/rustc}"
```

This installs build tools, not a Keep runtime requirement for binary-package users.
Do not run installation commands without authority on the target machine. Consult
the official [rustup installation instructions](https://rust-lang.github.io/rustup/installation/other.html)
if rustup is absent. The [minimal profile](https://rust-lang.github.io/rustup/concepts/profiles.html)
does not include rustfmt, hence the explicit component above. Keep's build still
checks the pinned compiler/library inventory; a matching version label alone is
not sufficient. A differing inventory is a diagnostic to investigate, not permission
to regenerate the lock to match an arbitrary compiler.

From the source root, after obtaining the required tools:

```sh
npm ci
npm run test:fast
npm run test:notices
npm run build
npm pack
```

The explicit build is useful while developing; npm pack also builds, so omit the
separate build when only producing an archive. Installation and packing use their
ordinary scripts-enabled paths. The current release record identifies the exact
build inputs and checks; earlier toolchain-acquisition results are in the [evidence history](evidence.md#evidence-history).

## Run the demonstration

Obtain the package and its accompanying `KEEP_RELEASE.md` from the same release.
Copy the **package** SHA256 from that record into the environment variable below;
do not calculate the expected value from the downloaded package itself.

~~~sh
export KEEP_RELEASE_SHA256='PASTE_PACKAGE_SHA256_FROM_KEEP_RELEASE_MD'
~~~

Then run this block from the directory containing `keep-0.0.1.tgz`:

~~~sh
(
  set -eu
  : "${KEEP_RELEASE_SHA256:?Set KEEP_RELEASE_SHA256 to the package SHA256 from KEEP_RELEASE.md}"
  keep_demo_archive="$(realpath keep-0.0.1.tgz)"
  printf '%s  %s\n' "$KEEP_RELEASE_SHA256" "$keep_demo_archive" |
    sha256sum --check --status
  keep_demo_consumer="$(mktemp -d)"
  npm install --prefix "$keep_demo_consumer" --no-audit --no-fund "$keep_demo_archive"
  node "$keep_demo_consumer/node_modules/keep/acceptance/installed_sg32_resources.mjs" \
    "$keep_demo_consumer/node_modules/keep" "$keep_demo_archive" "$KEEP_RELEASE_SHA256"
)
~~~

The block stops before creating the consumer or invoking npm when the expected
checksum is absent, malformed or mismatched, or the archive cannot be read.
The outer parentheses contain the failure handling without closing the caller's
shell. A checksum compares bytes; it does not independently authenticate the publisher.

Installation needs registry access or cached locked dependencies. The experiment
uses no model or external service and writes synthetic state into a new temporary
directory. Keep the printed report location when reporting results. The consumer and
report are not automatically deleted. The source checkout's `demo:recovery` command
runs the same experiment; it is not the separate illustrative `npm run demo`.

## Inspect evidence instead of trusting the success label

Read the outbox JSONL rows for actual local effects. Then compare the per-phase
committed/reserved counts, invocation counts and Keep events in the report and child
logs. The outbox is a separate outcome oracle, but it is administered by the same
test operator—not an independent institution or remote provider.

The controls distinguish intended, attempted, observed and unresolved work. Repeated
operation IDs, shared capacity and single-entry dispatch are different properties.
An audit-chain verification result establishes structural integrity under its trust
assumptions; it does not prove that all external events were observed. An unresolved
outcome is a legitimate result, not a failure to print a convincing success message.

## Interpreting the result

The result covers these gateway accounting and permit-entry schedules with a trusted
in-process adapter and a durable local test sink. It does not establish arbitrary
remote-service finality, abrupt in-flight crash recovery, or a combined guarantee
under memory and permission revocation. Personal and injected-tenant configurations
are tested separately; the latter does not qualify a production identity provider.
See the [evidence record](evidence.md) for exact results and broader failures, and
[Security](../SECURITY.md) before using other execution arrangements.

## Release preparation

The current candidate is private pending the owner's publication decision and the
GitHub private-reporting setup described in SECURITY.md. Status language changes only
after the corresponding release action occurs. A reviewed whole-source snapshot
does not require exposing private development history.
