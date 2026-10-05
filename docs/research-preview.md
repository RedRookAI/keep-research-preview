# Research preview: install, run and inspect

Current development source is **0.0.8-preview.1**, adding [one provider-check fresh-price policy](provider-check-pricing.md). Downloadable archive identities and installation blocks below remain bound to 0.0.5-preview.1.

It retains [budget-bound FrontDoor calls](frontdoor-metering.md) and [provider-check admission](provider-check.md).

## This research preview

Keep **0.0.5-preview.1** includes the October 4 audit remedies and measured
Bubblewrap 0.13.0 pin. Use the [installation quickstart](quickstart.md) and the
matching [release and downloads](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-04.1).
The external [release record](../KEEP_RELEASE.md) identifies the exact source,
package, environment, actual qualification results and limitations.

Node.js 22.23.2 is the qualified runtime. The Linux x64 package needs no Rust or C
compiler to install; contributors building source use pinned Rust 1.97.1, its
musl target and host C build tools. The historical 0.0.4-preview.1 archive keeps
its original checksum and affected launcher pin.

## Verify a matching archive before installation

For the matching 0.0.5-preview.1 archive, set `KEEP_RELEASE_SHA256` to its trusted
release-record checksum. Do not rename the older archive or use a file's own hash
as publisher authentication. The following block
refuses before installation when the archive or required checksum is absent or
mismatched, then runs the installed experiment:

~~~sh
(
  set -eu
  : "${KEEP_RELEASE_SHA256:?Set KEEP_RELEASE_SHA256 to the published package checksum}"
  keep_demo_archive="$(realpath keep-0.0.5-preview.1.tgz)"
  printf '%s  %s\n' "$KEEP_RELEASE_SHA256" "$keep_demo_archive" |
    sha256sum --check --status
  keep_demo_consumer="$(mktemp -d)"
  npm install --prefix "$keep_demo_consumer" --no-audit --no-fund "$keep_demo_archive"
  node "$keep_demo_consumer/node_modules/keep/acceptance/installed_sg32_resources.mjs" \
    "$keep_demo_consumer/node_modules/keep" "$keep_demo_archive" "$KEEP_RELEASE_SHA256"
)
~~~

## First supported experiment

```sh
keep demo recovery
```

The [installed experiment](../acceptance/installed_sg32_resources.mjs) writes an append-only, fsynced local outbox, injects lost acknowledgments and starts fresh processes. It compares actual sink effects with committed and reserved capacity. No real payment, mail, model request or private data is involved. Its provider throws if called.

The 24 checks cover acknowledged work, uncertainty after adapter entry, unsuccessful results, pre-entry refusal, useful work when capacity remains, restarted/concurrent permit reuse and a durable claim with no adapter entry. The same cases run under personal and injected-tenant configurations.

For artifact-specific verification, the harness also retains its original interface:

```sh
node acceptance/installed_sg32_resources.mjs /absolute/installed/keep /absolute/keep-0.0.5-preview.1.tgz PACKAGE_SHA256
```

The CLI demonstration invokes the installed-only form and reports the local checks. The release qualification separately verifies the exact archive and installed bytes.

## Interpreting the result

A passing experiment demonstrates the named synthetic accounting and restart behaviors. It is builder-administered evidence, not independent replication, production identity verification, authoritative confirmation of remote effects or proof of general coding quality. A possibly executed obligation remains reserved until supported reconciliation; unknown obligations do not automatically expire.

The native client/supervisor exchange is currently refusal-only development functionality. Shipping its genuine binaries does not imply that they launch arbitrary workloads or provide production isolation. Its custody checks remain unchanged; see [Security](../SECURITY.md).

The completed development checkpoint ran all ordinary, release/security and native phases.
That result belongs to its exact development inputs; it does not automatically
qualify this exported source or a new archive. Public export checks and historical
artifact results appear separately in [the checkpoint record](../KEEP_RELEASE.md)
and [the evidence record](evidence.md#known-test-status).

Use synthetic data and isolated resources. Production credentials, unrestricted paid services, outside identity providers, Firecracker hosts and required project jails require their own supported setup and qualification. No automatic native fallback or universal provider compatibility is promised.

## Upgrading existing data

Stop writers and retain a verified private backup of the complete data directory before opening it with this version. Do not change schema labels or mix operational files from different releases. Review [skill-registry upgrades](skill-registry.md#upgrading-data-from-the-september-9-research-preview), [backup guidance](backup.md) and [the current checkpoint notes](maintenance-2026-10-04.txt).

## Build from source

Contributors use the complete source export, not the binary package, for compilation and tests. Install locked npm dependencies, configure the pinned Rust 1.97.1 toolchain with the `x86_64-unknown-linux-musl` target, and provide host C build tools. `RUSTUP_HOME` or `KEEP_P1_TOOLCHAIN_ROOT` selects the already acquired toolchain; the build verifies its identities and does not fetch replacements. See [Contributing](../WORKFLOW.md).

Optional Firecracker fixture qualification takes explicit `KEEP_FIRECRACKER_RUNTIME_DIR`, `KEEP_FIRECRACKER_IMAGES_DIR`, `KEEP_FIRECRACKER_ASSETS_DIR` and `KEEP_NATIVE_FIXTURE_BUILD_DIR` paths. The non-authorizing historical P2 dependency inventory normalizes maintainer paths; regenerate it with the current collector before claiming a newly qualified optional P2 closure. This does not affect the introductory binary transport build or recovery experiment.
