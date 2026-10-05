# Install the current research preview

Current development source is **0.0.6-preview.1** and adds [budget-bound provider-check](provider-check.md). The downloadable preview and installation examples below remain **0.0.5-preview.1**.

Keep **0.0.5-preview.1** is a Linux x64 research preview. Use Node.js 22.23.2 and
npm. The package includes compiled JavaScript, its bundled TypeScript dependency
and three genuine native transport executables; ordinary installation needs no
Rust or C compiler. The optional native refusal exchange has additional
[custody requirements](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites).

## Download, verify and run

Download `keep-0.0.5-preview.1.tgz` and the companion `KEEP_RELEASE.md` from
[the matching release](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-04.1).
Set `KEEP_RELEASE_SHA256` to the binary package checksum from that trusted release
record. A file's own computed hash alone does not authenticate its publisher.
The following refuses a missing or mismatched checksum before installation:

```sh
(
  set -eu
  : "${KEEP_RELEASE_SHA256:?Set the checksum from the matching release record}"
  printf '%s  %s\n' "$KEEP_RELEASE_SHA256" 'keep-0.0.5-preview.1.tgz' |
    sha256sum --check --status
  keep_preview_consumer="$(mktemp -d)"
  npm install --prefix "$keep_preview_consumer" --offline --no-audit --no-fund \
    ./keep-0.0.5-preview.1.tgz
  "$keep_preview_consumer/node_modules/.bin/keep" version
  "$keep_preview_consumer/node_modules/.bin/keep" demo recovery
)
```

Expected version: `keep 0.0.5-preview.1`. A passing demo prints:

```text
Recovery experiment passed: 24 checks; 0 model calls.
Detailed results: /tmp/keep-installed-fleet-uncertainty-<generated-id>/report.json
```

Inspect the generated report and durable local outbox records. No account or paid
model is required. The demo uses synthetic effects; it does not qualify arbitrary
external services, live enterprise identity or general native workload execution.

Required project jail operations additionally need the exact reviewed Bubblewrap
launcher and a qualified namespace environment. An absent or mismatched launcher
must refuse. This package does not install a host launcher or change shared-host
security policy. The older 0.0.4-preview.1 archive remains historical and affected;
see [Security](../SECURITY.md).

## Build from source

Use an isolated Linux x64 checkout, Node.js 22.23.2, npm, Git, pinned Rust 1.97.1
with its musl target, and host C build tools. The build verifies the existing
toolchain; it does not fetch a replacement. Configure `RUSTUP_HOME` or
`KEEP_P1_TOOLCHAIN_ROOT` as described in [Contributing](../WORKFLOW.md).

```sh
git clone https://github.com/RedRookAI/keep-research-preview.git
cd keep-research-preview
npm ci
npm run build
node dist/src/main.js version
node dist/src/main.js demo recovery
```

Before upgrading existing state, stop writers and retain a verified complete
private backup. Read [backup guidance](backup.md) and the
[release record](../KEEP_RELEASE.md). Do not mix old and new writers.
