# Install Keep and inspect a tested proposal

Keep **0.0.13-preview.1** is the Linux x64 source candidate currently undergoing package qualification. Until its release is published, use the prior0.0.12 release and its tagged documentation. You need Node.js 22.23.2 and npm; the repository walkthrough also needs Git. The installed package includes compiled JavaScript, its existing bundled TypeScript dependency and three native executables. No Rust or C compiler is needed to install or run the walkthrough.

## Download, verify and run

Download `keep-0.0.13-preview.1.tgz` and the companion `KEEP_RELEASE.md` from [the matching preview release](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-07.1).

Set `KEEP_RELEASE_SHA256` to the binary package checksum in that trusted release record. A computed checksum by itself does not authenticate the publisher. This block refuses a missing or mismatched expected checksum before installation:

```sh
(
  set -eu
  : "${KEEP_RELEASE_SHA256:?Set the checksum from the matching release record}"
  printf '%s  %s\n' "$KEEP_RELEASE_SHA256" 'keep-0.0.13-preview.1.tgz' |
    sha256sum --check --status
  keep_preview_consumer="$(mktemp -d)"
  npm install --prefix "$keep_preview_consumer" --offline --no-audit --no-fund \
    ./keep-0.0.13-preview.1.tgz
  "$keep_preview_consumer/node_modules/.bin/keep" version
  "$keep_preview_consumer/node_modules/.bin/keep" demo project
  printf 'Installed command: %s\n' "$keep_preview_consumer/node_modules/.bin/keep"
)
```

Expected version: `keep 0.0.13-preview.1`. The walkthrough states that its two responses are scripted locally and its sample approval/veto decisions are simulated. It then shows an actual changed working copy, passing repository/goal tests and a diff. It checks restart without replay, token refusal and source preservation after veto. No account or paid request is needed, and it uses its own temporary repository rather than your files.

This installs into a temporary user-owned prefix. Use the printed `Installed command` path wherever this guide says `keep`, or add that prefix's `node_modules/.bin` to your shell's PATH. Retain the prefix to keep using the preview.

Open the printed evidence directory to inspect `result.json`, `outcome.json`, `source/`, `workspaces/project/` and command records. The [walkthrough guide](portfolio-walkthrough.md) explains what to inspect and what the result does not establish. The demo needs permission to bind an ephemeral loopback port; if a constrained environment refuses it, retain the report and use the recovery experiment below.

## Try recovery or your own repository

```sh
keep demo recovery
```

This prints `Recovery experiment passed: 24 checks; 0 model calls.` and a report path. It requires no Git or model account. Its synthetic local outbox and fresh processes demonstrate the named recovery/accounting cases.

When ready, [configure your provider and repository](installed-solve.md), run `keep doctor`, and use `keep solve "your goal"`. Your chosen provider's prices, permissions and custody requirements apply; the demo is not model-quality or production-host qualification.

Required-jail operations need the exact reviewed Bubblewrap launcher and a qualified namespace environment. Missing/mismatched bytes must refuse. Installation does not install a host launcher or change shared-host policy; [native custody prerequisites](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites) remain separate.

## Build from source

Contributors need isolated Linux x64 resources, Node.js 22.23.2/npm/Git, pinned Rust 1.97.1 with its musl target and host C build tools. Follow [Contributing](../WORKFLOW.md); the build verifies existing pinned tools rather than fetching replacements.

```sh
git clone https://github.com/RedRookAI/keep-research-preview.git
cd keep-research-preview
npm ci
npm run build
node dist/src/main.js demo project
```

Before upgrading existing state, stop its writers and retain a verified complete private backup. See [backup guidance](backup.md) and the [release record](../KEEP_RELEASE.md). Do not mix old/new writers or stop other users' services.
