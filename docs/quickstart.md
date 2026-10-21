# Install and try Keep

The current **0.0.19-preview.1** combined Linux x64 download includes Keep, bundled TypeScript, the generation-only Codex engine and the restricted OpenClaw plugin. Use Linux x64 with the Ubuntu 24.04 library baseline, Node 22.23.3 or later on the Node 22 line, and Git for the repository walkthrough. This installation path needs no npm installer or Rust/C compiler. Review the dated [dependency conditions](dependency-status.md).

## Download, verify and run

Download `keep-combined-0.0.19-preview.1-linux-x64.tar.gz` from the [current release](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-20.1) into a new directory you own. Compare its expected checksum with the [release record](../KEEP_RELEASE.md); a checksum alone does not authenticate a publisher.

Set the Node path to an existing supported runtime. This block refuses a missing or mismatched archive before extraction:

```sh
(
  set -eu
  printf '%s  %s\n' \
    '42625af9b7be8a493f9309f6822e137f2365c4ae3accfe869750e4be535c53c7' \
    'keep-combined-0.0.19-preview.1-linux-x64.tar.gz' | sha256sum --check --status
  tar -xzf keep-combined-0.0.19-preview.1-linux-x64.tar.gz
  cd keep-0.0.19-preview.1
  export KEEP_NODE_EXECUTABLE=/absolute/path/to/node22/bin/node
  ./bin/keep version
  ./bin/keep demo project
)
```

Expected version: `keep 0.0.19-preview.1`. The walkthrough discloses two scripted local responses and simulated approval/veto. It produces a real separate-workspace edit, passing checks, a diff and retained evidence, with no account request. [What to inspect](portfolio-walkthrough.md).

For later commands, select the same Node runtime and use the extracted command's absolute path, or add that archive's `bin` directory to your own shell's PATH. The [combined archive guide](combined-preview.md) covers engine selection and native OpenClaw setup. OpenClaw uses its separately supported Node 24 runtime; selecting Keep's Node does not upgrade or reconfigure another installation.

## Continue with Keep

- Run `keep demo recovery` for the account-free recovery experiment: 24 synthetic checks and zero model calls.
- [Configure a repository and Codex](installed-solve.md), using your own existing login and the bundled engine. The [genuine recorded result](genuine-codex-walkthrough.md) shows what has actually passed.
- [Start an owned instance and open its console](local-instance.md), then [connect the restricted OpenClaw plugin](../integrations/openclaw/README.md). An unconfigured instance remains paused and does not generate code.

Required-jail work additionally needs the measured Bubblewrap 0.13.0 helper in a protected installation and working host namespaces. Missing prerequisites refuse; extraction does not install a host helper or change host policy. Keep's native refusal transport has separate [custody prerequisites](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites).

## Build from source

The current public source and combined download are **0.0.19-preview.1**. The downloadable source snapshot is bound to its exact release commit; later documentation corrections do not rebuild or requalify that archive. See [the release record](../KEEP_RELEASE.md) for source identity and [Contributing](../WORKFLOW.md) for build interfaces and evidence limits.

Contributors need isolated Linux x64 resources, Node.js 22.23.3 or later on Node 22, npm and Git, pinned Rust 1.97.1 with its musl target and host C build tools. Follow [Contributing](../WORKFLOW.md); the build verifies existing pinned tools rather than fetching replacements.

```sh
git clone https://github.com/RedRookAI/keep-research-preview.git
cd keep-research-preview
npm ci
npm run build
node dist/src/main.js demo project
```

Before upgrading existing state, stop its writers and retain a verified complete private backup. See [backup guidance](backup.md) and the [release record](../KEEP_RELEASE.md). Do not mix old/new writers or stop other users' services.

## Historical 0.0.12 installation

These older installation steps describe the October 5 artifact and its original evidence. They are retained for reference, not the current recommended installation path. In particular, the current direct route excludes the advisory-matched Node 22 npm installer; use the combined archive above for a new installation.

Keep **0.0.12-preview.1** is a Linux x64 research preview. Use Node.js 22.23.3 or later on Node 22 and npm; the repository walkthrough also needs Git. The installed package includes compiled JavaScript, its existing bundled TypeScript dependency and three native executables. No Rust or C compiler is needed to install or run the walkthrough. The original installed qualification used Node 22.23.2; the updated runtime guidance follows a published dependency fix and is not a rerun of that qualification. See [dependency status](dependency-status.md).

### Historical download, verify and run

Download `keep-0.0.12-preview.1.tgz` and the companion `KEEP_RELEASE.md` from [the matching preview release](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-05.1).

Set `KEEP_RELEASE_SHA256` to the binary package checksum in that trusted release record. A computed checksum by itself does not authenticate the publisher. This block refuses a missing or mismatched expected checksum before installation:

```sh
(
  set -eu
  : "${KEEP_RELEASE_SHA256:?Set the checksum from the matching release record}"
  printf '%s  %s\n' "$KEEP_RELEASE_SHA256" 'keep-0.0.12-preview.1.tgz' |
    sha256sum --check --status
  keep_preview_consumer="$(mktemp -d)"
  npm install --prefix "$keep_preview_consumer" --offline --no-audit --no-fund \
    ./keep-0.0.12-preview.1.tgz
  "$keep_preview_consumer/node_modules/.bin/keep" version
  "$keep_preview_consumer/node_modules/.bin/keep" demo project
  printf 'Installed command: %s\n' "$keep_preview_consumer/node_modules/.bin/keep"
)
```

Expected version: `keep 0.0.12-preview.1`. The walkthrough states that its two responses are scripted locally and its sample approval/veto decisions are simulated. It then shows an actual changed working copy, passing repository/goal tests and a diff. It checks restart without replay, token refusal and source preservation after veto. No account or paid request is needed, and it uses its own temporary repository rather than your files.

This installs into a temporary user-owned prefix. Use the printed `Installed command` path wherever this guide says `keep`, or add that prefix's `node_modules/.bin` to your shell's PATH. Retain the prefix to keep using the preview.

Open the printed evidence directory to inspect `result.json`, `outcome.json`, `source/`, `workspaces/project/` and command records. The [walkthrough guide](portfolio-walkthrough.md) explains what to inspect and what the result does not establish. The demo needs permission to bind an ephemeral loopback port; if a constrained environment refuses it, retain the report and use the recovery experiment below.

### Historical follow-up commands

```sh
keep demo recovery
```

This prints `Recovery experiment passed: 24 checks; 0 model calls.` and a report path. It requires no Git or model account. Its synthetic local outbox and fresh processes demonstrate the named recovery/accounting cases.

When ready, [configure your provider and repository](installed-solve.md), run `keep doctor`, and use `keep solve "your goal"`. Your chosen provider's prices, permissions and custody requirements apply; the demo is not model-quality or production-host qualification.

Required-jail operations need the exact reviewed Bubblewrap launcher and a qualified namespace environment. Missing/mismatched bytes must refuse. Installation does not install a host launcher or change shared-host policy; [native custody prerequisites](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites) remain separate.
