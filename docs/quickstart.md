# Install and try Keep

Open the public browser demo. No sign-in is needed:

https://keep-demo.redrook.ai/console

Choose **Start demo**, then **Prepare the fix**. Review the diff and four checks, approve or veto the proposal, and download the evidence. The sample uses authored responses and needs no AI account. [Full walkthrough](guided-demo.md).

## Self-contained reviewer appliance

The **0.0.30-preview.1** appliance supplies Keep, Node and the required sandbox in a Linux x64 VM. Your host needs QEMU/KVM with existing KVM access, Python 3.8+ and OpenSSH. Its release receipt records the browser decisions, checks, export and restart observations.

Download and checksums:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.4

Follow the [appliance guide](reviewer-appliance.md) for storage requirements, startup and shutdown. Personal repository/account setup remains outside the completed account-free consumer result.

## Earlier direct Node archive

The **0.0.21-preview.1** combined Linux x64 archive includes Keep, TypeScript, the generation-only Codex engine and the restricted OpenClaw plugin. Use Linux x64 with the Ubuntu 24.04 library baseline, Node 22.23.5 or later on Node 22, and Git. This path runs without npm installation or Rust/C compilers. See [dependency conditions](dependency-status.md).

Its account-free workflow was reproduced on a fresh x64 VM. The [source-build report](qualification/independent-preview-2026-11-12.md) also records the additional host prerequisite for required-jail preparation.

## Download, verify and run

Download `keep-combined-0.0.21-preview.1-linux-x64.tar.gz` into a new directory you own:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-11-11.2

Compare the checksum with the [release record](../KEEP_RELEASE.md), then select your existing supported Node runtime:

```sh
(
  set -eu
  printf '%s  %s\n' \
    '7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca' \
    'keep-combined-0.0.21-preview.1-linux-x64.tar.gz' | sha256sum --check --status
  tar -xzf keep-combined-0.0.21-preview.1-linux-x64.tar.gz
  cd keep-0.0.21-preview.1
  export KEEP_NODE_EXECUTABLE=/absolute/path/to/node22/bin/node
  ./bin/keep version
  ./bin/keep demo project
)
```

Expected version: `keep 0.0.21-preview.1`. The demo uses two authored responses and sample approval/veto decisions. It produces a workspace edit, passing checks, diff and retained evidence. [What to inspect](portfolio-walkthrough.md).

For later commands, use that same Node runtime and the extracted command's absolute path, or add its `bin` directory to your shell's PATH. The [combined guide](combined-preview.md) covers engine selection and OpenClaw, which uses its own supported Node 24 runtime.

## Continue with Keep

- Run `keep demo recovery` for 24 synthetic recovery checks and zero model calls.
- [Configure a repository and Codex](installed-solve.md) with your own login. The [recorded genuine case](genuine-codex-walkthrough.md) shows one live-generation result.
- [Start a local instance](local-instance.md), then optionally [connect OpenClaw](../integrations/openclaw/README.md). An unconfigured instance starts paused.

Required-jail operations also need the measured Bubblewrap 0.13.0 helper in a protected installation and working host namespaces. Missing prerequisites refuse. Native refusal transport has separate [custody prerequisites](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites).

## Build from source

Current development source and the frozen reviewer appliance both carry **0.0.30-preview.1**. Their source commits differ; the [release record](../KEEP_RELEASE.md) identifies the appliance's guest/runtime and assembly inputs. The earlier combined archive is **0.0.21-preview.1**.

Use isolated Linux x64 resources with Node.js 22.23.5 or later on Node 22, npm, Git, Rust 1.97.1 with its musl target, and host C build tools. The build verifies installed pinned tools. [Contributing](../WORKFLOW.md) lists build and partial-source checks.

```sh
git clone https://github.com/RedRookAI/keep-research-preview.git
cd keep-research-preview
npm ci
npm run build
node dist/src/main.js demo project
```

Before upgrading state, stop its writers and retain a verified private backup. Follow [backup guidance](backup.md) and the matching release notes.

## Historical 0.0.12 installation

These steps describe the October 5 archive. Use the combined route above for a new direct installation; it avoids the advisory-matched Node 22 npm installer.

The historical **0.0.12-preview.1** Linux x64 package includes compiled JavaScript, TypeScript and three native executables. It needs Node.js 22.23.3 or later on Node 22, npm and Git, with no Rust/C compiler. Its original qualification used Node 22.23.2. Updated runtime guidance follows a dependency fix; see [dependency status](dependency-status.md).

### Historical download, verify and run

Download `keep-0.0.12-preview.1.tgz` and its companion `KEEP_RELEASE.md`:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-05.1

Set `KEEP_RELEASE_SHA256` to the package checksum in that release record:

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

Expected version: `keep 0.0.12-preview.1`. The demo uses a temporary repository, two authored responses and sample decisions. It checks the edit, repository/goal tests, restart without replay, token refusal and vetoed source preservation.

Use the printed `Installed command` path for later commands, or add its directory to your PATH. Retain the installation prefix to keep using it. The printed evidence directory contains `result.json`, `outcome.json`, source, workspace and command records. The demo needs an available ephemeral loopback port; if that is blocked, use the recovery experiment.

### Historical follow-up commands

```sh
keep demo recovery
```

Expected output: `Recovery experiment passed: 24 checks; 0 model calls.` The experiment uses a synthetic local outbox and fresh processes; Git and a model account are unnecessary.

For model-backed work, [configure your provider and repository](installed-solve.md), run `keep doctor`, then use `keep solve "your goal"`. Your provider's prices and processing conditions apply. Required-jail operations still need their protected helper and namespace environment.
