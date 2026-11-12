# Run the combined preview

The **0.0.21-preview.1** Linux x64 archive includes Keep, TypeScript, the restricted OpenClaw plugin and the measured Codex generation.2 engine with source support. Run it directly from the extracted directory. See the [release record](../KEEP_RELEASE.md) for its download identity, checksum and tested scope.

This November 11 archive includes the corrected Unicode example. The October 20 combined/core/source archives retain the malformed patch; use the [corrected example](genuine-codex-walkthrough.md#example-export-correction) for reproduction.

## Open the preview

Use Linux x64 with the Ubuntu 24.04 library baseline and Node 22.23.5 or later on the Node 22 line. OpenClaw 2026.10.5 uses its separately supported patched Node 24 runtime. The direct archive route excludes Node 22's bundled npm 10 installer, which has unresolved advisory matches. Check [dependency status](dependency-status.md) before selecting a runtime.

Verify the published SHA256, then extract into a new directory you own:

```sh
tar -xzf keep-combined-0.0.21-preview.1-linux-x64.tar.gz
cd keep-0.0.21-preview.1
export KEEP_NODE_EXECUTABLE=/absolute/path/to/node22/bin/node
export PATH="$(pwd)/bin:$PATH"
./bin/keep version
./bin/keep demo project
```

The account-free demo produces a workspace proposal, checks and a veto using two authored responses. For generated work, follow the [Codex guide](codex-project.md) and select the bundled native engine:

```sh
export KEEP_CODEX_EXECUTABLE="$(pwd)/engines/codex-generation.2/bin/codex"
```

Use your own existing Codex login. Required-jail repository checks also need the measured Bubblewrap 0.13.0 helper at a protected path and working host namespaces. Follow [helper selection](local-instance.md#selecting-an-existing-required-jail-helper). Extraction leaves host tools and policy unchanged; unsupported required-jail setup refuses.

## Connect OpenClaw

Use a dedicated profile in an existing supported OpenClaw 2026.10.5 installation. Install the included plugin with that runtime:

```sh
openclaw --profile keep-portfolio plugins install ./integrations/openclaw/redrookai-openclaw-keep-0.0.21-preview.1.tgz --force --accept-capabilities --no-enable
```

Review the local package before accepting its capabilities. These flags affect the dedicated profile and leave the plugin disabled until configured. Use the direct archive path shown; `npm-pack:` selects a different managed-npm route. The plugin has no runtime dependencies, and the observed direct installation invoked no npm.

Follow [restricted client setup](../integrations/openclaw/README.md) to issue its identity, set Keep's origin and enable it in that profile. Submit a repository goal, approve preparation in Keep's console, then inspect and decide the proposal. The restricted client can submit and inspect its own work; owner approval stays in Keep.

## Source and support

`engines/codex-generation.2/source-support.tar.gz` contains the engine's source patches, notices and declared MPL source. Its README gives the upstream commit and build recipe. Keep's source and notices accompany the runtime. A rebuilt engine has a new identity and needs its own verification.

The [genuine repository case](genuine-codex-walkthrough.md) records live generation with this engine. The release record separately identifies exact-archive checks and historical failures.
