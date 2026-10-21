# Run the combined preview

This guide describes the combined **0.0.19-preview.1** Linux x64 archive.
Use the [release record](../KEEP_RELEASE.md) for its exact download identity,
checksum and observed qualification. A source checkout is a separate artifact.
The earlier qualified 0.0.12 download keeps its original identity.

The October 20 combined/core/source archives contain a malformed exported Unicode example patch. The [October 21 example correction](genuine-codex-walkthrough.md#example-export-correction) provides the fixed file and a standalone example download. Those old runtime/archive bytes and receipts remain unchanged.

The new archive includes Keep, its TypeScript dependency, the restricted OpenClaw
plugin and the measured Codex generation.2 engine with source/attribution support.
Run Keep directly from the extracted directory; npm is not needed for this path.
The Node22 runtime's bundled npm10 installer is outside this supported route and
has unresolved advisory matches. [Dependency status](dependency-status.md).

## Open the preview

Use Linux x64 with the Ubuntu24.04 runtime/library baseline and a patched Node22
runtime, at least22.23.3 on that line. Keep and OpenClaw use different Node lines:
OpenClaw2026.10.5 uses its supported patched Node24 runtime. Selecting Keep's Node
below does not replace PATH or change the OpenClaw installation.

After verifying the published SHA256, extract into a new directory you own:

```sh
tar -xzf keep-combined-0.0.19-preview.1-linux-x64.tar.gz
cd keep-0.0.19-preview.1
export KEEP_NODE_EXECUTABLE=/absolute/path/to/node22/bin/node
export PATH="$(pwd)/bin:$PATH"
./bin/keep version
./bin/keep demo project
```

The demo produces a separate-workspace proposal, checks and a veto using disclosed
scripted responses. It needs no account. For actual generated work, inspect the
[recorded genuine result](genuine-codex-walkthrough.md), then configure your own
repository using the [Codex role](codex-project.md). Select the bundled native
engine rather than an arbitrary stock Codex launcher:

```sh
export KEEP_CODEX_EXECUTABLE="$(pwd)/engines/codex-generation.2/bin/codex"
```

Use your own existing Codex login. Authentication is not bundled or copied.
Required-jail repository checks still need the measured Bubblewrap0.13.0 helper,
a protected installation path and working host namespaces. Follow [owned setup](local-instance.md#selecting-an-existing-required-jail-helper).
An absent helper or unsupported namespace setup refuses required-jail work;
extracting this archive does not install a host helper or change host policy.

## Connect OpenClaw

Use a dedicated profile in your existing supported OpenClaw2026.10.5 installation.
Install the included local plugin archive with that runtime:

```sh
openclaw --profile keep-portfolio plugins install ./integrations/openclaw/redrookai-openclaw-keep-0.0.19-preview.1.tgz --force --accept-capabilities --no-enable
```

Review the verified local package before consenting. The flags apply to that
dedicated profile; the plugin stays disabled until configured. Use the direct
archive path shown: `npm-pack:` selects a different managed-npm route. The plugin
has no runtime dependencies, and the observed direct install invoked no npm. Follow the [restricted client setup](../integrations/openclaw/README.md)
to issue its client identity, configure Keep's origin and enable the plugin in
that same profile. Then submit one repository
goal, open the Keep console, inspect its pending step and decide the proposal.
Original commands, grants and decisions stay attributable in Keep. No supplied
profile grants the agent owner approval or broad host tools.

## Source and support

The engine's source patches, dependency notices and included MPL source are under
`engines/codex-generation.2/source-support.tar.gz`; the support README documents
the exact upstream commit and build recipe. Keep's source and normal notices are
included alongside its emitted runtime. Rebuilding is optional; a rebuilt engine
has a new identity and does not inherit these measured-binary observations.

The release record binds the exact archive, source and installed checks.
Historical failures and account uncertainty remain recorded; one genuine case
is integration evidence, not a model-quality benchmark or enterprise certification.
