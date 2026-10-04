# Run the current source checkpoint

The public source version is **0.0.5-preview.1**. There is no downloadable binary
for this version yet. The older 0.0.4-preview.1 archive remains historical and
retains its affected launcher pin; see [Security](../SECURITY.md).

## Prerequisites and build

Use an isolated Linux x64 checkout, Node.js 22.23.2, npm, Git, the pinned Rust
1.97.1 toolchain with its musl target, and host C build tools. The build verifies
the existing toolchain; it does not fetch a replacement. Configure `RUSTUP_HOME`
or `KEEP_P1_TOOLCHAIN_ROOT` for your already acquired toolchain as described in
[Contributing](../WORKFLOW.md).

```sh
git clone https://github.com/RedRookAI/keep-research-preview.git
cd keep-research-preview
npm ci
npm run build
node dist/src/main.js version
node dist/src/main.js demo recovery
```

Expected version: `keep 0.0.5-preview.1`. A passing demo prints:

```text
Recovery experiment passed: 24 checks; 0 model calls.
Detailed results: /tmp/keep-installed-fleet-uncertainty-<generated-id>/report.json
```

Inspect the generated report and local outbox records. No account or paid model
is required. Use synthetic data and isolated resources. Required project jail
operations additionally need the exact reviewed Bubblewrap launcher and a
qualified namespace environment; an absent or mismatched launcher must refuse.
Do not change a shared host's security policy to make a demonstration pass.

Before upgrading existing state, stop writers and retain a verified complete
private backup. Read [backup guidance](backup.md) and the
[checkpoint record](../KEEP_RELEASE.md). Do not mix old and new writers.
