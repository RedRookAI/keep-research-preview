# Five-minute quickstart

The first-run experiment needs Linux x64, Node.js 22 and npm. This release is qualified on Node 22.23.2. It needs no Rust compiler, C compiler, Git, model account, GPU or API key. The binary archive bundles TypeScript, its existing JavaScript dependency, so installation can also be performed offline after obtaining the archive.

## 1. Obtain and verify the package

Download `keep-0.0.4-preview.1.tgz` and the accompanying `KEEP_RELEASE.md` from the named [release](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-02.1).

Copy the package SHA256 from the release record, then check it before installation:

```sh
printf '%s  %s\n' 'COPY_THE_PACKAGE_SHA256_FROM_KEEP_RELEASE.md' 'keep-0.0.4-preview.1.tgz' | sha256sum -c -
```

Continue only if it prints `keep-0.0.4-preview.1.tgz: OK`. Comparing a downloaded file with its own computed hash is not publisher authentication; use the digest in the trusted release record.

## 2. Install

```sh
npm i -g ./keep-0.0.4-preview.1.tgz
```

For a writable user-local installation instead:

```sh
npm i -g --prefix "$HOME/.local" ./keep-0.0.4-preview.1.tgz
export PATH="$HOME/.local/bin:$PATH"
```

Keep the second line in your shell's usual PATH configuration if you want it to persist. No administrator access or source-build toolchain is required for this introductory installation. The package is specifically for Linux x64; other architectures need a separately qualified build.

## 3. Run the recovery experiment

```sh
keep version
keep demo recovery
```

Expected output:

```text
keep 0.0.4-preview.1
Recovery experiment passed: 24 checks; 0 model calls.
Detailed results: /tmp/keep-installed-fleet-uncertainty-<generated-id>/report.json
```

The results directory is generated for each run. The report and child-process logs contain the detailed checks; inspect `report.json` at the printed path. Preserve that directory elsewhere if you need it after temporary-file cleanup.

Sixteen accounting cases and eight dispatch-permit cases compare Keep's state with a durable local outbox. They cover successful work, lost acknowledgments, refusal, retained uncertainty, fresh-process restart and permit reuse. Both personal and injected-tenant configurations run; injected identity is not a production identity provider. The experiment checks the actual local sink, not just a success label, and makes no external effect or paid call.

## 4. Explore

```sh
keep help
```

The [preview guide](research-preview.md) explains configuration and limitations. The package includes the actual native client, supervisor and patch-capture binaries. The optional native refusal exchange requires administrator-owned custody described in [Security](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites); ordinary npm installation does not silently relax that boundary.

The recovery experiment does not qualify arbitrary coding tasks, production isolation, outside identity systems or remote-effect finality. Choose the next workflow from its own documented prerequisites rather than assuming that a successful introductory experiment establishes every guarantee.
