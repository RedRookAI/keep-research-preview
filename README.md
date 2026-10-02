# Keep

Keep is a self-hosted platform for AI agents working on ongoing projects. It combines persistent knowledge, reusable skills and a native execution runtime with controls for permissions, acceptance and recovery. Security is at the heart of its approach to autonomy: useful work should preserve the operator's control over data, resources and effects.

## Install and try it

**Linux x64, Node.js 22 with npm. No Rust or C toolchain is needed to install the binary package.** The qualified Node version for this release is 22.23.2.

Download `keep-0.0.4-preview.1.tgz` from the [0.0.4-preview.1 release](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-02.1), verify its SHA256 against the release record, then install:

```sh
npm i -g ./keep-0.0.4-preview.1.tgz
```

If your npm global directory is not writable, use the user-local installation in the [five-minute quickstart](docs/quickstart.md). The archive bundles its existing JavaScript runtime dependency and the real native transport binaries. Installation does not compile native code or download a replacement transport.

Run the no-key recovery experiment:

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

Only the generated results-directory suffix varies. The experiment records local outbox effects, loses acknowledgments and restarts processes. It checks that uncertain work stays accounted for and that permitted work can still proceed. It uses synthetic data, makes no model calls and requires no account or paid service.

The native transport is included exactly through Keep's source-build packaging mechanism. Its optional refusal-only exchange has separate custody requirements; the introductory experiment exercises the installed accounting and recovery API. See [Security](SECURITY.md#optional-native-refusal-transport-installation-prerequisites).

## What this preview offers

Keep has CLI, gateway and client interfaces, project and memory storage, skill validation, governed coding workflows and resource-accounting mechanisms. The supported first-run result is the installed recovery experiment above. Provider-backed coding, enterprise identity and host isolation require their own configuration and qualification.

This remains a research preview. Use synthetic data and isolated test resources while evaluating it. It is not qualified for unattended consequential production work, universal spending enforcement or exactly-once effects across arbitrary remote services. [Known limitations](docs/research-preview.md#interpreting-the-result) describe those boundaries.

## Read further

- [Five-minute quickstart](docs/quickstart.md)
- [Release changes and upgrade guidance](docs/maintenance-2026-10-02.md)
- [Installation details and limitations](docs/research-preview.md)
- [Release record and qualification evidence](KEEP_RELEASE.md)
- [Proposed security research](docs/security-experiments.md)
- [Semantic memory](docs/semantic-memory.md), [skills](docs/skill-registry.md) and [backups](docs/backup.md)
- [Contributing and source builds](WORKFLOW.md)
- [Security and private reporting](SECURITY.md)
- [Licensing and attribution](docs/licensing.md)

## Source contributors

Binary-package users can skip source builds. Contributors need Node/npm, Git, the pinned Rust toolchain and host C build tools for native compilation. The source includes the locked dependencies and build instructions; see [Contributing](WORKFLOW.md).

