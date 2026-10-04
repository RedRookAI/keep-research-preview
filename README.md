# Keep

Keep is a self-hosted platform for AI agents working on ongoing projects. It combines persistent knowledge, reusable skills and a native execution runtime with controls for permissions, acceptance and recovery. Security is at the heart of its approach to autonomy: useful work should preserve the operator's control over data, resources and effects.

## Current research preview

**0.0.5-preview.1** carries the completed scoped audit remedies, including the
measured Bubblewrap 0.13.0 identity across all three source launcher consumers.
The Linux x64 package includes compiled JavaScript and the three existing native
transport executables. Read the [exact release record](KEEP_RELEASE.md) for
artifact identities, actual qualification results and boundaries.

Release assets: [keep-preview-2026-10-04.1](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-04.1).
Verify the matching package against the release record before installation;
[installation and the first experiment](docs/quickstart.md) need Node 22 and npm,
without a Rust or C compiler. The historical **0.0.4-preview.1** archive retains
its affected launcher pin and original checksum.

## Build and try the current source

Use Linux x64 and Node.js 22.23.2. Source builds additionally require the pinned
Rust 1.97.1 toolchain, its musl target and host C build tools. Follow the
[source quickstart](docs/quickstart.md) and [build prerequisites](WORKFLOW.md).
After building:

```sh
node dist/src/main.js version
node dist/src/main.js demo recovery
```

Expected version: `keep 0.0.5-preview.1`. The recovery experiment uses synthetic
local outbox effects and no model calls. Its 24 cases exercise accounting,
uncertain acknowledgements and fresh-process restart. A passing demonstration
has narrower scope than complete source or installed-artifact qualification.

The optional native refusal transport has separate custody requirements. See
[Security](SECURITY.md#optional-native-refusal-transport-installation-prerequisites).

## What this preview offers

Keep has CLI, gateway and client interfaces, project and memory storage, skill validation, governed coding workflows and resource-accounting mechanisms. The supported first-run result is the synthetic local recovery experiment. Provider-backed coding, enterprise identity and host isolation require their own configuration and qualification.

This remains a research preview. Use synthetic data and isolated test resources while evaluating it. It is not qualified for unattended consequential production work, universal spending enforcement or exactly-once effects across arbitrary remote services. [Known limitations](docs/research-preview.md#interpreting-the-result) describe those boundaries.

## Read further

- [Preview installation and source quickstart](docs/quickstart.md)
- [October 4 changes and qualification](docs/maintenance-2026-10-04.txt)
- [Latest audit and security-update progress](docs/maintenance-2026-10-04.txt)
- [Installation details and limitations](docs/research-preview.md)
- [Release record and qualification evidence](KEEP_RELEASE.md)
- [Proposed security research](docs/security-experiments.md)
- [Semantic memory](docs/semantic-memory.md), [skills](docs/skill-registry.md) and [backups](docs/backup.md)
- [Contributing and source builds](WORKFLOW.md)
- [Security and private reporting](SECURITY.md)
- [Licensing and attribution](docs/licensing.md)

## Source contributors

Binary-package users can skip source builds. Contributors need Node/npm, Git, the pinned Rust toolchain and host C build tools for native compilation. The source includes the locked dependencies and build instructions; see [Contributing](WORKFLOW.md).

