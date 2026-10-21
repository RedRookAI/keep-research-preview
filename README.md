# Keep

**Repository automation with explicit control.**

Keep turns a repository goal into a tested, reviewable change proposal. It prepares edits in a separate working copy and records the tests, decisions and recovery state behind the result. The project explores how to give AI agents useful responsibility while keeping consequential actions accountable.

## Inspect a real result

A genuine Codex follow-up produced a working Unicode-regex fix through Keep and the native OpenClaw plugin. The unchanged independent checker passed all three cases, fresh-process status returned the same job, and the exact proposal was vetoed while the original source stayed unchanged.

[Inspect the patch, actual console panels and execution record](docs/genuine-codex-walkthrough.md). The record distinguishes live Codex generation from scripted OpenClaw tool selection and developer-administered decisions.

## Try the preview

Extract the [combined Linux x64 preview](docs/combined-preview.md), select its supported Node runtime, then run:

```sh
./bin/keep demo project
```

The walkthrough creates a sample repository, proposes a change, runs its tests and prints the actual diff. It also checks approval before dispatch, restart without replay, rejection of a wrong token, and source preservation after veto. Open the printed evidence directory to inspect the files and results.

```text
PASS  Approval gate held: 0 model calls before sample approval
PASS  Materialized change: retry limit 0 → 7
PASS  Tests: limit; goal: requested outcome
PASS  Restart retained the proposal without replay
PASS  Wrong token refused; exact proposal vetoed; original source unchanged
```

The demo uses **two scripted local responses and simulated approval/veto decisions**, with no model account or paid request. The workspace edits, tests and retained artifacts are real. Use Node.js 22.23.3 or later on Node 22 and Git; the direct archive route needs no npm installer, Rust or C compiler. See the dated [dependency guidance](docs/dependency-status.md). [Walkthrough and evidence](docs/portfolio-walkthrough.md).

## How it works

```mermaid
flowchart LR
    Goal[Repository goal] --> Approval[Approval decision]
    Approval --> Workspace[Separate working copy]
    Workspace --> Checks[Repository and goal checks]
    Checks --> Proposal[Diff and review evidence]
    Proposal --> Decision[Proposal-bound decision]
```

- **Separate proposal from source.** Inspect the proposed files and tests before an authorized landing operation.
- **Bind decisions to the result.** Review controls identify the exact proposal; recording a decision does not grant missing execution authority.
- **Retain interrupted work.** Durable project records distinguish pending, completed and uncertain outcomes instead of assuming a retry is safe.
- **Make limits visible.** The demo's best-effort isolation and the opt-in required project jail have different prerequisites and evidence.

[Architecture and trust boundaries](docs/architecture.md) · [Security model](SECURITY.md) · [Validation evidence](docs/evidence.md) · [Dependency status](docs/dependency-status.md)

## Current status

| Component | Status |
|---|---|
| Download | **0.0.19-preview.1**, combined Linux x64 preview with the generation-only engine and OpenClaw plugin. [Release record](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-20.1) · [Run from the archive](docs/combined-preview.md). |
| Development source | **0.0.19-preview.1**. Includes literal patch replacement, applicability checks before goal-test generation, browser-compatible console decisions and explicit native-plugin exclusion. A genuine installed Codex/OpenClaw follow-up now passes at its documented scope. The combined archive adds a direct startup command and bundled runtime dependencies. [Status and limits](docs/codex-project.md). |
| OpenClaw | The **0.0.19-preview.1** plugin is included in the combined archive. Native submission/status, separate human approval, tested proposal and fresh-process recovery were observed in the controlled workflow and genuine Codex follow-up. The final archive separately passed plugin install/configuration/load. [Client setup and limits](integrations/openclaw/README.md). |

Keep is a research preview. The supplied demonstrations establish specific workflow and recovery behavior, with developer-administered evidence. They do not establish general model quality, production enterprise isolation or independently audited security. [Supported scope and roadmap](ROADMAP.md).

## Documentation

- [Install and run](docs/quickstart.md) and [operate a development instance](docs/local-instance.md)
- [Configure repository work](docs/installed-solve.md) and [experimental Codex access](docs/codex-project.md)
- [OpenClaw plugin](integrations/openclaw/README.md) and [restricted client admission](docs/openclaw-client.md)
- [Recovery experiment](docs/research-preview.md) and [backup compatibility](docs/backup.md)
- [Memory](docs/semantic-memory.md), [skill registry](docs/skill-registry.md) and [usage accounting](docs/monetary-accounting.md)
- [Build and contribute](WORKFLOW.md)
- [Release identities](KEEP_RELEASE.md), [license and attribution](docs/licensing.md)

Released under the [MIT license](LICENSE).
