# Keep research preview

Start with the [guided browser demo](guided-demo.md) or [installation guide](quickstart.md). The current reviewer appliance is **0.0.30-preview.1**; the separate direct Node archive is **0.0.21-preview.1**. The historical **0.0.19-preview.1** combined archive includes the generation-only Codex engine and restricted OpenClaw plugin described below.

That .19 observation used Node 22.23.3 for Keep and Node 24.22.0 for OpenClaw 2026.10.5. Select a patched runtime using the current [dependency guidance](dependency-status.md). The direct archive route needs Git for repository work and runs without npm installation or Rust/C compilers.

## First useful result

```sh
keep demo project
```

The installed walkthrough uses two authored responses and sample approval/veto decisions. It prints a workspace diff and two passing tests, checks restart without replay and token refusal, and preserves the original source. Inspect the printed directory for proposal and command records. [Walkthrough details](portfolio-walkthrough.md).

For the recovery experiment:

```sh
keep demo recovery
```

The experiment compares append-only local outbox effects with committed/reserved capacity through lost acknowledgments and fresh-process restarts. Its 24 synthetic checks need neither Git nor a model account; the fixture provider throws if called.

## Continue on your own repository

[Configure a provider and repository](installed-solve.md), run `keep doctor`, then submit a bounded goal with `keep solve`. Review the pending approval, diff/checks and exact-proposal decision. Your selected provider's accounting, processing and authority requirements apply.

Related controls cover [FrontDoor monetary admission](frontdoor-metering.md), [provider-check pricing](provider-check-pricing.md), [memory query admission](memory-recall-embedding.md), [manual writes](manual-memory-write.md) and [corrections](manual-memory-correction.md).

## Interpreting the result

The [release record](../KEEP_RELEASE.md) and [evidence](evidence.md) identify each tested source and archive. The account-free demonstrations use synthetic Linux fixtures. The [genuine Codex case](genuine-codex-walkthrough.md) records live generation on one historical public issue, with scripted OpenClaw tool selection. These observations were developer-administered; broader model evaluation and live organization operation remain open in the [completion map](completion-map.md).

The demo uses best-effort process isolation. Required-jail operations need measured Bubblewrap 0.13.0 and working host namespaces; absent or mismatched launcher bytes refuse. Native binaries have [additional custody prerequisites](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites). Production native authority, offsite recovery, complete spend enforcement and arbitrary-service exactly-once effects remain unqualified.

Before upgrading state, stop its writers and retain a verified private backup. Follow [backup guidance](backup.md) and the matching release notes. Older 0.0.5 and affected 0.0.4 archives retain their original tags and records.
