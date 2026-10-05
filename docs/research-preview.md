# Keep research preview

**0.0.12-preview.1**, Linux x64, Node.js 22.23.2/npm. [Download the matching preview](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-10-05.1), verify its checksum in [the external release record](../KEEP_RELEASE.md), and follow the [installation guide](quickstart.md). No Rust/C compiler is needed for installation; the repository walkthrough also requires Git.

## First useful result

```sh
keep demo project
```

The walkthrough uses the installed repository workflow and two scripted local responses. It simulates sample approval/veto actions, prints an actual proposed diff and two passing tests, checks restart without replay and token refusal, and leaves the original sample source unchanged. Open the printed directory to inspect the workspace, proposal and command records. No account or paid provider request is needed. [Walkthrough details](portfolio-walkthrough.md).

For the companion recovery experiment:

```sh
keep demo recovery
```

It compares actual append-only local outbox effects against committed/reserved capacity, including lost acknowledgments and fresh-process restarts. The 24 named synthetic checks require no Git or model account; the provider throws if called.

## Continue on your own repository

[Configure a provider and repository](installed-solve.md), run `keep doctor`, then submit one bounded goal with `keep solve`. Review the printed project approval and exact-proposal merge/veto controls. The selected model's accounting, processing and authority requirements apply. The walkthrough's scripted result is not a model-quality prediction.

Keep retains [FrontDoor monetary admission](frontdoor-metering.md), [provider-check pricing](provider-check-pricing.md), [memory query admission](memory-recall-embedding.md), and [manual write](manual-memory-write.md)/[correction](manual-memory-correction.md) controls from recent checkpoints.

## Interpreting the result

The [release record](../KEEP_RELEASE.md) and [evidence](evidence.md) bind actual checks to exact source and package identities. Component passes, a scripted workflow and complete source/installed qualification are distinct. Historical receipts keep their original identities and counts.

The demonstration reports best-effort process isolation. Required-jail operations separately require measured Bubblewrap 0.13.0 and a qualified namespace environment; absent/mismatched launcher bytes must refuse. Installing Keep does not install a host launcher or change shared-host policy. Native binaries have [additional custody prerequisites](../SECURITY.md#optional-native-refusal-transport-installation-prerequisites); their presence does not qualify arbitrary workloads or production PROBER/D3 authority.

Evidence remains same-agent on a synthetic Linux fixture. It does not establish real-model success rates, live organization identity/custody, offsite disaster survival, universal spend enforcement or exactly-once effects across arbitrary services. Personal and organization requirements remain coequal in the [completion map](completion-map.md); this preview is not complete-product readiness.

Before upgrading existing state, stop its writers and retain a verified complete private backup. See [backup guidance](backup.md) and the matching release notes; do not mix old/new writers or interfere with other instances. Older 0.0.5 and affected 0.0.4 releases retain their original archives, tags and qualification records.
