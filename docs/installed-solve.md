# Configure a repository goal

The qualified **0.0.12-preview.1** download includes `keep solve` through the project runtime with an API-compatible provider. The existing-account [Codex project role](codex-project.md) is experimental **0.0.14-preview.1 source only**; it is not in that download. Start with [the account-free walkthrough](quickstart.md) to inspect the workflow without configuring a provider.

## Repository settings

Choose a repository you own or are authorized to process. Keep requires an exact commit and a separate existing directory for its working copies.

| Variable | Value |
|---|---|
| `KEEP_REPOSITORY` | Path to the source Git working tree, trusted by the current OS user. |
| `KEEP_WORKSPACE_BASE` | Existing directory disjoint from the source: neither may contain the other. |
| `KEEP_REVISION` | Exact lowercase 40- or 64-hex commit ID that exists in the source repository. |
| `KEEP_REPO_REF` | Repository identifier as one canonical path component. |
| `KEEP_BASE_BRANCH` | Existing local branch pointing at that exact commit; defaults to `main`. |
| `KEEP_TEST_COMMAND` | Executable for the repository's own checks. |
| `KEEP_TEST_ARGS_JSON` | Optional JSON array of arguments, such as `["test"]` for an npm test command; defaults to `[]`. |
| `KEEP_TEST_NAMESPACE_JAIL` | Optional `required`, `best-effort` or `off` selection. Only `required` demands the measured launcher and qualified namespace setup. |

Use predefined repository checks that distinguish the requested fix from unrelated behavior. Best-effort/default execution does not establish the required jail's boundary. Review the [execution limits and prerequisites](../SECURITY.md#opt-in-required-project-boundary-experimental) before running repository code.

## Provider settings

For existing Codex access, use the [source-only account setup](codex-project.md), then return to the commands below. That route uses your existing login without a separate API key. Its live installed workflow remains unqualified.

For an already authorized API-compatible provider, the existing configuration is:

| Variable | Value |
|---|---|
| `KEEP_PROVIDER` | `openai-compatible` or `anthropic-compatible`. The separate `local` mode is a deterministic stub, not a local language model. |
| `KEEP_PROVIDER_AUTHORITY` | Explicitly `owner` for a personal configuration. Organization mode has separate release, identity and custody requirements. |
| `KEEP_PROVIDER_BASE_URL`, `KEEP_PROVIDER_MODEL` | Authorized endpoint and supported model identifier. HTTPS is required except for explicit loopback endpoints. |
| `KEEP_PROVIDER_LOCATION` | `local` or `external`, matching the processing location. Loopback can be inferred as local. |
| `KEEP_PROVIDER_API_KEY`, `KEEP_PROVIDER_API_KEY_FILE`, `KEEP_PROVIDER_API_KEY_STDIN` | Select exactly one credential source; stdin selection is exactly `1`. An owner-local loopback fixture may omit credentials. Keep secrets out of repository files and logs. |
| `KEEP_REMOTE_PROCESSING_PURPOSE`, `KEEP_REMOTE_PROCESSING_REGION` | Declared purpose and region for processing. |

The API-priced solver requires a model price known to its accounting path. Unknown remote-compatible model prices refuse before a request, including on loopback; locality does not imply a zero fee. Readiness does not establish current prices, funded execution or model quality. This guide does not require purchasing API access.

Run `keep doctor` after configuration. A readiness result checks configuration; it does not qualify the model or production host. `keep onboard` captures directives and does not supply these execution settings.

## Request and review a proposal

```sh
keep solve "Correct the retry limit; preserve unrelated behavior and tests"
```

Solve accepts a description and no options. It starts with approval required, including when `KEEP_PROJECT_POSTURE` is `autonomous`. The printed run and decision identify the next operation:

```sh
keep project resume <run-id> --approve=<decision-id>
```

Keep materializes the exact source revision into a workspace and records the proposal, diff, rollback information and test results. Follow its printed controls. Pending project work uses project resume/merge controls rather than the legacy `keep review` queue. A merge decision is bound to the exact proposal digest:

```sh
keep merge <run-id> approve --proposal=<sha256>
keep merge <run-id> veto --proposal=<sha256>
```

A decision does not grant missing merge authority. Inspect a refused or held result; a successfully recorded decision does not prove that source changes landed. The original repository remains unchanged while a proposal awaits a decision. Existing owner-token checks and organization session/roster/custody restrictions apply; the remote gateway uses the same authenticated project endpoint.

The [installed-solve receipt](qualification/installed-solve-2026-10-05.json) records an installed controlled-endpoint check of routing, approval, a useful fixture edit and review/restart behavior. The [download qualification](qualification/preview-2026-10-05.json) covers the later packaged preview. Neither establishes arbitrary real-model success, live organization onboarding or production isolation.
