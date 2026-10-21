# Codex for owner repository projects

Source **0.0.19-preview.1** provides a project generation role using an existing signed-in Codex CLI. A [genuine installed follow-up](genuine-codex-walkthrough.md) now passes through Keep, native OpenClaw tools and the browser console. Earlier failed attempts and their uncertainty remain recorded. The [combined preview](combined-preview.md) packages this route; the historical **0.0.12-preview.1** download does not support this selector.

Keep's intended division of responsibility is structured generation through Codex, with edits, tests, approval and proposals controlled by Keep. The bundled source-derived generation-only CLI has passed a credential-free tool-catalog check; stock CLI flags do not establish that boundary. The genuine account workflow is observed. The combined preview supplies the measured native engine; see the supported scope below.

Use an existing ChatGPT Codex login on the same machine. Keep checks `codex --version` and `codex login status`; it does not copy authentication files or change global configuration. Select a public repository you own or are authorized to process. Configure the repository/test variables in [repository settings](installed-solve.md#repository-settings), then explicitly set:

```sh
export KEEP_PROVIDER=local
export KEEP_PROJECT_MODEL=codex
export KEEP_CODEX_PROCESSING=owner-public-repository
export KEEP_CODEX_EXECUTABLE=/absolute/path/to/keep-0.0.19-preview.1/engines/codex-generation.2/bin/codex
export KEEP_CODEX_MODEL=your-supported-codex-model
export KEEP_CODEX_MAX_INVOCATIONS=2
export KEEP_CODEX_MAX_PROMPT_BYTES=65536
export KEEP_CODEX_MAX_OUTPUT_BYTES=262144
export KEEP_CODEX_TIMEOUT_MS=180000
keep doctor
keep solve "Your bounded repository goal"
```

These are suggested operator-selected limits, not account billing guarantees. The project role is remote; `KEEP_PROVIDER=local` applies only to the remaining non-project roles and credential-free embeddings. No API key or separate API provider is used. Codex subscription allowance still applies; total subscription cost cannot be attributed per turn here. Observed input/cached/output token usage is recorded alongside unknown dollar cost, internal wire attempts and reported model identity. Requested model is recorded separately.

Keep bounds CLI invocations across the data directory, submitted stdin bytes, captured stdout/stderr and process time. These are not verified hard model output-token, complete model input-byte or internal wire-attempt ceilings. Legacy API requests requiring such guarantees refuse; the explicit project selector opts into the account-managed contract. The invocation requests read-only operation, disabled search and explicit per-invocation exclusions for shell tools, snapshots, dependency installation, apps, hooks and multi-agent channels. An October 20 metadata check on CLI **0.163.0** reported `shell_tool` disabled but `unified_exec` still enabled despite requested false settings. The [official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) explains that user opt-outs for unified exec are ignored; its state alone does not establish which command tools are available. These flags therefore do **not** establish unconditional tool prevention. Rejecting an unexpected tool event after it appears is detection, not proof that execution was prevented. The native CLI rejects overrides of its built-in openai provider, so its internal default retries are not disabled or bounded here. Requests requiring a verified hard wire-attempt ceiling refuse. Unexpected tool activity/output, timeout or cancellation may leave remote work uncertain and prevent another invocation. Stopping the local process cannot prove remote work stopped. There is no automatic reconciliation or quota reset. Changing the model binding does not refund claims; operator changes to the configured allowance are explicit.

Before generation, the installed native path rechecks the pinned source commit and clean working tree as well as the original command authority. Keep data and workspaces must remain outside that source. Keep prepares proposed edits in a separate workspace; the source must remain unchanged while a proposal awaits a decision. Approve through the existing project workflow; inspect its diff and test evidence. Restart reuses the same configured descriptor. This initial role supports public owner software projects only: no private task-memory, domain workflows, embeddings via Codex, organization custody or production isolation claim. CLI executable hashing pins the selected executable bytes, not every dynamically loaded dependency.

The matching 0.163.0 [tool-assembly source](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core/src/tools/spec_plan.rs) separately registers `apply_patch` from model/environment metadata, outside the shell-feature check. Its [startup tool policy](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/ext/extension-api/src/tool_policy.rs) can express an empty allowlist, but the stock CLI has no established injection path through this adapter. The bundled generation variant instead imposes that ceiling inside startup, as described below. Shell exclusions and read-only sandboxing must not be described as a complete generation-only tool catalog.

## Generation-only native engine

The bundled engine is derived from upstream Codex 0.163.0 with a narrow startup-policy change: an empty allowed-tools ceiling is applied before session/router construction and retained in thread initialization. The bundled variant is `0.163.0-keep-generation.2`, updating Rustls to 0.23.46 while preserving the generation policy. It compiled successfully under the owned resource limits. Its credential-free native consumer used the v4 common settings and observed empty outgoing tool catalogs, refusal of an unadvertised tool request and completed structured generation. The earlier `.1` executable remains preserved at its original identity. This is stronger evidence than requesting read-only mode or detecting a tool event after execution, but applies to that measured engine and profile.

The measured executable SHA-256 is `fdd9a1a3e86fc2213e4c0bd9c9b278080f38d756a5256e3217092a30e48d98c1`. The combined archive includes it with source patches, attribution and the declared MPL source packages. Its exact installed qualification belongs to the matching release record. The linked genuine follow-up is observed at its declared scope. Do not substitute an arbitrary stock executable and assume equivalent enforcement. [Current dependency status](dependency-status.md).

## Compatibility and qualification

The version check now identifies CLI 0.163.0; the first failed native attempt used 0.159.3. Metadata from a newer CLI does not explain that earlier failure or qualify the installed account route. The process profile now explicitly disables apps, hooks and multi-agent features as well as shell tools, snapshots and dependency installation. Duplicate and ineffective unified-exec opt-outs have been removed. The profile version is part of the durable generation identity, so a previously queued command cannot silently adopt a different profile. Complete pre-execution tool exclusion is not established for the stock CLI by these flags. Native Codex plugins are also explicitly disabled for this generation-only subprocess; this does not disable Keep's OpenClaw integration.

The generation transport recognizes the specific Codex0.163.0 startup warning that its optional code-mode host is absent and will fail closed. It records only the warning code `code-mode-host-unavailable`, and still requires a completed structured answer with usage. Unknown errors, tool activity and incomplete results continue to refuse. This diagnostic compatibility was introduced in generation profile v3. The current source uses v4 to additionally disable native Codex plugin discovery and startup synchronization. Queued work and follow-up authorizations bound to older profiles cannot silently adopt it. Earlier installations retain their recorded profiles until an explicit upgrade. Handling a warning does not establish tool exclusion or qualify an installed account-backed workflow.

Select the actual native executable with `KEEP_CODEX_EXECUTABLE` when preparing the supported profile. Keep hashes the selected executable before dispatch. Use the platform binary supplied by the trusted installation, rather than its Node launcher; do not change a shared installation to select it. The recorded genuine follow-up used this direct-native route; archive-specific qualification is recorded with the matching release. Measure the actual native executable as well as any launcher. Hashing a Node wrapper alone does not bind the platform binary it loads. This review did not change the installed CLI, authentication or global configuration.

## Qualification and recovery

Controlled source checks cover explicit generation approval and safe error diagnostics. They do not establish success of the installed live-account route or qualify a downloadable release. The first native failure's cause remains unresolved; diagnostic categories are hints, not proof of zero remote work or authority to retry.

Retain the uncertain invocation. Do not automatically retry or use a new data directory to bypass the retained claim. Use the [combined download](combined-preview.md) for the bundled measured engine and established preview capabilities. See [validation evidence](evidence.md), [architecture](architecture.md) and [release priorities](../ROADMAP.md) for the current scope.

### Explicit owner follow-up after uncertainty

The current preview includes a local owner command for bounded follow-up work. It does not reconcile remote work or qualify the native generation route. An uncertain attempt remains uncertain and consumes its original invocation allowance.

With `KEEP_DATA_DIR` pointing at the existing instance, run:

```sh
keep codex-usage status
```

This needs the existing local owner credential, but no provider setup or model call. It reports the total claims and exact IDs of unresolved attempts, without prompt text or native diagnostics. An explicit `KEEP_OWNER_TOKEN_FILE` or `KEEP_OWNER_TOKEN` must match the instance's protected owner token. Remote gateway clients cannot administer account usage.

After reviewing a recorded uncertain failure and authorizing further account use, configure the intended personal Codex project and its total allowance. For example, one old claimed attempt plus two approved follow-ups requires `KEEP_CODEX_MAX_INVOCATIONS=3`. Substitute the actual ID from status:

```sh
keep codex-usage authorize-followup \
  --uncertain=ACTUAL_UNCERTAIN_CLAIM_ID \
  --expected-claims=1 \
  --additional-invocations=2
```

List every unresolved claim ID separated by commas. A still-pending invocation cannot be acknowledged as a recorded uncertain failure. Changed claim counts or incomplete IDs refuse rather than authorize different work. The command records the current generation identity and a finite additional allowance; it invokes no model and resumes no job. Repeating the same acknowledgement before new dispatch adds no allowance. Normal project approval, source/grant checks and runtime restrictions still apply.

The authorization survives restart. Successful follow-ups consume its allowance; another uncertain failure stops further dispatch until an owner reviews the new complete set of uncertain claims. Changing the model, executable, profile or configured limits cannot transfer an old authorization to that new identity. Configured totals never refund previous claims, including the original uncertain one. This is an owner acknowledgement of risk and bounded additional use, not evidence that the earlier remote work stopped or that Codex's generation-only tool restriction has been established.

## Observed genuine follow-up

The [recorded repository result](genuine-codex-walkthrough.md) passed through actual installed Keep, native OpenClaw tools and the browser console using the generation.2 executable above. Codex performed two successful generation invocations; the unchanged independent checker passed all three checks, fresh-process status recovered the same job, and exact veto preserved the source. OpenClaw tool selection was scripted; decisions were developer-administered. Earlier failures remain historical, and this integration result is distinct from archive-specific qualification.
