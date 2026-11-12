# Use Codex for repository projects

Codex generates proposed edits and goal tests; Keep controls workspace changes, repository checks and proposal decisions. The [combined preview](combined-preview.md) supplies the measured generation-only engine. A [recorded repository case](genuine-codex-walkthrough.md) completed this route through native OpenClaw and Keep's browser console.

Use an existing ChatGPT Codex login on the same machine and a public repository you own or are authorized to process. Keep checks the engine's version and login status. Authentication files stay with the selected installation.

## Save generation setup with the instance CLI

Choose a new instance directory outside the repository and select your installed native engine:

```sh
keep instance init /absolute/path/to/my-keep \
  --repository=/absolute/path/to/my-public-project \
  --test-command=npm --test-args='["test"]' \
  --project-model=codex \
  --codex-processing=owner-public-repository \
  --codex-executable=/absolute/path/to/keep-install/engines/codex-generation.2/bin/codex \
  --codex-model=your-supported-codex-model \
  --codex-max-invocations=2 \
  --codex-max-prompt-bytes=65536 \
  --codex-max-output-bytes=262144 \
  --codex-timeout-ms=180000
keep instance status /absolute/path/to/my-keep
keep instance start /absolute/path/to/my-keep --paused
```

The `keep.instance/v1` profile saves these settings for later starts. Explicit flags override supported environment settings. Init checks version/login metadata without generating; status reads the saved configuration. Failed validation identifies corrective options for the engine, login, model, limits or helper.

Explicit init options were introduced in **0.0.20-preview.1**. The historical **0.0.19-preview.1** archive uses environment-based setup; **0.0.12-preview.1** predates this project selector. See the [instance guide](local-instance.md) for startup and controls.

Use the measured bundled engine or qualify another native executable for your workload. The profile saves its path, model and limits, while account secrets stay outside it. [Workspace preparation](local-instance.md#prepare-repository-checks) holds generation until declared checker dependencies are available. Prepared repositories can use the checker directly; offline npm preparation requires its selected toolchain and required-jail helper.

## Environment-based setup

For direct `keep solve` or `keep doctor`, configure the [repository settings](installed-solve.md#repository-settings), then set:

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

The project role processes through Codex remotely. `KEEP_PROVIDER=local` selects deterministic fixture behavior only for the other roles and credential-free embeddings. The Codex route uses your subscription login without a separate API key. Records distinguish requested/reported model identity, observed input/cached/output usage and unknown dollar cost or internal wire attempts.

The selected limits cover CLI invocations across the data directory, submitted stdin bytes, captured stdout/stderr and local process time. Full model input, output tokens and provider-internal retries remain outside those ceilings. Legacy requests requiring verified hard token/byte/wire-attempt limits refuse.

Before dispatch, Keep rechecks the pinned clean source, original command authority and selected executable hash. Data and workspaces must stay outside the source. Proposed edits run in the separate workspace; review the diff/checks before deciding. Restart retains the configured generation identity and usage claims. This profile supports personal public-repository software work. Private task-memory, Codex embeddings, domain workflows, organization custody and production isolation remain outside it.

## Generation-only native engine

The bundled `0.163.0-keep-generation.2` engine applies an empty allowed-tools ceiling before session/router construction and retains it through thread initialization. It derives from Codex 0.163.0 and updates Rustls to 0.23.46. Its credential-free v4 consumer observed empty outgoing tool catalogs, refusal of an unadvertised tool request and completed structured generation.

Executable SHA256: `fdd9a1a3e86fc2213e4c0bd9c9b278080f38d756a5256e3217092a30e48d98c1`.

The combined archive includes this executable, source patches, notices and declared MPL source. The earlier `.1` engine retains its original identity. See [dependency status](dependency-status.md) and the matching release record for installed checks. Hashes bind the executable bytes; dynamically loaded dependencies need their own identity checks.

### Stock CLI behavior

The adapter requests read-only operation and disables search, shell tools, snapshots, dependency installation, apps, hooks, multi-agent features and native Codex plugins. An October 20 check of stock CLI **0.163.0** still reported `unified_exec` enabled despite its requested opt-out. Stock flags therefore leave tool exclusion unverified. Unexpected tool activity causes refusal and can leave remote work uncertain.

The configuration reference describes the unified-exec opt-out behavior:

https://learn.chatgpt.com/docs/config-file/config-reference

The matching tool-assembly source registers `apply_patch` separately from shell-feature checks:

https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core/src/tools/spec_plan.rs

Its startup policy supports an empty allowlist; this adapter has no established injection path for the stock CLI:

https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/ext/extension-api/src/tool_policy.rs

Stock native Codex also rejects overrides of its built-in OpenAI provider, leaving internal default retries outside Keep's control. Use the measured bundled variant for the demonstrated generation-only boundary.

## Compatibility and qualification

The first failed native attempt used **0.159.3**; its cause remains unresolved. The later profile targets **0.163.0**. Generation profile v3 recognizes the specific startup warning for an absent optional code-mode host as `code-mode-host-unavailable`. It still requires a completed structured answer with usage. Unknown errors, tool activity and incomplete results refuse.

Current profile v4 also disables native Codex plugin discovery and startup synchronization. Queued work and follow-up authorizations remain bound to their original profile. Upgrade explicitly to change that identity. Keep's separate OpenClaw integration is unaffected by this subprocess setting.

Set `KEEP_CODEX_EXECUTABLE` to the native platform binary supplied by your installation. A Node launcher hash alone leaves the loaded binary unpinned. Keep checks the selected executable before dispatch; changing global installation or authentication is unnecessary.

## Qualification and recovery

Timeout, cancellation, tool activity or incomplete output can leave remote work uncertain. Stopping the local process leaves that uncertainty and invocation claim retained. Inspect the original attempt before authorizing further use. Changing the model or data directory must not bypass claims. [Validation evidence](evidence.md), [architecture](architecture.md) and [release priorities](../ROADMAP.md) record the current scope.

### Explicit owner follow-up after uncertainty

With `KEEP_DATA_DIR` set to the existing instance:

```sh
keep codex-usage status
```

Status lists total claims and exact unresolved IDs without prompt text or native diagnostics. It needs the existing local owner credential and makes no model call. An explicit `KEEP_OWNER_TOKEN_FILE` or `KEEP_OWNER_TOKEN` must match the protected instance token. Remote gateway clients cannot administer this allowance.

After reviewing uncertain work, configure the intended project and total allowance. For example, one old claim plus two approved follow-ups requires `KEEP_CODEX_MAX_INVOCATIONS=3`. Use the actual claim ID:

```sh
keep codex-usage authorize-followup \
  --uncertain=ACTUAL_UNCERTAIN_CLAIM_ID \
  --expected-claims=1 \
  --additional-invocations=2
```

List every unresolved ID, separated by commas. Pending invocations cannot be acknowledged as recorded uncertain failures. Changed counts or incomplete IDs refuse. Authorization records the current generation identity and finite additional allowance without invoking a model or resuming a job. Repeating an acknowledgement before new dispatch adds no allowance. Project approval and source/grant checks still apply.

Authorization survives restart. Successful follow-ups consume it; another uncertain failure holds dispatch for owner review. Model, executable, profile or limit changes cannot transfer the authorization. Original claims remain consumed. The earlier remote outcome stays unresolved.

## Observed genuine follow-up

The [recorded case](genuine-codex-walkthrough.md) used generation.2 through installed Keep and native OpenClaw. Two completed Codex invocations produced a patch that passed all three unchanged predefined checks. Fresh-process status recovered the same job, and veto preserved the source. OpenClaw tool selection was scripted and decisions were developer-administered. The record includes earlier failures; archive qualification remains attached to its exact release.
