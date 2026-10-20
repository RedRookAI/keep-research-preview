# Codex for owner repository projects

Development source **0.0.15-preview.1** adds a project generation role using an existing signed-in Codex CLI. It is experimental: the first installed native attempt produced no usable response and left one invocation uncertain. The installed live-account workflow remains unqualified, and the **0.0.12-preview.1** download does not support this selector.

Keep's intended division of responsibility is structured generation through Codex, with edits, tests, approval and proposals controlled by Keep. Effective native execution restrictions have not been established; see the limits below.

Use an existing ChatGPT Codex login on the same machine. Keep checks `codex --version` and `codex login status`; it does not copy authentication files or change global configuration. Select a public repository you own or are authorized to process. Configure the repository/test variables in [repository settings](installed-solve.md#repository-settings), then explicitly set:

```sh
export KEEP_PROVIDER=local
export KEEP_PROJECT_MODEL=codex
export KEEP_CODEX_PROCESSING=owner-public-repository
export KEEP_CODEX_EXECUTABLE=/absolute/path/to/installed/codex
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

Keep prepares proposed edits in a separate workspace; the source must remain unchanged while a proposal awaits a decision. Approve through the existing project workflow; inspect its diff and test evidence. Restart reuses the same configured descriptor. This initial role supports public owner software projects only: no private task-memory, domain workflows, embeddings via Codex, organization custody or production isolation claim. CLI executable hashing pins the selected executable bytes, not every dynamically loaded dependency.

## Compatibility and qualification

The version check now identifies CLI 0.163.0; the first failed native attempt used 0.159.3. Metadata from a newer CLI does not explain that earlier failure or qualify the installed account route. The process profile now explicitly disables apps, hooks and multi-agent features as well as shell tools, snapshots and dependency installation. Duplicate and ineffective unified-exec opt-outs have been removed. The profile version is part of the durable generation identity, so a previously queued command cannot silently adopt a different profile. Complete pre-execution tool exclusion remains unverified.

Select the actual native executable with `KEEP_CODEX_EXECUTABLE` when preparing the supported profile. Keep hashes the selected executable before dispatch. Use the platform binary supplied by the trusted installation, rather than its Node launcher; do not change a shared installation to select it. Direct-native installed operation remains to be qualified. Measure the actual native executable as well as any launcher. Hashing a Node wrapper alone does not bind the platform binary it loads. This review did not change the installed CLI, authentication or global configuration.

## Qualification and recovery

Controlled source checks cover explicit generation approval and safe error diagnostics. They do not establish success of the installed live-account route or qualify a downloadable release. The first native failure's cause remains unresolved; diagnostic categories are hints, not proof of zero remote work or authority to retry.

Retain the uncertain invocation. Do not automatically retry or use a new data directory to bypass the retained claim. Use the [qualified download](quickstart.md) for established preview capabilities. See [validation evidence](evidence.md), [architecture](architecture.md) and [release priorities](../ROADMAP.md) for the current scope.
