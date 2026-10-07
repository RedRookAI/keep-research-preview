# Codex for owner repository projects

The0.0.13 source candidate adds a project generation role using an existing signed-in Codex CLI. Downloadable release qualification is pending;0.0.12 does not support this selector. Keep controls edits, tests, approval and proposals; Codex supplies structured generation only.

Use an existing ChatGPT Codex login on the same machine. Keep checks `codex --version` and `codex login status`; it does not copy authentication files or change global configuration. Select a public repository you own or are authorized to process. Configure the existing repository/test variables in [the quickstart](quickstart.md), then explicitly set:

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

Keep bounds CLI invocations across the data directory, submitted stdin bytes, captured stdout/stderr and process time. These are not verified hard model output-token, complete model input-byte or internal wire-attempt ceilings. Legacy API requests requiring such guarantees refuse; the explicit project selector opts into the account-managed contract. Execution tools and search are disabled. The native CLI rejects overrides of its built-in openai provider, so its internal default retries are not disabled or bounded here. Requests requiring a verified hard wire-attempt ceiling refuse. Unexpected tool activity/output, timeout or cancellation may leave remote work uncertain and prevent another invocation. Stopping the local process cannot prove remote work stopped. There is no automatic reconciliation or quota reset. Changing the model binding does not refund claims; operator changes to the configured allowance are explicit.

The source must remain unchanged until an exact proposal decision. Approve through the existing project workflow; inspect its diff and test evidence. Restart reuses the same configured descriptor. This initial role supports public owner software projects only: no private task-memory, domain workflows, embeddings via Codex, organization custody or production isolation claim. CLI executable hashing pins the selected executable bytes, not every dynamically loaded dependency.

[Research and implementation status](maintenance/codex-case-20261007/INDEX.md).

Current qualification status: the first native account attempt produced no usable response and left one invocation uncertain. Clear-goal generation approval and safe error diagnostics are now source-vetted. The final source/downloadable profile and live account route remain unconfirmed. Native feature listing shows shell_tool disabled but unified_exec still enabled despite requested false settings; this is not unconditional tool-prevention evidence. Failure categories are hints, not proof of zero remote work or authority to retry. Read the shared plan before trying this experimental source role; retain unknown work and use the last qualified download for established capabilities.
