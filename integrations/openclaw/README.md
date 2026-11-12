# Keep for OpenClaw

Two optional tools connect OpenClaw to Keep's repository workflow:

- `keep_submit` submits a goal. Keep retains the job and waits for a human decision before Codex generation.
- `keep_status` retrieves the conversation's job, pending decision, proposal/checks and delivery result. A lost acknowledgement can recover the original submission with its body and key.

The plugin has submission/status authority. Approval, merge and configuration stay in Keep's browser console. Tool arguments cannot select arbitrary endpoints, identities, source paths or commands.

The **0.0.29-preview.1** plugin targets **OpenClaw 2026.11.3**. On Node **24.22.3**, the native client submitted to the shipped gateway and recovered the same queued job from a fresh process: one POST and two GETs. Tool results, source preservation, audit records and shutdown passed. Dispatch stayed paused, tool selection was scripted and the SDK fixture used a refusal descriptor. There were zero account/model calls. Fresh saved-instance login, generation and owner handover remain open.

[Current API observation](../../docs/qualification/current-openclaw-api-2026-11-12.json) · [Contract observation](../../docs/qualification/current-openclaw-contract-2026-11-12.json) · [Dependency guidance](../../docs/dependency-status.md)

## Retained installed compatibility

The frozen **0.0.21-preview.1** plugin targets **OpenClaw 2026.10.5** with a Node engine floor of **24.18.1–24.x or ≥26.5.1**. Use a currently patched release within that range and follow the dependency guidance above. Keep core uses its own Node 22 runtime.

The historical .19 installed consumer passed plugin loading, the two-tool model catalog, submission, human approval, checked proposal, fresh-process status and veto on **Node 24.22.0**. Both model routes were scripted loopback fixtures. The [genuine Codex follow-up](../../docs/genuine-codex-walkthrough.md) separately records live generation. [Compatibility evidence](../../docs/qualification/openclaw-2026-10-20.json) and the [release record](../../KEEP_RELEASE.md) identify those exact subjects. The .20 package retained the same client modules; its installation/load was not rerun.

The engine floor follows published Node security fixes. Later announced updates affected the 22, 24 and 26 lines; select runtimes using current dependency guidance rather than the earlier fixture version. The private Node 24.16.0 fixture remains outside the admitted release profile.

https://nodejs.org/en/blog/vulnerability/july-2026-security-releases

https://nodejs.org/en/blog/vulnerability/october-2026-security-releases

https://nodejs.org/dist/index.json

## Historical .21 profile configuration

Configure the [personal public-repository Codex role](../../docs/codex-project.md) and issue a restricted client through [Keep's admission guide](../../docs/openclaw-client.md). Give OpenClaw that client credential; keep owner/Codex credentials private.

Install the local package in a dedicated OpenClaw profile you own:

```sh
openclaw --profile keep-portfolio plugins install ./redrookai-openclaw-keep-0.0.21-preview.1.tgz --force --accept-capabilities --no-enable
```

Verify the release checksum and review the package before accepting its capabilities. `--no-enable` leaves it inactive until configured. Use the direct archive path shown; `npm-pack:` selects managed-npm installation. The observed dependency-free direct install invoked no npm.

Installation can affect a running Gateway, so select the owned profile first. Keep the change within that profile.

Merge `example.openclaw.json` into its configuration, preserving existing model/provider plugins. If `plugins.allow` exists, append `keep` without removing provider entries. This plugin list is separate from the tool allowlist.

Replace the endpoint and private paths. Copy `clientId`, `grantId` and `commandBinding` from the issued client profile. Set `openclawAgentId` to the trusted agent that will use Keep. Supply its restricted token file with access limited to that process user, a private state directory and the chosen `requestTimeoutMs`. Replace the example's zero binding and placeholder grant with issued values.

Enable the configured plugin in the same profile:

```sh
openclaw --profile keep-portfolio plugins enable keep --accept-capabilities
```

Keep the effective catalog restricted to `keep_submit` and `keep_status`. Preserve the example's optional-tool declarations and disabled tool-search/Code Mode wrappers, then verify the outgoing catalog. Keep general host tools outside this profile and restrict its process from writing the source or reading owner/Codex credentials. The tool catalog and operating-system access controls are separate boundaries.

The fixed endpoint accepts HTTPS or literal `http://127.0.0.1` locally. Redirects refuse. Owner-direct context, configured agent, current session and the version-2 invocation guard are checked before storage/network effects and before results return. Missing or stale authority holds the call.

## Use the workflow

Ask the agent to submit one bounded repository goal through `keep_submit`. In Keep's console, inspect the requesting agent and approve or decline the pending generation step. Use `keep_status` for stage, checks, proposal digest and delivery results. Review the full diff in Keep before deciding the proposal.

The tool reports queued work, generated proposals, check results and source landing separately. Missing checks stay unavailable. After cancellation or timeout, inspect the retained job before retrying. Calls are explicit; the plugin has no background polling or direct-execution fallback.

## Durable recovery

The private `keep-submissions.sqlite` journal records the canonical request and idempotency key before HTTP. It uses Node's built-in SQLite with short transactions, WAL and full synchronization. The original API reference is Node 24.16; runtime selection follows the compatibility guidance above:

https://nodejs.org/download/release/v24.16.0/docs/api/sqlite.html

The key binds client, grant/runtime identity and trusted tool-call/session incarnation. A conversation slot survives session reset under the same logical session key. A new tool-call ID recovers unresolved work and reports that the new goal was not submitted. Concurrent processes share the journal without a persistent lock directory.

Each explicit call makes at most one submission fetch and one status fetch. There is no retry loop. Responses are capped at **64 KiB**, checked against the restricted contract and stripped of a reflected client credential. Raw exceptions and authentication responses stay out of model results.

Only an observed terminal outcome releases the conversation for another goal. Unknown, interrupted and reconciliation states remain held. Changed credentials/bindings cannot redirect an unresolved request to another client. Preserve the original journal and resolve that job with its owner. Keep's server job journal and Codex usage claims remain authoritative.

The journal includes private goal text and job observations. Before backup, stop this profile's writers and retain the whole `stateDirectory`, SQLite sidecars, matching configuration, restricted credential and logical session state. Keep's data-directory backup excludes that client state. Restore the matching set and reconcile subsequent revocations before starting restored writers. The [component recovery guide](../../docs/backup.md#recovering-the-openclaw-client-candidate) records the synthetic recovery/upgrade scope; offsite reconstruction remains unqualified.

## Package contents and limits

The package includes JavaScript, its native manifest, example configuration and MIT license. OpenClaw is an exact peer dependency with its own runtime/dependencies. This profile supports owner-directed public-repository work. Organization identity/custody and stronger isolation need separately qualified deployments.
