# Keep for OpenClaw

Two optional native tools connect OpenClaw to Keep's repository workflow:

- `keep_submit` accepts a repository goal. Keep creates a durable job and waits for the separate human decision before Codex generation.
- `keep_status` retrieves this conversation's retained job, wait, proposal/check and delivery observations. If the original acknowledgement was lost, it can recover that same submission with its original body and key.

The plugin cannot approve, merge, change configuration or choose arbitrary endpoints, identities, source paths or commands through tool arguments. Human decisions happen in the same Keep browser console used by the direct CLI.

This **0.0.17-preview.1 candidate** targets **OpenClaw 2026.10.5**. Its Node engine floor is **24.18.1–24.x or ≥26.5.1**, stricter than OpenClaw's compatibility minimum because of [published Node security fixes](https://nodejs.org/en/blog/vulnerability/july-2026-security-releases). Use a current patched release in an admitted runtime; the engine range alone is not security admission. Keep's core remains on its Node 22 line. A controlled installed consumer passed native plugin loading, the actual two-tool model catalog, submission, human approval, tested proposal, fresh-process status and veto on **Node 24.22.0**. Both model routes were scripted loopback fixtures, with no live account call. This establishes that measured SDK workflow; genuine Codex operation and final downloadable release qualification remain pending. [Compatibility evidence](https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/openclaw-2026-10-20.json).

As checked on **October 20, 2026**, Node has [announced security updates for October 21](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) affecting the 22, 24 and 26 lines. Final runtime admission remains pending the published fixes and their applicability. The earlier private Node 24.16.0 fixture is not an admitted release runtime; no shared-host upgrade is required by this candidate.

## Configure an owned OpenClaw profile

First configure Keep's experimental personal public-repository Codex role and issue the restricted client described in [Keep's admission guide](https://github.com/RedRookAI/keep-research-preview/blob/main/docs/openclaw-client.md). Do not give OpenClaw a Keep owner token or Codex authentication files.

Use a dedicated OpenClaw profile you own. Install the packaged plugin in that profile, using the selected runtime's local install command:

```sh
openclaw plugins install npm-pack:./redrookai-openclaw-keep-0.0.17-preview.1.tgz
```

OpenClaw can apply plugin installation to a running Gateway. Select the dedicated profile before running installation; this is not an instruction to modify another claw. No global plugin registration or ClawHub publication is required.

Merge `example.openclaw.json` into that owned profile's configuration. Retain the profile's model/provider plugins. If it already has `plugins.allow`, append `keep` while preserving the existing provider entries; that plugin list is separate from the two-tool allowlist. Replace the example endpoint and private paths. Copy `clientId`, `grantId` and `commandBinding` from the issued client profile. Set `openclawAgentId` to the trusted OpenClaw agent that will use Keep. Give that process its restricted token file, readable only by its user, and a private owned state directory. Choose `requestTimeoutMs` for the local request deadline. The example's zero binding and placeholder grant are not working credentials.

Keep the effective tool catalog restricted to exactly `keep_submit` and `keep_status`. The example uses an explicit allowlist, declares both tools optional and disables native tool-search/Code Mode catalog wrappers for this direct two-tool interface. Preserve those settings when merging the example. Verify the actual admitted catalog: configuration text alone is insufficient evidence. Shell, filesystem mutation, general HTTP/browser, agent spawning and approval/admin tools do not belong in this profile. The plugin process must also lack source-write access and access to Keep owner/Codex credentials. An allowlist is not operating-system isolation.

The fixed endpoint accepts HTTPS, or literal `http://127.0.0.1` for a local listener. Redirects are refused. The owner-direct context, configured agent, current session and version-2 invocation guard are checked before storage/network effects and before returning observations. Missing or stale invocation authority yields a hold.

## Use the workflow

Ask the selected OpenClaw agent to submit one concrete repository goal with `keep_submit`. Open Keep's printed console address to inspect the requesting agent and approve or decline the exact pending generation step. Then use `keep_status` to inspect the real stage, repository tests, proposal digest and recorded source delivery. Review the full diff in Keep before the separate proposal decision.

A queued job, completed callback, generated proposal, passed test and source landing are different observations. The tool reports those separately; an unavailable check stays unavailable. Cancellation or a local timeout does not prove Keep stopped. There is no direct-execution fallback or background polling service.

## Durable recovery

The private `keep-submissions.sqlite` journal records the canonical request and idempotency key **before** HTTP. Node's built-in SQLite provides short transactions with WAL and full synchronization; no database dependency is added to Keep. Its API and behavior remain part of exact-runtime qualification. The [Node 24.16 SQLite reference](https://nodejs.org/download/release/v24.16.0/docs/api/sqlite.html) documents the implementation's original API baseline, not an admitted runtime version.

The key binds the configured client, grant/runtime identity and trusted tool-call/session incarnation. The outstanding conversation slot also survives a session reset with the same logical session key. A new tool-call ID cannot silently replace unresolved work: the plugin returns or recovers the original submission and states that the new goal was not submitted. Concurrent processes use the same journal; no persistent lock directory needs to be stolen after a crash.

One explicit tool call issues at most one submission fetch and one status fetch. The plugin has no retry loop; transport failure can still leave work uncertain. Responses are capped at 64 KiB, validated against the restricted contract and stripped of the known client credential if reflected. Raw exceptions and authentication responses are not sent to the model.

Only an observed terminal outcome releases the conversation for another explicit goal. A generation decline or proposal veto is a human decision; recorded source delivery is separate. Unknown, interrupted and reconciliation states remain held. A changed credential/binding cannot send an unresolved request to a different client. Preserve the journal and resolve the old job through its owner rather than deleting state or choosing a fresh key.

The journal contains the submitted goal and job observations. Keep it private, retain it across restarts and back it up with the other operator-owned client state. Keep's own job journal and Codex invocation claims remain the server authority; changing plugin state cannot erase those claims.

For backup, stop this profile's writers and retain the entire `stateDirectory`, including any SQLite sidecars, together with the matching configuration, restricted credential and logical session state. A Keep data-directory backup alone does not include them. Restore the matching set before recovery; reconcile later grant revocations against current owner evidence before activating restored writers. See the [component recovery procedure](https://github.com/RedRookAI/keep-research-preview/blob/main/docs/backup.md#recovering-the-openclaw-client-candidate). This candidate's combined installed recovery remains unqualified.

## Package contents and limits

This package contains JavaScript, its native manifest, an example config and its MIT license. OpenClaw is an exact peer dependency; its runtime and dependencies are not copied into Keep's core. There is no install script, API-key bridge, second solver or service manager.

This first profile supports owner-directed public repository work. Organization identity/custody and stronger isolation claims require their own qualified deployment. Actual OpenClaw runtime compatibility, combined installed behavior and genuine Codex quality are separate evidence; do not infer any of them from transport-only checks.
