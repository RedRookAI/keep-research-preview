# Project status and roadmap

Updated October 20, 2026. This page describes the product direction and the current supported scope. Future capabilities are not claims about the downloadable preview.

## Available to inspect

The qualified **0.0.12-preview.1** Linux x64 download includes an account-free repository walkthrough and a recovery experiment. The repository walkthrough exercises a separate working copy, passing checks, a reviewable diff, simulated approval/veto, restart and source preservation. Its responses are explicitly scripted.

Configured repository work, memory, skill handling, usage admission and backup interfaces are documented in the source. Each has its own prerequisites and evidence limits. The [release record](KEEP_RELEASE.md) and [validation guide](docs/evidence.md) identify what was actually checked.

Development **0.0.17-preview.1** adds the native project console and a packaged
OpenClaw client. Its controlled installed workflow passed submission, separate
human approval, tested proposal, fresh-process status and veto with scripted local
providers. Genuine Codex work and the final combined download remain release work.

## Next release priorities

1. **A usable Codex-backed workflow.** Complete the existing-account integration and demonstrate one genuine repository task against predefined tests, retaining unsuccessful outcomes.
2. **OpenClaw as a supported client.** Let OpenClaw submit repository goals and inspect their status through the same Keep runtime. Restrict its authority; keep human approval separate from agent submission.
3. **Observable safety and recovery.** Check permitted work and refused actions, interruption without disrupting another owned job, and preservation of pending work and authority across upgrade/restore.
4. **A coherent installation and release.** Align setup, dependency identities, security limits, packaged artifacts and user documentation around one tested version.

The direct Keep CLI and the account-free walkthrough remain part of that experience. OpenHands is relevant implementation prior art; it is not a selected runtime dependency or an additional required service.

## Broader product commitments

Keep is intended to support both individual owners and organizations. Personal operation must remain usable without organization-only infrastructure; organization operation needs its own authenticated identity, tenant isolation and custody evidence.

| Area | Remaining work |
|---|---|
| Execution and credentials | Admitted native execution, stronger isolation/attestation, separate signing and credential authority, and platform-specific conformance. |
| Identity and operations | Organization login, rotation/revocation, scoped non-human identities, agent discovery, tenant boundaries and operational observability. |
| Privacy and memory | Retention/erasure, controlled retrieval, private-data custody and authorization across project changes. |
| Skills and learning | Validated reuse, feedback and rollback, bounded research and adaptation, with measured usefulness and preserved safety constraints. |
| Integrations and clients | Framework-neutral control, governed triggers/notifications and external capabilities, broader client and domain workflows. |
| Governance and evidence | Complete usage coverage, threat interception, drift response, attributable compliance evidence and outside-principal witnessing. |
| Reliability and evaluation | Protected recovery, bounded state growth, structural integration, measured performance, reproducible builds and broader task evaluation. |

Completing one preview workflow does not complete these areas. Historical component tests and simulated organization fixtures do not establish live enterprise readiness. Stronger claims require the corresponding installed consumer, meaningful allowed/refused checks and attributable evidence.

See [architecture](docs/architecture.md), [security](SECURITY.md), [contributing](WORKFLOW.md) and [the current release](KEEP_RELEASE.md).
