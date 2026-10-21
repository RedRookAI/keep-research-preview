# Project status and roadmap

Updated October 21, 2026. This page distinguishes the shipped portfolio preview from the remaining product commitments. Future capabilities are not claims about the downloadable preview.

## Available to inspect

The shipped **0.0.19-preview.1** combined Linux x64 download includes Keep, its TypeScript dependency, the generation-only Codex engine, the restricted OpenClaw plugin and the native project console. [Download and run](docs/combined-preview.md) · [Exact artifacts and checks](KEEP_RELEASE.md).

The portfolio release milestone is complete at this supported scope:

| Delivered capability | Observed result and limit |
|---|---|
| Genuine Codex repository work | One historical public issue produced a working patch and passed all three unchanged predefined checks. Native OpenClaw submitted and recovered the job; actual browser approval and exact veto preserved the original source. Codex generation was real; OpenClaw tool selection was scripted and decisions developer-administered. [Inspect the result](docs/genuine-codex-walkthrough.md). |
| Restricted OpenClaw client | Submission/status use the same Keep runtime, a separate expiring/revocable credential and a durable client journal. The two tools cannot approve or land a proposal. [Setup](integrations/openclaw/README.md). |
| Review and recovery | The console exposes pending steps, diffs, checks and exact decisions. Scoped installed checks cover refused authority, outage, cancellation without stopping another job, and synthetic protected recovery/upgrade. These are bounded observations, not universal containment or offsite recovery. [Evidence](docs/evidence.md). |
| Combined installation | The exact archive passed unprivileged extraction, direct startup, both account-free demos, instance/console lifecycle and plugin install/configuration/load. Final runtime comparison explicitly reuses matching component evidence; no new full-suite or live-account release run is claimed. [Qualification](docs/qualification/combined-preview-2026-10-20.json). |

The account-free repository walkthrough uses two scripted responses and simulated decisions. It produces actual workspace edits, checks and review artifacts. The separate recovery experiment checks synthetic local effects. Configured memory, skills, usage admission and backup interfaces retain their own prerequisites and evidence limits.

## Remaining delivery priorities

The completed portfolio milestone does not close the full enterprise platform. Further work should deliver one usable consumer at a time; this ordering is product direction, not an already activated implementation batch.

1. **Make adoption easier.** Reduce manual setup for a new owner's supported Codex/OpenClaw repository workflow, including clear readiness failures and the required helper/runtime prerequisites. The shipped archive and existing walkthrough remain usable now.
2. **Deliver live organization identity and isolation.** Implement an attributable organization credential lifecycle, scoped non-human identity and tenant boundaries while preserving personal operation. Injected tenant fixtures do not establish these capabilities in a live deployment.
3. **Strengthen production execution and custody.** Complete the native authority, credential/signing separation and attestation requirements beyond the selected trusted-host namespace profile.
4. **Complete retained product consumers and operations.** Connect the remaining privacy, memory, skills, integrations, observability and recovery requirements below, with evidence for the supported installed behavior. Broader evaluation and platform parity remain open.

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
